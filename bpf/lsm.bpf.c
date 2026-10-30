// axiom-lsm — governed egress for real Linux processes.
//
// The Axiom-X constitution, enforced on Linux: a task may not create a
// socket unless it holds Rights::NET. Every governed call is audited —
// denials AND grants — to a ring buffer the userspace daemon signs into
// the same ledger record format the kernel produced.
//
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef EPERM
#define EPERM 1
#endif
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

// axiom-x-capability bit values (keep in sync with the prototype).
#define RIGHTS_NET (1ULL << 16)
#define RIGHTS_ALLOC (1ULL << 5)
#define RIGHTS_READ (1ULL << 1)
#define RIGHTS_WRITE (1ULL << 2)
#define RIGHTS_EXECUTE (1ULL << 3)
#define RIGHTS_RECV (1ULL << 8)
#define RIGHTS_SPAWN (1ULL << 10)
#define RIGHTS_KILL (1ULL << 11)

// fmode bits (linux/fs.h macros — not in vmlinux.h)
#define FMODE_READ 1
#define FMODE_WRITE 2

// Per-task rights as task-local storage — keyed by the task struct
// itself, updated from userspace via pidfd. Immune to pid namespaces:
// the hook sees the task, not a number someone else translated.
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, __u64);
} task_rights SEC(".maps");

// Audit event stream: every governed decision.
struct ev {
    __u64 tgid;
    __u64 rights;
    __u64 arg;
    __u32 hook;
    __u32 kind; /* 0 = allow, 1 = deny */
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

// Scoped mode: when the operator pins a cgroup into scope_cgroups and
// sets scope_cfg[0]=1, every hook applies only to tasks inside that
// cgroup subtree — the deployment shape. Unconfigured = legacy mode
// (egress host-wide; other classes governed-entry-only).
struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} scope_cgroups SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} scope_cfg SEC(".maps");

// 0 = unconfigured (legacy), 1 = in scope, -1 = out of scope.
static __always_inline int scope_check(void)
{
    __u32 k = 0;
    __u64 *on = bpf_map_lookup_elem(&scope_cfg, &k);
    if (!on || !*on)
        return 0;
    return bpf_current_task_under_cgroup(&scope_cgroups, 0) ? 1 : -1;
}

static __always_inline int gate(__u32 hook, __u64 need, __u64 arg)
{
    __u64 pidtgid = bpf_get_current_pid_tgid();
    __u32 tgid = pidtgid >> 32;
    __u64 *r = bpf_task_storage_get(&task_rights, bpf_get_current_task_btf(), 0, 0);
    __u64 rights = r ? *r : 0;
    int deny = (rights & need) != need;
    struct ev *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->tgid = tgid;
        e->rights = rights;
        e->arg = arg;
        e->hook = hook;
        e->kind = deny;
        bpf_ringbuf_submit(e, 0);
    }
    return deny ? -EPERM : 0;
}

// Rights inheritance: a forking parent passes a subset of its own rights
// to the child — never more. lsm/task_alloc hands us the new task struct
// directly; its storage is seeded with the parent's mask (attenuation:
// the child can only ever receive what the parent holds).
SEC("lsm/task_alloc")
int BPF_PROG(axiom_task_alloc, struct task_struct *task,
             unsigned long clone_flags, int prevstate)
{
    struct task_struct *parent = bpf_get_current_task_btf();
    __u64 *r = bpf_task_storage_get(&task_rights, parent, 0, 0);
    if (!r)
        return 0;
    __u64 *c = bpf_task_storage_get(&task_rights, task, 0,
                                    BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (c)
        *c = *r;
    // Audit the grant propagation (kind 2 = inherit).
    __u32 tgid = (bpf_get_current_pid_tgid() >> 32);
    struct ev *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->tgid = tgid;
        e->rights = *r;
        e->arg = (__u64)clone_flags;
        e->hook = 2;
        e->kind = 2;
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

// socket(2) is the governed egress channel: Rights::NET or nothing.
// Only INET families are egress — AF_UNIX/AF_NETLINK local IPC is not,
// and gating it breaks the tools needed to govern (sudo's audit socket).
SEC("lsm/socket_create")
int BPF_PROG(axiom_socket_create, int family, int type, int protocol, int kern)
{
    if (scope_check() < 0)
        return 0;
    if (family != AF_INET && family != AF_INET6)
        return 0;
    return gate(1, RIGHTS_NET, family);
}

// Socket family via CO-RE: a passed fd (SCM_RIGHTS) lets a denied task skip
// socket_create entirely, so creation alone isn't the boundary — action is.
static __always_inline int inet_family_of(struct socket *sock)
{
    struct sock *sk = sock->sk;
    if (!sk)
        return 0;
    return sk->__sk_common.skc_family;
}

// connect(2): closing the SCM_RIGHTS bypass. A denied task holding a passed
// fd can call connect/send on it — gating action (not just creation) is the
// difference between a firewall and a mediation boundary.
SEC("lsm/socket_connect")
int BPF_PROG(axiom_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
    if (scope_check() < 0)
        return 0;
    int fam = inet_family_of(sock);
    if (fam != AF_INET && fam != AF_INET6)
        return 0;
    __u64 a = fam;
    if (address) {
        if (fam == AF_INET)
            a = ((struct sockaddr_in *)address)->sin_port;
        else if (fam == AF_INET6)
            a = ((struct sockaddr_in6 *)address)->sin6_port;
    }
    return gate(3, RIGHTS_NET, a);
}

// sendmsg(2)/send(2)/write(2): UDP tasks can reach arbitrary destinations
// without ever calling connect — gate the send path too, or the connect
// hook is decorative. arg = socket family (msg_name may be NULL).
SEC("lsm/socket_sendmsg")
int BPF_PROG(axiom_socket_sendmsg, struct socket *sock,
             struct msghdr *msg, int size)
{
    if (scope_check() < 0)
        return 0;
    int fam = inet_family_of(sock);
    if (fam != AF_INET && fam != AF_INET6)
        return 0;
    return gate(4, RIGHTS_NET, fam);
}

// Non-network classes are scoped to GOVERNED tasks: a task_rights entry
// (even 0x0) marks the task as a subject of this monitor; tasks without
// one are not governed and pass free. Denying file opens or exec for
// every unlisted task would brick the host — the egress gate is host
// policy, but file/exec gates are per-subject, like the kernel's model.
static __always_inline int governed_gate(__u32 hook, __u64 need, __u64 arg)
{
    int sc = scope_check();
    if (sc < 0)
        return 0;                    /* outside the governed cgroup — not a subject */
    if (sc == 0) {
        /* legacy: only tasks holding a rights entry are subjects */
        __u64 *r = bpf_task_storage_get(&task_rights, bpf_get_current_task_btf(), 0, 0);
        if (!r)
            return 0;
    }
    return gate(hook, need, arg);
}

// open(2): READ/WRITE by open mode. arg = fmode.
SEC("lsm/file_open")
int BPF_PROG(axiom_file_open, struct file *file)
{
    __u32 mode = file->f_mode;
    __u64 need = 0;
    if (mode & FMODE_READ)
        need |= RIGHTS_READ;
    if (mode & FMODE_WRITE)
        need |= RIGHTS_WRITE;
    if (!need)
        return 0;
    return governed_gate(5, need, mode);
}

// mmap(2): memory is allocated authority, not a side effect. arg = prot.
SEC("lsm/mmap_file")
int BPF_PROG(axiom_mmap, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags)
{
    return governed_gate(6, RIGHTS_ALLOC, prot);
}

// execve(2): running a different program is the EXECUTE right. fork is
// not gated — a forked child IS the parent (task_alloc copies the mask).
SEC("lsm/bprm_check_security")
int BPF_PROG(axiom_bprm, struct linux_binprm *bprm)
{
    return governed_gate(7, RIGHTS_EXECUTE, 0);
}

// Inbound authority — RECV is the counterpart of NET: bind/listen/accept
// make a task *reachable*, which is new authority, not a byte arriving.
// recvmsg is intentionally ungated: a reply to a petition you were
// allowed to send confers no new authority, and gating it would break
// every client. Governed-scoped like the other per-subject gates.
static __always_inline int is_inet(struct socket *sock)
{
    int fam = inet_family_of(sock);
    return fam == AF_INET || fam == AF_INET6;
}

SEC("lsm/socket_bind")
int BPF_PROG(axiom_bind, struct socket *sock, struct sockaddr *address, int addrlen)
{
    if (!is_inet(sock))
        return 0;
    __u64 a = 0;
    if (address && address->sa_family == AF_INET)
        a = ((struct sockaddr_in *)address)->sin_port;
    else if (address && address->sa_family == AF_INET6)
        a = ((struct sockaddr_in6 *)address)->sin6_port;
    return governed_gate(8, RIGHTS_RECV, a);
}

SEC("lsm/socket_listen")
int BPF_PROG(axiom_listen, struct socket *sock, int backlog)
{
    if (!is_inet(sock))
        return 0;
    return governed_gate(9, RIGHTS_RECV, backlog);
}

SEC("lsm/socket_accept")
int BPF_PROG(axiom_accept, struct socket *sock, struct socket *newsock)
{
    if (!is_inet(sock))
        return 0;
    return governed_gate(10, RIGHTS_RECV, 0);
}

// Namespace mutation: creating or deleting a name is WRITE authority on
// the filesystem, not a side effect of open(2). inode_create firing
// *before* file_open also closes the documented gap where a denied
// O_CREAT still left an empty file behind.
SEC("lsm/inode_create")
int BPF_PROG(axiom_inode_create, struct inode *dir, struct dentry *dentry,
             umode_t mode)
{
    return governed_gate(11, RIGHTS_WRITE, mode);
}

SEC("lsm/inode_unlink")
int BPF_PROG(axiom_inode_unlink, struct inode *dir, struct dentry *dentry)
{
    return governed_gate(12, RIGHTS_WRITE, 0);
}

// ptrace(2): inspecting or steering another task is process-control
// authority — and the natural way to hijack a *granted* task's rights.
// Both directions gated: attaching (access_check) and volunteering to
// be traced (traceme) — a governed task could otherwise let an
// ungoverned accomplice drive it.
SEC("lsm/ptrace_access_check")
int BPF_PROG(axiom_ptrace_access, struct task_struct *child, unsigned int mode)
{
    return governed_gate(13, RIGHTS_KILL, mode);
}

SEC("lsm/ptrace_traceme")
int BPF_PROG(axiom_ptrace_traceme, struct task_struct *parent)
{
    return governed_gate(14, RIGHTS_KILL, 0);
}

// Signal delivery is process-control authority crossing a task boundary:
// without this gate a governed task could SIGKILL/SIGSTOP a *granted*
// task or the monitor itself. Self-signals (raise/abort) pass — a task
// degrading itself is not an authority crossing — and kernel-origin
// signals (si_code > 0, e.g. SIGCHLD to a parent) must stay free.
SEC("lsm/task_kill")
int BPF_PROG(axiom_task_kill, struct task_struct *p,
             struct kernel_siginfo *info, int sig, const struct cred *cred)
{
    if (p == bpf_get_current_task_btf())
        return 0;
    if (info && info->si_code > 0)
        return 0;
    return governed_gate(15, RIGHTS_KILL, sig);
}

char LICENSE[] SEC("license") = "GPL";
