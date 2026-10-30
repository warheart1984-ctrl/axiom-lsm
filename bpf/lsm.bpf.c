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
    int fam = inet_family_of(sock);
    if (fam != AF_INET && fam != AF_INET6)
        return 0;
    return gate(4, RIGHTS_NET, fam);
}

char LICENSE[] SEC("license") = "GPL";
