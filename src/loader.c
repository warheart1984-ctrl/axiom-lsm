// axiom-lsm loader — attach/detach the LSM programs, grant rights,
// print the audit ring. Requires CAP_SYS_ADMIN + CAP_BPF (sudo).
//
// Maps and links pin under /sys/fs/bpf/axiom-lsm/ so `attach`, `grant`,
// `audit` and `detach` can run as separate invocations.
//
//   axiom-lsm attach                  load + attach, pin everything
//   axiom-lsm detach                remove links + pins (unloads)
//   axiom-lsm grant <tgid> <hex>    set a task's rights bitmask
//   axiom-lsm run <rights-hex> <cmd> exec cmd with rights granted
//   axiom-lsm audit                 stream denial/grant events
//
// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "lsm.skel.h"

#define PIN_DIR "/sys/fs/bpf/axiom-lsm"

static volatile int quit;
static void sig_int(int s) { (void)s; quit = 1; }

struct ev {
    __u64 tgid;
    __u64 rights;
    __u64 arg;
    __u32 hook;
    __u32 kind;
};

static int on_event(void *ctx, void *data, size_t n)
{
    const struct ev *e = data;
    (void)ctx; (void)n;
    printf("[audit] tgid %-7llu rights 0x%-6llx hook %-2u arg %-4llu -> %s\n",
           (unsigned long long)e->tgid, (unsigned long long)e->rights,
           e->hook, (unsigned long long)e->arg,
           e->kind == 2 ? "INHERIT" : e->kind ? "DENY" : "ALLOW");
    fflush(stdout);
    return 0;
}

static int pin_map(struct bpf_map *m, const char *name)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", PIN_DIR, name);
    unlink(path);
    int err = bpf_map__pin(m, path);
    if (err) fprintf(stderr, "pin %s: %s\n", name, strerror(-err));
    return err;
}

static int pinned_map_fd(const char *name)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", PIN_DIR, name);
    int fd = bpf_obj_get(path);
    if (fd < 0) fprintf(stderr, "%s: %s — is `attach` running?\n", path, strerror(errno));
    return fd;
}

// BPF hooks see host-kernel tgids; inside a pid namespace (WSL, containers)

static int do_attach(void)
{
    if (mkdir(PIN_DIR, 0755) && errno != EEXIST) {
        fprintf(stderr, "mkdir %s: %s — is bpffs mounted? (`mount -t bpf bpf /sys/fs/bpf`)\n",
                PIN_DIR, strerror(errno));
        return 1;
    }
    struct lsm_bpf *skel = lsm_bpf__open_and_load();
    if (!skel) { fprintf(stderr, "load failed (sudo? CONFIG_BPF_LSM? lsm=...,bpf?)\n"); return 1; }
    int err = lsm_bpf__attach(skel);
    if (err) { fprintf(stderr, "attach: %s\n", strerror(-err)); lsm_bpf__destroy(skel); return 1; }
    if (pin_map(skel->maps.task_rights, "task_rights") ||
        pin_map(skel->maps.events, "events")) {
        lsm_bpf__detach(skel); lsm_bpf__destroy(skel); return 1;
    }
    if (bpf_link__pin(skel->links.axiom_socket_create, PIN_DIR "/link-socket_create"))
        fprintf(stderr, "warn: link pin failed — detach won't find it\n");
    if (bpf_link__pin(skel->links.axiom_task_alloc, PIN_DIR "/link-fork"))
        fprintf(stderr, "warn: fork link pin failed\n");
    fprintf(stderr, "[axiom-lsm] attached; pins in %s\n", PIN_DIR);
    lsm_bpf__destroy(skel); /* skeleton frees; pinned objs stay live */
    return 0;
}

static int do_detach(void)
{
    unlink(PIN_DIR "/link-socket_create");
    unlink(PIN_DIR "/link-fork");
    unlink(PIN_DIR "/task_rights");
    unlink(PIN_DIR "/events");
    rmdir(PIN_DIR);
    fprintf(stderr, "[axiom-lsm] detached\n");
    return 0;
}

// pidfd_open — glibc 2.36+; fall back to the raw syscall number (434).
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
static int x_pidfd_open(pid_t pid) { return syscall(SYS_pidfd_open, pid, 0); }

// Task-storage grants are keyed by pidfd → task struct: namespace-immune.
static int grant_task(int fd, pid_t pid, __u64 rights)
{
    int pidfd = x_pidfd_open(pid);
    if (pidfd < 0) { fprintf(stderr, "pidfd_open %d: %s\n", pid, strerror(errno)); return -1; }
    int err = bpf_map_update_elem(fd, &pidfd, &rights, BPF_ANY);
    close(pidfd);
    if (err) fprintf(stderr, "grant: %s\n", strerror(errno));
    return err;
}

static int do_grant(const char *tgid_s, const char *hex_s)
{
    pid_t tgid = (pid_t)strtoul(tgid_s, NULL, 10);
    __u64 rights = strtoull(hex_s, NULL, 16);
    int fd = pinned_map_fd("task_rights");
    if (fd < 0) return 1;
    if (grant_task(fd, tgid, rights)) return 1;
    fprintf(stderr, "[axiom-lsm] tgid %u rights := 0x%llx\n",
            tgid, (unsigned long long)rights);
    return 0;
}

static int do_audit(void)
{
    int fd = pinned_map_fd("events");
    if (fd < 0) return 1;
    struct ring_buffer *rb = ring_buffer__new(fd, on_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "ring buffer: %s\n", strerror(errno)); return 1; }
    signal(SIGINT, sig_int);
    fprintf(stderr, "[axiom-lsm] audit streaming (ctrl-c to stop)\n");
    while (!quit) ring_buffer__poll(rb, 100);
    ring_buffer__free(rb);
    return 0;
}

static int do_run(const char *hex_s, char **cmd)
{
    __u64 rights = strtoull(hex_s, NULL, 16);
    int fd = pinned_map_fd("task_rights");
    if (fd < 0) return 1;
    pid_t p = fork();
    if (p == 0) {
        /* task storage survives exec: the grant rides the same task_struct */
        if (grant_task(fd, getpid(), rights)) {
            dprintf(2, "[axiom-lsm] rights grant failed\n");
            _exit(126);
        }
        dprintf(2, "[axiom-lsm] task granted 0x%llx\n", (unsigned long long)rights);
        execvp(cmd[0], cmd);
        _exit(127);
    }
    int st;
    waitpid(p, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "usage: axiom-lsm attach|detach|grant <tgid> <hex>|run <hex> <cmd...>|audit\n");
        return 2;
    }
    if (!strcmp(argv[1], "attach")) return do_attach();
    if (!strcmp(argv[1], "detach")) return do_detach();
    if (!strcmp(argv[1], "grant") && argc == 4) return do_grant(argv[2], argv[3]);
    if (!strcmp(argv[1], "audit")) return do_audit();
    if (!strcmp(argv[1], "run") && argc >= 4) return do_run(argv[2], &argv[3]);
    fprintf(stderr, "bad args\n");
    return 2;
}
