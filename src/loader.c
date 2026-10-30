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
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/random.h>
#include <openssl/evp.h>
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

// ============================================================================
// record — stream ring-buffer events into an Axiom-X v3 ledger disk image
// (512-byte sectors), verified offline by the *same* `ledger-tool verify`
// that audits the kernel's disks. The image carries its own AXIDENT1
// signing identity at sector 259, exactly like the kernel's ledger disk.
//
//   axiom-lsm record <image> [<checkpoint-every-N-records>]
// ============================================================================

#define AX_SECTOR 512
#define AX_RECORD_LEN 96
#define AX_SLOT (AX_RECORD_LEN + 32)
#define AX_IDENT_SECTOR 259
#define AX_RECORD_BASE 260
#define AX_CKPT_BASE 4
#define AX_CKPT_MAX 255u     /* sectors 4..258; 259 is the identity */
#define AX_JRNL_HDR 2
#define AX_JRNL_DATA 3
#define AX_IDENT_MAGIC "AXIDENT1"
#define CKPT_DOMAIN "AXIOM-X-LEDGER-CHECKPOINT-V1" /* 28 bytes */
#define CKPT_MSG_LEN 108     /* domain(28) + total(8) + boots(8) + head(32) + pubkey(32) */

#define KIND_BOOT 100
#define KIND_LSM_AUDIT 107
#define KIND_LSM_INHERIT 108
#define DEC_DENY 0
#define DEC_ALLOW 1

static void le32(unsigned char *b, unsigned v) { for (int i = 0; i < 4; i++) b[i] = v >> (8 * i); }
static void le64(unsigned char *b, unsigned long long v) { for (int i = 0; i < 8; i++) b[i] = v >> (8 * i); }
static unsigned rd32(const unsigned char *b) { unsigned v = 0; for (int i = 3; i >= 0; i--) v = (v << 8) | b[i]; return v; }
static unsigned long long rd64(const unsigned char *b) { unsigned long long v = 0; for (int i = 7; i >= 0; i--) v = (v << 8) | b[i]; return v; }

static void ax_sha256(const void *d, size_t n, unsigned char out[32])
{
    size_t l = 32;
    EVP_Q_digest(NULL, "SHA256", NULL, d, n, out, &l);
}

static int img_fd = -1;
static unsigned char tail[AX_SECTOR];   /* current record sector, in memory */
static unsigned long long tail_sector;
static int tail_persisted;              /* sector exists on disk -> rewrites go through the journal */
static unsigned long long r_seq, r_boots, r_archived, r_gen;
static unsigned char r_head[32], r_seed[32], r_pubk[32], ckpt_pub[32];
static unsigned long long ckpt_every = 32;
static unsigned long long since_ckpt;

static int pwrite_full(unsigned long long sec, const unsigned char *b)
{
    return pwrite(img_fd, b, AX_SECTOR, (off_t)sec * AX_SECTOR) == AX_SECTOR ? 0 : -1;
}

/* In-place rewrite of an existing sector: journal data + header first,
 * then the target, then clear the journal — the kernel's torn-write rule. */
static int journaled_write(unsigned long long sec, const unsigned char *data)
{
    unsigned char hdr[AX_SECTOR] = {0}, zero[AX_SECTOR] = {0}, sum[32];
    memcpy(hdr, "AXJRNL01", 8);
    le64(hdr + 8, sec);
    ax_sha256(data, AX_SECTOR, sum);
    memcpy(hdr + 16, sum, 32);
    ax_sha256(hdr, 48, sum);
    memcpy(hdr + 48, sum, 32);
    if (pwrite_full(AX_JRNL_DATA, data) || pwrite_full(AX_JRNL_HDR, hdr) ||
        pwrite_full(sec, data) || pwrite_full(AX_JRNL_HDR, zero))
        return -1;
    fsync(img_fd);
    return 0;
}

static int ed25519_pubkey_of(const unsigned char seed[32], unsigned char out[32])
{
    EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    size_t l = 32;
    int ok = pk && EVP_PKEY_get_raw_public_key(pk, out, &l) == 1 ? 0 : -1;
    EVP_PKEY_free(pk);
    return ok;
}

static int ed25519_sign(const unsigned char *m, size_t n, unsigned char sig[64])
{
    EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, r_seed, 32);
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    size_t l = 64;
    int ok = pk && c && EVP_DigestSignInit(c, NULL, NULL, NULL, pk) == 1 &&
             EVP_DigestSign(c, sig, &l, m, n) == 1 ? 0 : -1;
    EVP_PKEY_free(pk);
    EVP_MD_CTX_free(c);
    return ok;
}

/* AXIDENT1 | seed@8 | pubkey@40 | sha256(seed||pubkey)[0..16]@72 */
static int provision_identity(void)
{
    unsigned char s[AX_SECTOR] = {0}, sum[32];
    if (pread(img_fd, s, AX_SECTOR, (off_t)AX_IDENT_SECTOR * AX_SECTOR) == AX_SECTOR &&
        !memcmp(s, AX_IDENT_MAGIC, 8)) {
        ax_sha256(s + 8, 64, sum);
        if (memcmp(sum, s + 72, 16)) { fprintf(stderr, "[record] identity sector corrupt\n"); return -1; }
        memcpy(r_seed, s + 8, 32);
        return ed25519_pubkey_of(r_seed, r_pubk);
    }
    if (getrandom(r_seed, 32, 0) != 32 || ed25519_pubkey_of(r_seed, r_pubk)) {
        fprintf(stderr, "[record] identity provisioning failed\n");
        return -1;
    }
    memcpy(s, AX_IDENT_MAGIC, 8);
    memcpy(s + 8, r_seed, 32);
    memcpy(s + 40, r_pubk, 32);
    ax_sha256(s + 8, 64, sum);
    memcpy(s + 72, sum, 16);
    fprintf(stderr, "[record] provisioned fresh disk-carried identity\n");
    return pwrite_full(AX_IDENT_SECTOR, s) == 0 ? (fsync(img_fd), 0) : -1;
}

/* Walk every slot; refuse to extend evidence that doesn't verify. */
static int verify_chain(void)
{
    unsigned char b[AX_SECTOR], prev[32] = {0}, dig[32];
    for (unsigned long long s = 0; s < r_seq; s++) {
        if (pread(img_fd, b, AX_SECTOR, (off_t)(AX_RECORD_BASE + s / 4) * AX_SECTOR) != AX_SECTOR) {
            fprintf(stderr, "[record] short image at seq %llu\n", s);
            return -1;
        }
        unsigned char *r = b + (s % 4) * AX_SLOT;
        if (rd64(r) != s || memcmp(r + 64, prev, 32)) {
            fprintf(stderr, "[record] chain broken at seq %llu — refusing to append\n", s);
            return -1;
        }
        ax_sha256(r, AX_RECORD_LEN, dig);
        if (memcmp(dig, r + 96, 32)) {
            fprintf(stderr, "[record] bad stored digest at seq %llu\n", s);
            return -1;
        }
        memcpy(prev, dig, 32);
    }
    if (memcmp(prev, r_head, 32)) {
        fprintf(stderr, "[record] chain head != superblock head — refusing to append\n");
        return -1;
    }
    return 0;
}

static int resume_image(void)
{
    unsigned char b[AX_SECTOR], sum[32];
    int found = -1;
    unsigned long long gen = 0, resumed = 0;
    for (int i = 0; i < 2; i++) {
        if (pread(img_fd, b, AX_SECTOR, (off_t)i * AX_SECTOR) != AX_SECTOR) continue;
        if (memcmp(b, "AXLEDGR1", 8) || rd32(b + 152) != 3) continue;
        ax_sha256(b, 176, sum);
        if (memcmp(sum, b + 176, 32)) continue;
        unsigned long long g = rd64(b + 160);
        if (found < 0 || g > gen) {
            gen = g; found = i;
            r_seq = rd64(b + 8); r_boots = rd64(b + 16);
            memcpy(r_head, b + 24, 32); memcpy(ckpt_pub, b + 56, 32);
            r_archived = rd64(b + 168);
        }
    }
    if (found < 0) { r_seq = 0; r_boots = 0; r_archived = 0; r_gen = 0; tail_sector = AX_RECORD_BASE; memset(tail, 0, sizeof tail); return 0; }
    if (verify_chain()) return -1;
    if (memcmp(ckpt_pub, r_pubk, 32)) {
        fprintf(stderr, "[record] disk is signed by a different identity — refusing\n");
        return -1;
    }
    resumed = r_seq;
    tail_sector = AX_RECORD_BASE + r_seq / 4;
    memset(tail, 0, sizeof tail);
    if (r_seq % 4) {
        if (pread(img_fd, tail, AX_SECTOR, (off_t)tail_sector * AX_SECTOR) != AX_SECTOR) {
            fprintf(stderr, "[record] cannot reload tail sector\n");
            return -1;
        }
        tail_persisted = 1;
    }
    r_gen = gen;
    r_boots++;   /* this daemon run is a new boot */
    fprintf(stderr, "[record] resumed: %llu records verified, head ...%02x%02x, boot %llu\n",
            resumed, r_head[30], r_head[31], r_boots);
    return 0;
}

static int ledger_append(unsigned kind, unsigned dec, unsigned pid, unsigned subj,
                         unsigned long long nr, unsigned long long arg,
                         long long result, unsigned long long rights)
{
    unsigned char enc[AX_RECORD_LEN] = {0}, dig[32];
    le64(enc, r_seq);
    le64(enc + 8, (unsigned long long)time(NULL) * 1000); /* tick = UNIX ms on LSM records */
    le32(enc + 16, kind); le32(enc + 20, dec);
    le32(enc + 24, pid); le32(enc + 28, subj);
    le64(enc + 32, nr); le64(enc + 40, arg);
    le64(enc + 48, (unsigned long long)result); le64(enc + 56, rights);
    memcpy(enc + 64, r_head, 32);
    ax_sha256(enc, AX_RECORD_LEN, dig);

    size_t off = (r_seq % 4) * AX_SLOT;
    memcpy(tail + off, enc, AX_RECORD_LEN);
    memcpy(tail + off + AX_RECORD_LEN, dig, 32);
    int rc = tail_persisted ? journaled_write(tail_sector, tail) : pwrite_full(tail_sector, tail);
    if (rc) { fprintf(stderr, "[record] image write failed\n"); return -1; }
    memcpy(r_head, dig, 32);
    r_seq++;
    since_ckpt++;
    if (r_seq % 4 == 0) { tail_sector++; memset(tail, 0, sizeof tail); tail_persisted = 0; }
    else tail_persisted = 1;
    return 0;
}

static int write_checkpoint(void)
{
    unsigned char a[AX_SECTOR] = {0}, m[CKPT_MSG_LEN], sig[64], sum[32];
    memcpy(a, "AXCKPT01", 8);
    le64(a + 8, r_seq); le64(a + 16, r_boots); memcpy(a + 24, r_head, 32);
    memcpy(m, CKPT_DOMAIN, 28);
    le64(m + 28, r_seq); le64(m + 36, r_boots);
    memcpy(m + 44, r_head, 32); memcpy(m + 76, r_pubk, 32);
    if (ed25519_sign(m, sizeof m, sig)) { fprintf(stderr, "[record] checkpoint sign failed\n"); return -1; }
    memcpy(a + 56, r_pubk, 32); memcpy(a + 88, sig, 64);
    a[152] = 1;
    ax_sha256(a, 160, sum); memcpy(a + 160, sum, 32);
    if (r_archived < AX_CKPT_MAX) {
        if (pwrite_full(AX_CKPT_BASE + r_archived, a)) return -1;
        r_archived++;
    }
    /* superblock: alternate copies — a torn write leaves the previous valid */
    unsigned char sb[AX_SECTOR] = {0};
    memcpy(sb, "AXLEDGR1", 8);
    memcpy(sb + 8, a + 8, 144);          /* checkpoint fields 8..152 */
    le32(sb + 152, 3); le32(sb + 156, 1); /* version 3, FLAG_SIGNED */
    r_gen++;
    le64(sb + 160, r_gen); le64(sb + 168, r_archived);
    ax_sha256(sb, 176, sum); memcpy(sb + 176, sum, 32);
    if (pwrite_full(r_gen % 2, sb)) return -1;
    fsync(img_fd);
    since_ckpt = 0;
    fprintf(stderr, "[record] checkpoint: %llu records, archive %llu, gen %llu\n",
            r_seq, r_archived, r_gen);
    return 0;
}

static int on_record(void *ctx, void *data, size_t n)
{
    const struct ev *e = data;
    (void)ctx; (void)n;
    int inherit = e->kind == 2;
    ledger_append(inherit ? KIND_LSM_INHERIT : KIND_LSM_AUDIT,
                  e->kind == 1 ? DEC_DENY : DEC_ALLOW,
                  (unsigned)e->tgid, (unsigned)e->tgid,
                  e->hook, e->arg, e->kind == 1 ? -1 : 0, e->rights);
    fprintf(stderr, "[audit] tgid %-7llu rights 0x%-6llx hook %-2u arg %-4llu -> %s\n",
            (unsigned long long)e->tgid, (unsigned long long)e->rights,
            e->hook, (unsigned long long)e->arg,
            e->kind == 2 ? "INHERIT" : e->kind ? "DENY" : "ALLOW");
    return 0;
}

static int do_record(const char *path, const char *every_s)
{
    if (every_s) ckpt_every = strtoull(every_s, NULL, 10);
    if (!ckpt_every) ckpt_every = 32;
    img_fd = open(path, O_RDWR | O_CREAT, 0600);
    if (img_fd < 0) { fprintf(stderr, "%s: %s\n", path, strerror(errno)); return 1; }
    if (provision_identity() || resume_image()) { close(img_fd); return 1; }
    unsigned long long resumed = r_seq;
    if (ledger_append(KIND_BOOT, DEC_ALLOW, 0, 0, rd64(r_pubk), r_boots,
                      (long long)resumed, (unsigned long long)time(NULL)) ||
        write_checkpoint())
        return 1;
    int fd = pinned_map_fd("events");
    if (fd < 0) return 1;
    struct ring_buffer *rb = ring_buffer__new(fd, on_record, NULL, NULL);
    if (!rb) { fprintf(stderr, "ring buffer: %s\n", strerror(errno)); return 1; }
    signal(SIGINT, sig_int);
    signal(SIGTERM, sig_int);
    fprintf(stderr, "[axiom-lsm] recording to %s (checkpoint every %llu records; ctrl-c to stop)\n",
            path, ckpt_every);
    while (!quit) {
        ring_buffer__poll(rb, 100);
        if (since_ckpt >= ckpt_every) write_checkpoint();
    }
    ring_buffer__free(rb);
    if (write_checkpoint()) return 1;
    fprintf(stderr, "[axiom-lsm] final checkpoint written; verify with ledger-tool\n");
    close(img_fd);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "usage: axiom-lsm attach|detach|grant <tgid> <hex>|run <hex> <cmd...>|audit|record <img> [every]\n");
        return 2;
    }
    if (!strcmp(argv[1], "attach")) return do_attach();
    if (!strcmp(argv[1], "detach")) return do_detach();
    if (!strcmp(argv[1], "grant") && argc == 4) return do_grant(argv[2], argv[3]);
    if (!strcmp(argv[1], "audit")) return do_audit();
    if (!strcmp(argv[1], "run") && argc >= 4) return do_run(argv[2], &argv[3]);
    if (!strcmp(argv[1], "record") && argc >= 3) return do_record(argv[2], argc > 3 ? argv[3] : NULL);
    fprintf(stderr, "bad args\n");
    return 2;
}
