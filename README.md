# axiom-lsm — governed egress for real Linux processes

The [Axiom-X](https://github.com/warheart1984-ctrl/Axiom-X) constitution
enforced inside Linux via **BPF LSM** — no kernel rebuild, runtime-attached
hooks, deny-by-default.

A task may not create a socket unless it holds `Rights::NET` (same bit
values as `axiom-x-capability`, `1 << 16`). Every governed call — denials
*and* grants — emits an audit event to a ring buffer; the asking IS the
audit trail.

Two scopes, deliberately different: **network egress is host policy** —
every task needs `Rights::NET` for INET sockets while attached.
**file_open / mmap / exec are governed-scoped** — they apply only to
tasks holding a rights entry (spawned under `run`/`grant` + descendants);
ungoverned tasks are not subjects of this monitor and pass free.

## Requirements

- Kernel with `CONFIG_BPF_LSM=y` and `bpf` in the LSM list
  (`cat /sys/kernel/security/lsm` — WSL2's Microsoft kernel includes it)
- `clang`, `bpftool`, `libbpf-dev`, `libelf-dev`, `zlib1g-dev`, `libssl-dev`
- Root for load/attach (`CAP_SYS_ADMIN` + `CAP_BPF`)

## Build & use

```bash
sudo mount -t bpf bpf /sys/fs/bpf      # once per boot (check: mountpoint /sys/fs/bpf)
make
sudo ./axiom-lsm attach        # hook live, objects pinned to /sys/fs/bpf/axiom-lsm/
# or: scoped mode — every hook applies only inside a cgroup subtree:
sudo mkdir /sys/fs/cgroup/axgov
sudo ./axiom-lsm attach /sys/fs/cgroup/axgov
sudo AXIOM_CGROUP=/sys/fs/cgroup/axgov ./axiom-lsm run 0x1042E python3 agent.py
sudo ./axiom-lsm audit &       # stream denials + grants
python3 -c 'import socket; socket.socket()'   # PermissionError + DENY event
sudo ./axiom-lsm grant <tgid> 0x10000         # grant Rights::NET to a task
sudo ./axiom-lsm run 0x10000 curl example.com # spawn a governed task
sudo ./axiom-lsm detach                       # unload everything
```

Rights bits (shared with `axiom-x-capability`): `READ 0x2`, `WRITE 0x4`,
`EXECUTE 0x8`, `ALLOC 0x20`, `RECV 0x100`, `SPAWN 0x400`, `KILL 0x800`,
`NET 0x10000`. A governed
task needs the right for each class it uses — e.g. `run 0x1042E` lets a
program exec, read/write files, mmap, and use INET sockets; `run
0x10000` gets a socket but fails its own `execve` (no `EXECUTE`).

## Signed evidence — `record`

`record` consumes the audit ring and appends each decision to an
**Axiom-X format-v3 ledger disk image** — the identical 512-byte sector
layout the kernel writes: hash-chained 96-byte records, journaled tail
rewrites, Ed25519-signed checkpoints, and a disk-carried `AXIDENT1`
signing identity in sector 259 (generated on first run, reread after).

```bash
sudo ./axiom-lsm record evidence/lsm-ledger.img   # checkpoint every 32; SIGINT for final
# verify offline with the SAME tool that audits the kernel's disks:
ledger-tool pubkey evidence/lsm-ledger.img
ledger-tool verify evidence/lsm-ledger.img <pubkey>
```

Verified output (2026-10-30): `hash chain: internally consistent from
genesis`, `checkpoint signature: Valid`, `6 signed checkpoints verified`,
`PASS: 9 records verified from genesis (1 denies)`.

Record kinds: `LSM_AUDIT` (107 — hook decision, `nr` = hook, `arg` =
family/arg, `result` = 0/−EPERM) and `LSM_INHERIT` (108 — parent rights
copied to child at `task_alloc`). `BOOT` (100) marks each daemon run;
`tick` carries UNIX ms on LSM records. Only checkpointed records are
durable — a daemon killed mid-window loses its un-checkpointed tail.

## Operational warnings (learned the hard way)

- **Stacked bpffs mounts**: `mount -t bpf` twice creates two instances —
  pins on the hidden lower mount keep *old programs* enforcing with
  unreachable maps (ALLOW + EPERM simultaneously). Check
  `bpftool link list | grep -c lsm` == 2; fix by unmounting until the
  count is right, remount once, reattach.
- **The gate is INET-only by design**: gating `AF_NETLINK`/`AF_UNIX`
  breaks `sudo` (PAM audit) and local IPC — a reference monitor that
  mediates too much locks out its operators.
- `attach` with no cgroup is **system-wide** default-deny for INET
  sockets; `attach <cgroup>` scopes EVERY hook to that subtree —
  inside, all 14 classes deny at rights=0 unless granted (`run` +
  `AXIOM_CGROUP` joins pre-exec); outside, untouched. Don't write your
  own shell's pid into `cgroup.procs` — a governed shell can't even
  write the file that governs it (learned the hard way).

## Status

| Piece | State |
|-------|-------|
| `socket_create` gate (Rights::NET) | `enforced` — DENY/ALLOW evidenced |
| `socket_connect` + `socket_sendmsg` gates | `enforced` — passed-fd `connect` DENIED (hook 3, port audited) |
| SCM_RIGHTS bypass | **closed** — mediation moved from creation to network action |
| `file_open` (READ/WRITE), `mmap` (ALLOC), `bprm_check` (EXECUTE) | `enforced` — governed-scoped; DENY evidenced per class |
| `bind`/`listen`/`accept` (RECV), `inode_create`+`unlink` (WRITE), `ptrace` both directions + `task_kill` signals (KILL) | `enforced` — DENY evidenced per class |
| Rights inheritance on fork (`lsm/task_alloc`) | `enforced` — INHERIT→ALLOW observed |
| Daemon signing events into AX ledger records | `enforced` — `ledger-tool verify` PASS: 1498 records, 11 denies, 18 signed checkpoints |
| Cgroup-scoped enforcement (`attach <cg>`) | `enforced` — in-cgroup `run 0x0` fully locked; outside unaffected |
| `rename`/`link`/`setattr`/`truncate`/`mkdir` (WRITE, hooks 16–20) | `enforced` — all five DENY-evidenced |
| Daemon signing events into AX ledger records | `enforced` — `ledger-tool verify` PASS: 3379 records, 16 denies, 21 signed checkpoints |
| Remaining surface | `recvmsg` (by design), `path_symlink`/`rmdir`/`chown`/xattrs, `brk` (ALLOC is mmap-gated), `SPAWN` (defined, unused — fork ungated), ringbuf events droppable under flood |
| Root/CAP_BPF detachment | trusted operator by design (see PAPER §3) |
