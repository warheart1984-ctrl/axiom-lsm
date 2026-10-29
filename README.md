# axiom-lsm — governed egress for real Linux processes

The [Axiom-X](https://github.com/warheart1984-ctrl/Axiom-X) constitution
enforced inside Linux via **BPF LSM** — no kernel rebuild, runtime-attached
hooks, deny-by-default.

A task may not create a socket unless it holds `Rights::NET` (same bit
values as `axiom-x-capability`, `1 << 16`). Every governed call — denials
*and* grants — emits an audit event to a ring buffer; the asking IS the
audit trail.

## Requirements

- Kernel with `CONFIG_BPF_LSM=y` and `bpf` in the LSM list
  (`cat /sys/kernel/security/lsm` — WSL2's Microsoft kernel includes it)
- `clang`, `bpftool`, `libbpf-dev`, `libelf-dev`, `zlib1g-dev`
- Root for load/attach (`CAP_SYS_ADMIN` + `CAP_BPF`)

## Build & use

```bash
sudo mount -t securityfs securityfs /sys/kernel/security   # once per boot
make
sudo ./axiom-lsm attach        # hook live, objects pinned to /sys/fs/bpf/axiom-lsm/
sudo ./axiom-lsm audit &       # stream denials + grants
python3 -c 'import socket; socket.socket()'   # PermissionError + DENY event
sudo ./axiom-lsm grant <tgid> 0x10000         # grant Rights::NET to a task
sudo ./axiom-lsm run 0x10000 curl example.com # spawn a governed task
sudo ./axiom-lsm detach                       # unload everything
```

## Status

| Piece | State |
|-------|-------|
| `socket_create` gate (Rights::NET) | `partial` — enforcement + ringbuf events |
| Rights inheritance on fork/clone | `roadmap` (parent→child attenuation) |
| More hooks (open/mmap/exec) | `roadmap` |
| Daemon signing events into AX ledger records | `roadmap` (same `Record` format, `ledger-tool` verifies) |

Root bypasses nothing — the hooks still fire; unlisted tasks simply
deny. Security boundary note: this is deny-by-default for *unlisted*
tasks; a task that can write the map (CAP_SYS_ADMIN) is trusted by
design — same trust model as SELinux policy load.
