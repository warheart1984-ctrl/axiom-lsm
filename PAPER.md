# A Constitutional Reference Monitor for AI Agency: Kernel-Mediated Governance for Autonomous Systems

Jon Halstead
Independent — Boyne Falls, Michigan
warheart1984-ctrl

## Abstract

Current AI governance models treat safety as a userspace convention: middleware filters, prompt guards, and policy wrappers that sit around autonomous agents. These layers are bypassable. An agent that can write code, delete data, or open network connections can often find the path around a userspace check.

We present two artifacts implementing the same constitutional model. **Axiom-X** is a Rust x86_64 research kernel — the reference implementation — in which user processes run in ring 3 under per-process page tables and every governed syscall passes a rights check before execution, with decisions recorded to a SHA-256 hash-chained evidence ledger carrying Ed25519-signed checkpoints. **axiom-lsm** is a BPF-LSM module that enforces the same rights model inside a stock Linux kernel: `socket()` returns `-EPERM` for tasks without `Rights::NET`, grants are keyed by task struct (immune to PID namespaces), and every decision is streamed to a ring-buffer audit channel.

Measured results include: a compromised-agent workload refused on all three escape paths (`ax_egress`, escalated spawn, `ax_mmap` → `-EPERM`); 88 of 88 proxy-attested egress signatures verified offline against the kernel ledger; a disk-carried signing identity surviving verification; an external rollback anchor detecting a full-disk image swap; and on Linux, `PermissionError` for unlisted tasks versus `socket ok` under a granted rights mask.

The work applies Anderson's 1972 reference-monitor requirements — tamperproof, always invoked, small enough to verify — to autonomous AI agency. The result is not a new distribution: Linux is trusted with machinery; governance is trusted with agency. They are not the same thing.

## 1 Introduction

Autonomous AI systems increasingly take direct action: writing code, deleting data, sending email, calling APIs, executing commands, spending money. These are decisions with consequences, not passive inferences.

Today's execution model is:

```
AI → Tool → Action
```

with governance bolted on in userspace: prompt filters, API wrappers, LLM proxies, agent frameworks. These are conventions. An agent operating within a convention can often find the path around it — prompt injection, tool-argument manipulation, or simply running under sufficient privilege.

We propose:

```
AI → Request → Kernel Governance → Approve / Deny / Escalate → Action
```

Governance is not a convention but an enforcement point every sensitive action must traverse. An AI can bypass a convention; it has a much harder time bypassing a kernel enforcement point. This is the reference-monitor principle of Anderson (1972): complete mediation, no exceptions.

Two security properties follow:

1. **Deny-by-default** — a task with no recorded rights has no path to the gated operation.
2. **Evidence-first** — every decision, deny or allow, produces a record; the asking is the audit trail.

## 2 Architecture

### 2.1 The Two Artifacts

| | Axiom-X (prototype) | axiom-lsm (application) |
|---|---|---|
| Form | Rust x86_64 kernel | BPF LSM programs + userspace loader |
| Environment | QEMU guest | Stock Linux kernel (BPF LSM) |
| Enforcement | Syscall dispatch: `required_right(nr)` | `lsm/socket_create` hook |
| Rights | Kernel-owned per-process bitmask | `BPF_MAP_TYPE_TASK_STORAGE` per task struct |
| Evidence | On-disk hash-chained ledger, signed checkpoints | Ring-buffer event stream (ledgered by a daemon — roadmap) |
| Status | ~19 commits of evidence-bound work | First enforcement point, working |

The relationship matters: the kernel proved the model — which invariants hold, which mechanisms leak — on a forgiving target. The LSM ports the proven semantics onto real machinery. They share the `Rights` bit values and the deny-by-default rule, not code.

### 2.2 Axiom-X (the kernel)

- **Ring-3 preemptive processes**, per-process page tables with W^X, ELF loading, real `syscall` entry.
- **Rights bitmask** (`axiom-x-capability`): `NET = 1<<16`, `ALLOC = 1<<5`, `SEND = 1<<7`, `DELEGATE`, etc. `required_right(nr)` gates every governed syscall; refusals are recorded.
- **Attenuated delegation**: children receive only a subset of parent rights; granting any nonempty mask requires `DELEGATE`.
- **Bounded rights**: per-process frame quotas; token-bucket egress rate limits — rights are quantities, not just flags.
- **`AX_EGRESS`**: processes cannot open sockets; they petition. `AXE2`-framed request with a SHA-256 trailer; `RSP2` reply carrying a status byte, response digest, and the proxy's Ed25519 signature over `sha256(request)‖sha256(response)` — appended to the kernel ledger as four attestation records.
- **Evidence ledger**: 96-byte records on a raw disk image; SHA-256 chain; Ed25519-signed checkpoints archived on every flush; superblock + journal for crash consistency.
- **Disk-carried identity**: the signing seed lives in sector 259 (`AXIDENT1` block) of the ledger disk — the ISO ships nothing.
- **External anchor**: `ledger-anchor.txt` pins `pubkey, total, head` after each boot; a full-disk swap is detected even though every on-disk signature verifies.

### 2.3 axiom-lsm (the port)

- `lsm/socket_create` program: gates `AF_INET`/`AF_INET6` only — local IPC (`AF_UNIX`, `AF_NETLINK`) passes free. Lesson learned the hard way: gating local sockets breaks `sudo`'s audit channel and locks out the operator.
- `task_rights` is `BPF_MAP_TYPE_TASK_STORAGE`: per-task-struct storage updated from userspace via `pidfd`. Chosen after PID namespaces made tgid-keyed maps unreliable (below).
- `sched_process_fork` tracepoint: copies the parent's rights to the child's task storage — attenuated inheritance; a task can only pass rights it holds.
- Ring-buffer audit stream: every decision emits `{tgid, rights, arg, hook, kind}` where kind ∈ {ALLOW, DENY, INHERIT}.
- Loader (`axiom-lsm`): `attach|detach|grant <tgid> <hex>|run <rights> <cmd>|audit`; objects pin under `/sys/fs/bpf/axiom-lsm/`.

## 3 Implementation Notes (the honest frictions)

The debugging path is itself evidence of the boundary's reality:

**PID namespaces.** Three different values were observed for one process's identity: `getpid()` (namespaced), the `NSpid` fields in `/proc` (which in WSL do not expose the outermost namespace), and the value `bpf_get_current_pid_tgid()` returns at the hook — e.g., 15736 vs 15806 vs 17485. tgid-keyed rights maps cannot be reliably populated from namespaced userspace. The fix — task-local storage keyed by the kernel's own task object — removes the translation entirely and survives `exec` because storage rides `task_struct`.

**Complete mediation cuts both ways.** The first hook version gated every socket family, including `AF_NETLINK`; `sudo`'s PAM audit channel immediately failed with `Operation not permitted`. A reference monitor that mediates too much locks out its operators — the egress gate now covers only real egress.

**Attestation caught two frame bugs.** Adding signatures to the egress frame, the first verify run found: (a) responses larger than the caller's buffer desynced the serial stream — the "signature" was payload tail bytes; fixed by reading the full frame and draining oversized ones; (b) a 10 s deadline raced an 8 s upstream timeout — every petition starved; raised to 30 s.

**A 16-slot module table.** Adding one ELF binary pushed boot modules to 17; `ledger.key` silently fell off the end and checkpoints went unsigned. Caught because verification is automatic, not aspirational.

## 4 Evaluation

### 4.1 Kernel-side evidence (Axiom-X, QEMU)

| Claim | Evidence | Result |
|-------|----------|--------|
| Deny-by-default | `elf-jailbreak` spawned with `Rights::SEND` only; attempts `ax_egress`, escalated `spawn`, `ax_mmap` | `-EPERM` on all three; `[jailbreak] verdict: prose compromised, environment not` |
| Attestation | `ledger-tool verify` with `ATTEST_KEY=<proxy pubkey>` | `88 signatures verified, 0 invalid/incomplete` |
| Chain integrity | same verify, 1,866-record disk | `hash chain: internally consistent`; `checkpoint signature: Valid`; `PASS` |
| Disk identity | `ledger-tool pubkey <disk.img>` reads sector 259 | pubkey `2d8a0b33…`; checkpoints verify under disk's own signer |
| Rollback anchor | anchor inflated to total 2000, verify | `FAIL: disk shows 1150 records but anchor recorded 2000 — disk rolled back or swapped`; restored → `anchor: prefix 1150 verified` |

### 4.2 Linux-side evidence (axiom-lsm)

| Scenario | Expected | Observed |
|----------|----------|----------|
| `socket()` from unlisted task | `EPERM` | `PermissionError: [Errno 1] Operation not permitted`; audit: `tgid 17410 rights 0x0 hook 1 arg 2 -> DENY` |
| `socket()` under `run 0x10000` | allowed | `[axiom-lsm] task granted 0x10000` / `socket ok` |
| Non-INET sockets | unaffected | `sudo` and local IPC unaffected |

### 4.3 What is *not* yet proven

- axiom-lsm's audit events are unsigned until the userspace daemon signs them into ledger records — today they are an event stream, not an attestation.
- Fork inheritance (`sched_process_fork`) is implemented and attaches; its INHERIT event is implemented but not yet demonstrated end-to-end in this paper.
- The LSM gates one hook. `execve`, `open`, `connect`, `ptrace` are unmediated.
- On QEMU a host attacker can read the disk-carried seed; the identity work is architectural, not secrecy.

## 5 Related Work

- **Anderson (1972)**, *Computer Security Technology Planning Study*: the reference monitor — tamperproof, always invoked, verifiable. Our `required_right`/LSM gate is its mechanism; "small enough to verify" argues for the thin gate plus rich evidence rather than a fat policy engine in-kernel.
- **SELinux / AppArmor**: LSM mandatory access control with static, label-driven policy. Different in kind: rights here are runtime-granted quantities with attenuated delegation, and every decision is evidence, not just an audit line.
- **seccomp-bpf**: syscall filtering, static allowlists, no rights model, no evidence chain.
- **KRSI → BPF LSM** (Google): the hook surface this work runs on; used there for anomaly *detection*. We use it for *enforcement* with receipts.
- **gVisor**: userspace syscall interception for isolation — same boundary instinct, different object (isolation, not rights + receipts).
- **TEE attestation**: attests platform state, not decisions; egress attestation here binds request‖response digests at the action level.

## 6 Discussion

**The escape-path question.** The right question is not "can the AI escape" but "where is the escape path." Userspace governance has many (injection, argument encoding, privilege). A kernel gate has exactly the paths it defines — which is why the governed `AX_EGRESS` petition channel and an escalation path are *features*, not holes: a cage without a petition channel just stalls the workload.

**Authority vs intent.** Kernel mediation proves "this task held `Rights::NET` when it called `socket()`" — not that the request was good. Content-level governance (is the *request* reasonable) belongs a layer up — llm-gateway in this stack. Mechanism below, intent above, receipts on both.

## 7 Future Work

- **Signaling daemon**: ringbuf events → the same 96-byte `Record` format → `ledger-tool verify` — the Linux audit trail becomes a signed ledger.
- **Hook coverage**: `file_open` (READ/WRITE), `mmap` (ALLOC), `bprm_check` (EXEC), `connect`.
- **Jailbreak suite on Linux**: the kernel's compromised-agent workload ported to the LSM.
- **SMP / KPTI / bare metal** for the kernel proper.

## 8 Conclusion

Governance for agents cannot be a convention layered over action; it must be the point every action traverses. The kernel prototype proved the model under QEMU — rights gated, denials ledgered, signatures verifiable. The LSM enforced the same constitution on a stock kernel the same day: an unlisted task got `-EPERM`; a granted task got a socket; every decision was recorded.

Linux is trusted with machinery. Governance is trusted with agency. They are not the same thing — and now they are different layers.

**Availability:** Axiom-X at github.com/warheart1984-ctrl/Axiom-X; axiom-lsm pending push.

**Keywords:** AI governance, reference monitor, complete mediation, Linux Security Module, BPF LSM, constitutional compute, evidence engineering, agentic systems.
