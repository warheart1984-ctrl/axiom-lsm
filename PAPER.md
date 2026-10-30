# A Constitutional Reference Monitor for AI Agency: Kernel-Mediated Governance for Autonomous Systems

Jon Halstead
Independent — Boyne Falls, Michigan
warheart1984-ctrl

*v0.5 — v0.2 added threat model and scope corrections; v0.4 the signed-evidence daemon; v0.5 closes the SCM_RIGHTS bypass*

## Abstract

Current AI governance models treat safety as a userspace convention: middleware filters, prompt guards, and policy wrappers that sit around autonomous agents. These layers are bypassable. An agent that can write code, delete data, or open network connections can often find the path around a userspace check.

We present two artifacts implementing the same constitutional model. **Axiom-X** is a Rust x86_64 research kernel — the reference implementation — in which user processes run in ring 3 under per-process page tables and every governed syscall passes a rights check before execution, with decisions recorded to a SHA-256 hash-chained evidence ledger carrying Ed25519-signed checkpoints. **axiom-lsm** is a BPF-LSM module that enforces the same rights model inside a stock Linux kernel: `socket()` returns `-EPERM` for tasks without `Rights::NET`, grants are keyed by task struct (immune to PID namespaces), and every decision is streamed to a ring-buffer audit channel that a daemon signs into the kernel's own ledger format — verified offline by the same `ledger-tool`.

Measured results include: a self-authored compromised-agent workload refused on all three attempted escape paths (`ax_egress`, escalated spawn, `ax_mmap` → `-EPERM`); 88 of 88 proxy signatures over request‖response digests verified offline — which binds the response bytes to the proxy's key, and asserts nothing about upstream provenance; a disk-carried signing identity surviving verification; an external rollback anchor detecting a full-disk image swap; and on Linux, `PermissionError` for ungranted tasks versus `socket ok` under a granted rights mask.

The work applies Anderson's 1972 reference-monitor requirements — tamperproof, always invoked, small enough to verify — to autonomous AI agency, and is honest about which of the three it currently satisfies (§3). The result is not a new distribution: Linux is trusted with machinery; governance is trusted with agency. They are not the same thing.

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
| Enforcement | Syscall dispatch: `required_right(nr)` | `lsm/socket_create` + `connect` + `sendmsg` hooks |
| Rights | Kernel-owned per-process bitmask | `BPF_MAP_TYPE_TASK_STORAGE` per task struct |
| Evidence | On-disk hash-chained ledger, signed checkpoints | Ring-buffer event stream (ledgered by a daemon — roadmap) |
| Status | Evidence-bound development history | First enforcement point, working |

The kernel exercised the model — which invariants hold, which mechanisms leak — on a forgiving target. The LSM ports the semantics onto real machinery. They share the `Rights` bit values and the deny-by-default rule, not code.

### 2.2 Axiom-X (the kernel)

- **Ring-3 preemptive processes**, per-process page tables with W^X, ELF loading, real `syscall` entry.
- **Rights bitmask** (`axiom-x-capability`): `NET = 1<<16`, `ALLOC = 1<<5`, `SEND = 1<<7`, `DELEGATE`, etc. `required_right(nr)` gates every governed syscall; refusals are recorded.
- **Attenuated delegation**: children receive only a subset of parent rights; granting any nonempty mask requires `DELEGATE`.
- **Bounded rights**: per-process frame quotas; token-bucket egress rate limits — rights are quantities, not just flags.
- **`AX_EGRESS`**: processes cannot open sockets; they petition. `AXE2`-framed request with a SHA-256 trailer; `RSP2` reply carrying a status byte, response digest, and the proxy's Ed25519 signature over `sha256(request)‖sha256(response)` — appended to the kernel ledger as four attestation records.
- **Evidence ledger**: 96-byte records on a raw disk image; SHA-256 chain; Ed25519-signed checkpoints archived on every flush; superblock + journal for crash consistency.
- **Disk-carried identity**: the signing seed lives in sector 259 (`AXIDENT1` block) of the ledger disk — the ISO ships nothing.
- **External anchor**: `ledger-anchor.txt` pins `pubkey, total, head` after each boot; a full-disk swap is detected even though every on-disk signature verifies (trust properties in §3).

### 2.3 axiom-lsm (the port)

- `lsm/socket_create`, `lsm/socket_connect`, `lsm/socket_sendmsg` programs: gate `AF_INET`/`AF_INET6` only — local IPC (`AF_UNIX`, `AF_NETLINK`) passes free. Lesson learned the hard way: gating local sockets breaks `sudo`'s audit channel and locks out the operator. Creation is gated *and* action is gated, so a passed fd confers nothing.
- `task_rights` is `BPF_MAP_TYPE_TASK_STORAGE`: per-task-struct storage updated from userspace via `pidfd`. Chosen after PID namespaces made tgid-keyed maps unreliable (§4.3).
- `lsm/task_alloc` hook: copies the parent's rights to the child's task storage at fork. This is a **plain copy bounded above by the parent** — a child can never hold rights the parent lacked, so no amplification is possible. It is *not* yet the kernel's stronger model: Axiom-X requires `DELEGATE` to grant a nonempty mask and supports narrowing at spawn; the LSM's inheritance neither narrows nor checks `DELEGATE`. The weaker form is intentional for v0 (it matches POSIX fork semantics — a forked child *is* the parent); attenuation-by-narrowing belongs to the spawn/delegation API in future work.
- Ring-buffer audit stream: every decision emits `{tgid, rights, arg, hook, kind}` where kind ∈ {ALLOW, DENY, INHERIT}.
- `record` command: drains the ring into an Axiom-X **format-v3 ledger disk image** — the identical layout the kernel writes (96-byte hash-chained records, journaled tail rewrites, Ed25519-signed checkpoints, `AXIDENT1` disk-carried identity in sector 259). The unmodified `ledger-tool verify` audits it.
- Loader (`axiom-lsm`): `attach|detach|grant <tgid> <hex>|run <rights> <cmd>|audit|record <img> [every]`; objects pin under `/sys/fs/bpf/axiom-lsm/`.

## 3 Threat Model and the Three Properties

Anderson's reference monitor requires three properties. We claim each only to the extent evidence supports:

**Adversary.** The governed subject is an **unprivileged userspace process** — the agent and anything it spawns — assumed to be fully compromised: arbitrary code execution, arbitrary arguments, arbitrary forks, full knowledge of the mechanism.

**Trusted base.** The operator (root, `CAP_SYS_ADMIN`, `CAP_BPF`) is *trusted*, not governed. This is a real limitation, not a footnote:

- `axiom-lsm detach` removes the gate entirely; the BPF objects pin under `/sys/fs/bpf/axiom-lsm` and any process with `CAP_BPF`/root can unlink them. The LSM is tamperproof *against the governed task*, not against the operator. Deployments requiring operator-mistrust need pinned-down module policy (e.g., lockdown mode, signed-BPF enforcement, IMA appraisal of the loader) — out of scope here.
- On the QEMU side, a host attacker can read the disk image including the signing seed; the disk-carried identity is an architectural property (identity travels with data), not a secrecy claim.
- The external anchor `ledger-anchor.txt` lives on the **host filesystem**, written by the boot harness outside the guest's reach. It therefore detects a disk rollback or swap by an adversary who can modify the disk image *but not the host-side file*. An adversary who can rewrite both defeats it — the correct fix is anchoring to storage the disk-writer cannot reach (remote append-only service, hardware counter), listed as future work.

**Property checklist:**

| Anderson property | Status | Evidence |
|---|---|---|
| Always invoked | Satisfied for the gated surface | Every `AF_INET`/`AF_INET6` `socket()` traverses `lsm/socket_create`; DENY/ALLOW events captured for every observed call |
| Tamperproof | **Partial** | Holds vs the governed unprivileged task (it cannot detach, unpin, or edit task storage — it lacks `CAP_BPF`). Does **not** hold vs root/`CAP_BPF` |
| Small enough to verify | Argued, bounded | Gate + loader = **295 lines** (111 BPF, 184 loader). The honest caveat: the real TCB includes the kernel's BPF verifier and LSM framework — our addition is small; the base it rides on is not |

**Scope.** `attach` is **system-wide, not scoped to a governed set**: while attached, *every* task on the host that lacks a `task_rights` entry is denied `AF_INET`/`AF_INET6` socket creation. That is the intended default-deny posture — but it means attachment is itself a privileged policy act, and a production deployment would scope enforcement to a cgroup or labeled set rather than the whole system.

**Bypasses — closed and open:**

- **`SCM_RIGHTS` fd-passing — CLOSED (v0.5).** `socket_create` alone mediated *creation*, not receipt: a permitted task could pass an INET fd to a denied task over `AF_UNIX`, and the denied task could `connect`/`send` on it. The gate now also mediates `socket_connect` (hook 3, destination port audited) and `socket_sendmsg` (hook 4 — required because UDP reaches arbitrary destinations without `connect`). Demonstrated: granted task passes a live socket to an ungranted task; the ungranted task's `connect` on the passed fd returns `-EPERM` and lands a signed DENY record (`tgid 6324 rights 0x0 hook 3 arg 2304 -> DENY`, port 9 network-order). The mediation boundary moved from *object creation* to *network action*.
- **Inbound paths are unmediated**: `bind`/`listen`/`accept`/`recvmsg` are not gated — the model governs *egress*, not listening. A denied task can still hold a bound INET socket via a passed fd; incoming connections on it are not currently denied (the send path is, so no data leaves — but `sendmsg` on a *connected-but-passed* socket is now denied too, so the residual is receive-only).
- **`AF_UNIX` sockets are unmediated by design** (operator escape hatch).

## 4 Evaluation

### 4.1 Kernel-side evidence (Axiom-X, QEMU)

| Claim | Evidence | Result |
|-------|----------|--------|
| Deny-by-default | `elf-jailbreak` spawned with `Rights::SEND` only; attempts `ax_egress`, escalated `spawn`, `ax_mmap` | `-EPERM` on all three; `[jailbreak] verdict: prose compromised, environment not` |
| Attestation | `ledger-tool verify` with `ATTEST_KEY=<proxy pubkey>` | `88 signatures verified, 0 invalid/incomplete` |
| Chain integrity | same verify run, 1,866-record disk | `hash chain: internally consistent`; `checkpoint signature: Valid`; `PASS` |
| Disk identity | `ledger-tool pubkey <disk.img>` reads sector 259 | pubkey `2d8a0b33…`; checkpoints verify under disk's own signer |
| Rollback anchor | on a *separate* 1,150-record disk: anchor inflated to total 2000, verify | `FAIL: disk shows 1150 records but anchor recorded 2000 — disk rolled back or swapped`; restored → `anchor: prefix 1150 verified` |

**Scope of these results.** The `elf-jailbreak` workload is a fixture we wrote — it demonstrates that deny-by-default holds on the three paths *we chose to attempt*, not that no other path exists. The 88/88 figure establishes that the proxy's Ed25519 key signed the digests of the request and response bytes that traversed the wire; it proves integrity and binding of *those bytes to that signer*, and asserts nothing about the upstream model's output, its provenance, or its correctness. The 1,866- and 1,150-record figures come from **different disks/runs** — one the attestation-verify run, one the rollback-anchor demonstration — not a single continuous ledger.

### 4.2 Linux-side evidence (axiom-lsm)

| Scenario | Expected | Observed |
|----------|----------|----------|
| `socket()` from ungranted task | `EPERM` | `PermissionError: [Errno 1] Operation not permitted`; audit: `tgid … rights 0x0 hook 1 arg 2 -> DENY` |
| `socket()` under `run 0x10000` | allowed | `[axiom-lsm] task granted 0x10000` / `socket ok` |
| Forked child of granted task | inherits, allowed | `[audit] tgid 2277 rights 0x10000 hook 2 arg 18874368 -> INHERIT` then `tgid 2278 rights 0x10000 hook 1 arg 2 -> ALLOW`; `child socket ok` |
| Non-INET sockets | unaffected | `sudo` and local IPC unaffected |
| LSM decisions become signed evidence | `record` daemon → v3 image → `ledger-tool verify` | `hash chain: internally consistent from genesis`; `checkpoint signature: Valid`; `8 signed checkpoints verified`; `PASS: 12 records verified from genesis (2 denies)` |
| `SCM_RIGHTS` bypass attempt | `-EPERM` at `connect` on the passed fd | `[audit] tgid 6324 rights 0x0 hook 3 arg 2304 -> DENY`; `denied: [Errno 1] Operation not permitted` |

### 4.3 The honest frictions (debugging as evidence)

**PID namespaces.** Three different values were observed for one process's identity: `getpid()` (namespaced), the `NSpid` fields in `/proc` (which in WSL do not expose the outermost namespace), and the value `bpf_get_current_pid_tgid()` returns at the hook — e.g., 15736 vs 15806 vs 17485. tgid-keyed rights maps cannot be reliably populated from namespaced userspace. The fix — task-local storage keyed by the kernel's own task object — removes the translation entirely and survives `exec` because storage rides `task_struct`.

**Complete mediation cuts both ways.** The first hook version gated every socket family, including `AF_NETLINK`; `sudo`'s PAM audit channel immediately failed with `Operation not permitted`. A reference monitor that mediates too much locks out its operators — the egress gate now covers only real egress.

**Hook surface reality.** The first inheritance attempt used the `sched_process_fork` tracepoint; the kernel rejected it (`func 'sched_process_fork' doesn't have 5-th argument`). `lsm/task_alloc` turned out to be the better hook anyway — it hands over the child `task_struct` directly, so no `bpf_task_from_pid` resolution is needed at all.

**Stacked bpffs mounts hide live pins.** Mounting `bpf` at `/sys/fs/bpf` twice creates two filesystem instances; pins on the hidden lower mount keep old programs attached and enforcing — with their own unreachable `task_rights` maps, which read 0 and deny. Symptom: the audit ring logged ALLOW (new program) while the task still received `-EPERM` (stale program). `bpftool link list` showed four LSM links where two were expected; unmounting until the count matched, then one clean mount and reattach, resolved it. An attach must verify its environment, not assume it.

**Attestation caught two frame bugs.** Adding signatures to the egress frame, the first verify run found: (a) responses larger than the caller's buffer desynced the serial stream — the "signature" was payload tail bytes; fixed by reading the full frame and draining oversized ones; (b) a 10 s deadline raced an 8 s upstream timeout — every petition starved; raised to 30 s.

**A 16-slot module table.** Adding one ELF binary pushed boot modules to 17; `ledger.key` silently fell off the end and checkpoints went unsigned. Caught because verification is automatic, not aspirational.

### 4.4 What is *not* yet proven

- Records are durable only after a checkpoint: a daemon killed mid-window loses its un-checkpointed tail (provisional records are dropped on resume — by design, matching the kernel's signed-prefix semantics).
- Receive-side paths (`bind`/`accept`/`recvmsg`) are unmediated (§3) — egress is governed, listening is not yet.
- Non-network classes are unmediated: `execve`, `open`, `mmap`, `ptrace` are unmediated.
- Tamperproofness against root/`CAP_BPF` is not claimed (§3).
- Inheritance is a copy, not a narrowing delegation (§2.3); `DELEGATE` is not ported.
- Enforcement is system-wide while attached; there is no cgroup/label scoping (§3).

## 5 Related Work

- **Anderson (1972)**, *Computer Security Technology Planning Study*: the reference monitor — tamperproof, always invoked, verifiable. Our `required_right`/LSM gate is its mechanism; "small enough to verify" argues for the thin gate plus rich evidence rather than a fat policy engine in-kernel.
- **SELinux / AppArmor**: LSM mandatory access control with static, label-driven policy. Different in kind: rights here are runtime-granted quantities with bounded inheritance, and every decision is evidence, not just an audit line.
- **seccomp-bpf**: syscall filtering, static allowlists, no rights model, no evidence chain.
- **KRSI → BPF LSM** (Singh, Google): the hook surface this work runs on. KRSI was designed for enforcement — LSM hooks return values and can deny — and has been deployed for both detection and mitigation; our earlier draft's detection-only characterization was wrong. The difference is the *object governed* (per-task runtime-granted rights with receipts), not the mechanism class.
- **Tetragon** (Cilium/Isovalent): eBPF observability **and enforcement** — it kills processes and overrides return values today, not detection only. Again: same mechanism class, different governance object.
- **Landlock**: the closest cousin — an LSM for *unprivileged self-restriction*, stacked via `landlock_create_ruleset`. The contrast is instructive: Landlock lets a process voluntarily confine *itself and its children*; axiom-lsm is operator-installed mediation of a subject that does not consent. Inverse trust directions, complementary uses.
- **Capsicum** (FreeBSD): capability mode — rights attenuated to a fixed set on file descriptors, `cap_enter` irreversible. The philosophical ancestor of "attenuated rights on objects"; we apply the vocabulary to tasks and make grants runtime-revocable by the operator.
- **seL4**: formally verified capability microkernel — takes attenuation, delegation (`seL4_CNode_*`), and the reference-monitor discipline to its logical conclusion *with proofs*. We borrow the rights/attenuation vocabulary without the proofs; seL4 is where this design space ends if taken seriously to its limit.
- **gVisor**: userspace syscall interception for isolation — same boundary instinct, different object (isolation, not rights + receipts).
- **TEE attestation**: attests platform state, not decisions; egress attestation here binds request‖response digests at the action level.

## 6 Discussion

**The escape-path question.** The right question is not "can the AI escape" but "where is the escape path." Userspace governance has many (injection, argument encoding, privilege). A kernel gate has exactly the paths it defines — which is why the governed `AX_EGRESS` petition channel and an escalation path are *features*, not holes: a cage without a petition channel just stalls the workload. It is also why §3's known bypasses matter more than the denied paths — the honest escape-path list is the `SCM_RIGHTS` row, not the threat-model boilerplate.

**Authority vs intent.** Kernel mediation proves "this task held `Rights::NET` when it called `socket()`" — not that the request was good. Content-level governance (is the *request* reasonable) belongs a layer up — llm-gateway in this stack. Mechanism below, intent above, receipts on both.

## 7 Future Work

- **Receive-side coverage**: `bind`/`accept`/`recvmsg` if inbound mediation is wanted.
- **Hook coverage**: `file_open` (READ/WRITE), `mmap` (ALLOC), `bprm_check` (EXEC), `ptrace`.
- **Scoped enforcement**: bind the gate to a cgroup or label set rather than system-wide.
- **Delegation narrowing on the LSM**: port the `DELEGATE` check and spawn-time mask attenuation.
- **Remote anchoring**: move `ledger-anchor` to storage the disk-writer cannot reach.
- **Jailbreak suite on Linux**: the kernel's compromised-agent workload ported to the LSM, plus attempts against the stated bypasses.
- **SMP / KPTI / bare metal** for the kernel proper.

## 8 Conclusion

Governance for agents cannot be a convention layered over action; it must be the point every action traverses. The kernel prototype exercised the model under QEMU — rights gated, denials ledgered, signatures verifiable. The LSM enforced the same constitution on a stock kernel the same day: an ungranted task got `-EPERM`; a granted task got a socket; a forked child inherited bounded rights; every decision was recorded.

We claim a reference monitor for the gated surface against the governed task — and we say plainly where that claim stops: the operator, the unmediated syscalls, the passed file descriptor. The escape paths are listed, not hidden. That is what makes the rest of it worth reading.

Linux is trusted with machinery. Governance is trusted with agency. They are not the same thing — and now they are different layers.

**Availability:** Axiom-X at github.com/warheart1984-ctrl/Axiom-X; axiom-lsm at github.com/warheart1984-ctrl/axiom-lsm.

**Keywords:** AI governance, reference monitor, complete mediation, Linux Security Module, BPF LSM, constitutional compute, evidence engineering, agentic systems.
