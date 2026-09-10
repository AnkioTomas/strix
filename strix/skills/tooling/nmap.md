---
name: nmap
description: Canonical Nmap CLI syntax, two-pass scanning workflow, and sandbox-safe bounded scan patterns.
---

# Nmap CLI Playbook

Official docs:
- https://nmap.org/book/man-briefoptions.html
- https://nmap.org/book/man.html
- https://nmap.org/book/man-performance.html

Canonical syntax:
`nmap [Scan Type(s)] [Options] {target specification}`

High-signal flags:
- `-n` skip DNS resolution
- `-Pn` skip host discovery when ICMP/ping is filtered
- `-sS` SYN scan (root/privileged)
- `-sT` TCP connect scan (no raw-socket privilege)
- `-sV` detect service versions
- `-sC` run default NSE scripts
- `-p <ports>` explicit ports (`-p-` for all TCP ports)
- `--top-ports <n>` quick common-port sweep
- `--open` show only hosts with open ports
- `-T<0-5>` timing template (`-T4` common)
- `--max-retries <n>` cap retransmissions
- `--host-timeout <time>` give up on very slow hosts
- `--script-timeout <time>` bound NSE script runtime
- `-oA <prefix>` output in normal/XML/grepable formats

Authorization first:
- Default: only scan ports listed in the system prompt ``authorized_ports`` for that host (`-p <authorized_ports>`).
- Never use `--top-ports`, `-p-`, or guessed common ports unless Special instructions explicitly authorize full/extra ports.
- If ``authorized_ports`` is empty, do not run proactive discovery nmap on that host.
- Incidental leak: if testing already disclosed a concrete port on an authorized host, you may run a minimal `-p <leaked_ports>` check to verify impact — not a broader sweep.

Agent-safe baseline for automation (authorized ports only):
`nmap -n -Pn --open -p <authorized_ports> -T4 --max-retries 1 --host-timeout 90s -oA nmap_quick <host>`

Common patterns:
- Authorized-port pass:
  `nmap -n -Pn -p <authorized_ports> --open -T4 --max-retries 1 --host-timeout 90s <host>`
- Service/script enrichment on already-authorized open ports:
  `nmap -n -Pn -sV -sC -p <authorized_ports> --script-timeout 30s --host-timeout 3m -oA nmap_services <host>`
- No-root fallback:
  `nmap -n -Pn -sT -p <authorized_ports> --open --host-timeout 90s <host>`
- Full/common-port sweeps (`--top-ports`, `-p-`) ONLY when Special instructions explicitly authorize them.

Critical correctness rules:
- Always set target scope explicitly.
- Prefer two-pass scanning only when broader ports were explicitly authorized: discovery pass, then enrichment pass.
- Always set a timeout boundary with `--host-timeout`; add `--script-timeout` whenever NSE scripts are involved.
- Keep discovery scans on authorized ports only; do not invent "important" ports outside authorization.
- In sandboxed runs, avoid exhaustive sweeps (`-p-`, high `--top-ports`, or wide host ranges) unless explicitly required by Special instructions.
- Do not spam traffic; start with the smallest authorized port set that can answer the question.

Usage rules:
- Add `-n` by default in automation to avoid DNS delays.
- Use `-oA` for reusable artifacts.
- Prefer `-p <authorized_ports>` only; never default to common-port lists or `--top-ports`.
- Do not use `-h`/`--help` for routine usage unless absolutely necessary.

Failure recovery:
- If host appears down unexpectedly, rerun with `-Pn`.
- If scan stalls, tighten scope (`-p` or smaller `--top-ports`) and lower retries.
- If scripts run too long, add `--script-timeout`.

If uncertain, query web_search with:
`site:nmap.org/book nmap <flag>`
