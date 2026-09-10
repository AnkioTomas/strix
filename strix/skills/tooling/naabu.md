---
name: naabu
description: Naabu port-scanning syntax with host input, scan-type, verification, and rate controls.
---

# Naabu CLI Playbook

Official docs:
- https://docs.projectdiscovery.io/opensource/naabu/usage
- https://docs.projectdiscovery.io/opensource/naabu/running
- https://github.com/projectdiscovery/naabu

Canonical syntax:
`naabu [flags]`

High-signal flags:
- `-host <host>` single host
- `-list, -l <file>` hosts list
- `-p <ports>` explicit ports (supports ranges)
- `-top-ports <n|full>` top ports profile
- `-exclude-ports <ports>` exclusions
- `-scan-type <s|c|syn|connect>` SYN or CONNECT scan
- `-Pn` skip host discovery
- `-rate <n>` packets per second
- `-c <n>` worker count
- `-timeout <ms>` per-probe timeout in milliseconds
- `-retries <n>` retry attempts
- `-proxy <socks5://host:port>` SOCKS5 proxy
- `-verify` verify discovered open ports
- `-j, -json` JSONL output
- `-silent` compact output
- `-o <file>` output file

Authorization first (HARD):
- Only scan ports listed in the system prompt ``authorized_ports`` for that host.
- Default: `-p <authorized_ports>` only. Never use `-top-ports` or guessed common ports unless Special instructions explicitly authorize full/extra ports.
- If ``authorized_ports`` is empty, do not run naabu against that host for discovery.

Agent-safe baseline for automation (authorized ports only):
`naabu -list hosts.txt -p <authorized_ports> -scan-type c -Pn -rate 300 -c 25 -timeout 1000 -retries 1 -verify -silent -j -o naabu.jsonl`

Common patterns:
- Authorized ports with controlled rate:
  `naabu -list hosts.txt -p <authorized_ports> -scan-type c -rate 300 -c 25 -timeout 1000 -retries 1 -verify -silent -o naabu.txt`
- Single-host authorized-port check:
  `naabu -host target.tld -p <authorized_ports> -scan-type c -rate 300 -c 25 -timeout 1000 -retries 1 -verify`
- Root SYN mode (if available) on authorized ports:
  `sudo naabu -list hosts.txt -p <authorized_ports> -scan-type syn -rate 500 -c 25 -timeout 1000 -retries 1 -verify -silent`
- `-top-ports` / full sweeps ONLY when Special instructions explicitly authorize them.

Critical correctness rules:
- Use `-scan-type connect` when running without root/privileged raw socket access.
- Always set `-timeout` explicitly; it is in milliseconds.
- Set `-rate` explicitly to avoid unstable or noisy scans.
- `-timeout` is in milliseconds, not seconds.
- Keep port scope on authorized ports only; do not invent "important" ports outside authorization.
- Do not spam traffic; start with the smallest authorized port set and conservative rate/worker settings.
- Prefer `-verify` before handing ports to follow-up scanners.

Usage rules:
- Keep host discovery behavior explicit (`-Pn` or default discovery).
- Use `-j -o <file>` for automation pipelines.
- Prefer `-p <authorized_ports>` only; never default to common-port lists or `-top-ports`.
- Do not use `-h`/`--help` for normal flow unless absolutely necessary.

Failure recovery:
- If privileged socket errors occur, switch to `-scan-type c`.
- If scans are slow or lossy, lower `-rate`, lower `-c`, and tighten `-p`/`-top-ports`.
- If many hosts appear down, compare runs with and without `-Pn`.

If uncertain, query web_search with:
`site:docs.projectdiscovery.io naabu <flag> usage`
