# Wazuh Detection Engineering Lab — AD Brute-Force Detection & Fleet Health

A hands-on blue-team exercise: generate well-known, benign attacker activity against a
self-owned, instrumented Windows Server 2022 domain controller, then work the Wazuh SIEM
from the analyst side to document detection coverage — which rules fire, their rule IDs,
and how they map to MITRE ATT&CK — followed by an agent-health / fleet-reporting exercise.

All activity was performed against isolated VirtualBox VMs I own and control.

---

## Environment

| Component | Detail |
|---|---|
| SIEM | Wazuh manager + indexer + dashboard (Linux), agent **v4.7.5** |
| Target | Windows Server 2022 Standard (Eval), domain controller `WIN-S0ESS5L5DIC` |
| Attacker | Kali Linux (`10.0.2.5`), netexec (`nxc`) + nmap |
| Endpoint telemetry | Sysmon installed on the DC, ingested via `Microsoft-Windows-Sysmon/Operational` |
| Target IP | `10.0.2.10` (agent id `001`) |

Note: a second Windows endpoint agent (`WIN11-LAB`) and a third registered agent were kept
powered off to conserve host RAM. The lab therefore ran against the DC as a single live
target — reflected in the fleet-health numbers below.

### Architecture

```
     ┌──────────────────────────┐
     │  Wazuh (Linux)           │
     │  manager+indexer+dash    │◄──── alerts / agent keepalives
     └──────────────────────────┘
                  ▲
      Wazuh agent │ (v4.7.5)
                  │
     ┌────────────┴───────────┐
     │ WIN-S0ESS5L5DIC        │
     │ Windows Server 2022 DC │
     │ + Sysmon               │
     └────────────────────────┘
                  ▲
                  │ SMB auth attempts / nmap scan
          ┌───────┴───────┐
          │  Kali 10.0.2.5│
          └───────────────┘
```

---

## Activity Generated

| # | Activity | Command | ATT&CK |
|---|---|---|---|
| 1 | TCP port/service scan | `nmap -sS -p- 10.0.2.10` | T1046 |
| 2 | SMB failed-auth burst | `nxc smb 10.0.2.10 -u Administrator -p wrong1..wrongN` | T1110 |
| 3 | Agent service stop | `Stop-Service -Name Wazuh` (on the DC) | T1562.001 |

---

## Detections Observed

| Activity | Windows event | Wazuh rule ID | Rule description | Level | ATT&CK |
|---|---|---|---|---|---|
| Single failed logon | 4625 | **60122** | Logon failure – unknown user or bad password | 5 | T1078 / T1531 |
| Brute force (composite) | 4625 ×N | **60204** | Multiple Windows logon failures | 10 | **T1110** (Brute Force / Credential Access) |

**Key finding — atomic vs. composite detection.** The individual failed logons matched the
atomic rule **60122** (level 5), which Wazuh tags as Valid Accounts (T1078/T1531). Once
failures crossed the frequency threshold (rule fired at `rule.frequency: 8` within the
window), the correlation engine escalated to the composite rule **60204** (level 10),
correctly mapped to **T1110 Brute Force**. Documenting both shows how the SIEM escalates
from single-event matching to frequency-based correlation — the atomic rule alone would not
convey an attack in progress.

Sample composite alert (redacted):
```
rule.id:          60204
rule.level:       10
rule.description: Multiple Windows logon failures
rule.frequency:   8
rule.groups:      windows, windows_security, authentication_failures
rule.mitre.id:    T1110
rule.mitre.tactic: Credential Access
agent.name:       WIN-S0ESS5L5DIC
data.win.eventdata.ipAddress: 10.0.2.5   (Kali)
```

### Coverage gap — network scanning (documented, not a pass)

A raw `nmap` SYN scan against the DC produced **no Wazuh alert and no Sysmon EID 3 events**.
Sysmon's NetworkConnect logging (SwiftOnSecurity-style config) filters heavily and primarily
records host-initiated outbound connections, so an inbound scan left no telemetry to match.
This is a real detection-coverage limitation: reliably catching internal scanning on Windows
requires either Windows Filtering Platform audit logging (event 5156/5157) or a custom
volume-based correlation rule — neither present out of the box. Recorded as a known gap
rather than forcing a detection.

---

## Fleet Health / Agent Reporting

Demonstrated agent-health monitoring by stopping the Wazuh service on the DC and observing
the fleet status degrade, then recover.

| State | Active | Disconnected | Coverage |
|---|---|---|---|
| Baseline | 1 | 1 | 33.33% |
| After `Stop-Service` | 0 | 2 | 0.00% |
| After `Start-Service` | 1 | 1 | 33.33% |

- Stopping the agent flipped `WIN-S0ESS5L5DIC` active → disconnected; restarting restored it.
- An attacker performing this maps to **T1562.001 (Impair Defenses: Disable or Modify Tools)**.
- **Standing fleet findings:** `WIN11-LAB` shows **disconnected** (registered, not reporting)
  and a third agent shows **never connected** (registered, never checked in). Both are
  legitimate fleet-health items — the exact conditions a SOC monitors for under "ensure
  agents are healthy and reporting across the fleet."

---

## Screenshots Captured

- [x] Discover — Sysmon telemetry landing in Wazuh (baseline, end-to-end pipeline confirmed)
- [x] Expanded 60122 alert JSON (atomic failed-logon, rule.mitre fields)
- [x] rule.level histogram showing escalation (levels 3 / 5 / 6 / 10 / 12)
- [x] Expanded 60204 alert JSON (composite brute-force, T1110)
- [x] Agents view — baseline 33.33% coverage
- [x] Agents view — 0.00% coverage after agent stop
- [x] Agents table — DC agent restored to active (recovery)

---

## Skills Demonstrated

- Generated known adversary behavior and validated SIEM detection coverage end-to-end
- Distinguished atomic (60122) vs. frequency-based composite (60204) detection logic
- Mapped detections to MITRE ATT&CK from raw alert JSON, and caught a level-12 Sysmon
  false-positive (svchost / T1055) that was unrelated to the attack — triage judgment,
  not just alert-reading
- Documented a real detection gap (Windows scan visibility) with the remediation path,
  rather than reporting a clean pass
- Performed agent-health / fleet-reporting monitoring: induced and recovered an agent
  outage, and identified standing disconnected / never-connected agents
- Onboarded Sysmon telemetry via `ossec.conf` eventchannel and verified ingestion
- Windows AD auth event analysis (4624 / 4625 / 4634), NTLM logonType 3

## Reproduction Notes

- Fire 8+ failed auth attempts in a tight window to trip the 60204 composite, not just 60122.
- `nxc smb <ip> -u Administrator` authenticates NTLM against the local account → 4625 only;
  4771/4776 require targeting a **domain** account.
- Raw nmap scans do not alert out of the box — Sysmon NetworkConnect filtering suppresses them.
- Confirm the agent service name with `Get-Service *wazuh*` before stopping it.
- All lab credentials must be scrubbed from screenshots before publishing.
