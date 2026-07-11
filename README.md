# Phishing Analysis — Amazon Impersonation (Credential Harvest)

Full manual triage of a real phishing email from a honeypot corpus: header/auth
analysis, MIME structure, attachment triage, hash + reputation lookup, and IOC
extraction across the full kill chain.

**Sample:** `sample-1014.eml` (phishing_pot corpus)
**Verdict:** Confirmed Amazon brand-impersonation phishing — credential harvest
**Analyst:** J. Gaskin

---

## Kill chain

```
Email (spoofs Amazon, authenticated as arulnotes.com)
  → PDF attachment (StatementAmazon#CASE-..., benign structure, social-engineering lure)
    → "Verify Now" button
      → i-centrix.com (newly-registered credential-harvest domain, now defunct)
```

---

## Method + findings

### 1. Header / authentication analysis

```
spf=pass   smtp.mailfrom=arulnotes.com
dkim=pass  header.d=arulnotes.com
dmarc=pass header.from=arulnotes.com
helo=mail-vk1-f193.google.com (209.85.221.193)
```

All three authentication checks passed and aligned to `arulnotes.com`, sent via
Google Workspace infrastructure.

**Key reasoning:** authentication verifies *origin*, not *intent* or *identity-vs-claim*.
A passing result only proves the mail genuinely originated from `arulnotes.com`
unaltered — it says nothing about whether that domain is trustworthy or whether it
is who the message claims to be. An attacker trivially passes SPF/DKIM/DMARC for
their own domain. The Google relay is not itself suspicious (legitimate senders use
Google/ESPs constantly); the relevant fact is that the authenticated domain is
`arulnotes.com`, not Amazon.

### 2. Display-name vs. authenticated-domain mismatch

Decoded MIME encoded-words (RFC 2047):

- **From (display):** "Amazon Service" : actual address
  `cs-noreplygrusakgrusuk0384911323@arulnotes.com` (gibberish-padded local part
  faking a service noreply)
- **Subject:** `[Important] Unauthorized access; Your Amazon...`

The message *presents* as Amazon while the *authenticated* domain is `arulnotes.com`.
Claim and cryptographic identity contradict: the core phishing indicator.

**Evasion signal:** the word "Amazon" in the subject and display name was padded with
zero-width / junk bytes (`A=DC=BF m=DC=BF a...`) to defeat keyword-based brand-impersonation
filters while still rendering as "Amazon" to the human. Deliberate filter evasion is a
near-conclusive intent signal as a legitimate Amazon email has no reason to hide the word "Amazon."

### 3. Body / URL extraction

Plaintext URL extraction returned empty — **because the body was base64-encoded**,
not because the message was linkless. Empty extraction on raw text means "cannot see
links in raw form," which required checking MIME structure next.

### 4. MIME structure → attachment

```
Content-Type: application/pdf; name="StatementAmazon#CASE-3987187467.pdf"
Content-Disposition: attachment
Content-Transfer-Encoding: base64
```

Payload was an attachment, not a body link. Filename impersonates Amazon with a
fabricated case number — social-engineering pretext.

### 5. Attachment triage (VirusTotal)

Extracted and hashed the PDF (never opened locally). VirusTotal classification:
**malicious — brand-impersonation phishing lure.**

Notably, the PDF structure is **technically clean** — no embedded JavaScript, no
exploit, no auto-execution. Nothing to detonate. It is a **social-engineering lure**:
alarmist "unauthorized access" text, fabricated 24-hour lockout urgency, and a
"Verify Now" button linking to an external credential-harvest URI. The malicious
classification is driven by intent and the outbound link, not executable behavior.

> Present on VirusTotal but **not** MalwareBazaar — consistent with a lure. MalwareBazaar
> catalogs technically-malicious files (executables, droppers, active maldocs); a clean-structured
> lure PDF has no malware to catalog. VT scores intent/reputation, so it flags it. The split
> is expected, not a discrepancy.

### 6. IOC extraction — VT Relations (noise filtering)

The file's relations listed 12 domains. All but one were **environmental noise**
from the detonation sandbox:

- `*.adobe.com`, `*.adobe.io` — Acrobat Reader update/licensing/telemetry (any opened PDF hits these)
- `accounts.google.com`, `*.googleapis.com`, `*.gvt1.com`, `gstatic.com` — sandbox browser/OS calling home
- `www.linkedin.com` — document footer / scenery

**One domain stood out:** `i-centrix.com` — the credential-harvest target.

- Note: `i-centrix.com` (hyphen) is its **own registered domain**, not a subdomain of
  the legitimate `centrix.com`. Chosen to visually resemble legit infrastructure.
- Only domain with a detection (1/91).
- **Registered 2025-10-09** — newly-created. Fresh registration + presence in a phish
  + detection = harvest infrastructure. Domain age was the decisive low-effort signal.

### 7. Payload domain status

`i-centrix.com` did **not resolve at time of analysis** — consistent with a
burned/taken-down phishing domain given its detection history and age. (Takedown
mechanism inferred, not directly observed.)

---

## Indicators of Compromise

| Layer | Indicator | Notes |
|-------|-----------|-------|
| Sender domain | `arulnotes.com` | Authenticated origin; ≠ claimed identity (Amazon) |
| Origin IP | `209.85.221.193` | Google Workspace relay (`mail-vk1-f193.google.com`) |
| From (spoofed) | "Amazon Service" `<cs-noreplygrusakgrusuk0384911323@arulnotes.com>` | Display/domain mismatch |
| Attachment | `StatementAmazon#CASE-3987187467.pdf` | Lure PDF; VT-malicious; benign structure |
| Attachment SHA256 | `73a0e5d5582ec223d1d4216df506c5ce6961948f76d39f73a84e966b607ea1b7` | From `Get-FileHash` / Python extraction |
| Harvest domain | `i-centrix.com` | Registered 2025-10-09; 1/91; defunct at analysis time |

---

## Assessment

Confirmed Amazon brand-impersonation phishing delivering a credential-harvest link
via a benign-structured lure PDF. The email authenticated cleanly as `arulnotes.com`
but presented as Amazon; the attachment used urgency and a fabricated case number to
drive the victim to `i-centrix.com`, a newly-registered harvest domain now defunct.
No executable payload — the mechanism is social engineering end to end.

**MITRE ATT&CK:** T1566.001 (Spearphishing Attachment), T1204.002 (User Execution),
T1656 (Impersonation)

**Recommended actions:**
- Block: `arulnotes.com`, `i-centrix.com`, attachment SHA256
- Hunt: sender domain + attachment hash across mail logs
- User: if delivered and clicked — credential reset

---

## Tools

PowerShell (`Select-String`, `Resolve-DnsName`, `Get-FileHash`), Python `email` module,
VirusTotal, urlscan.io. No commercial tooling — fully reproducible manual triage.# Security Labs
