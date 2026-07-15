# AWS CloudTrail → Splunk Detection Engineering Lab

A hands-on detection engineering lab that replicates a production cloud-monitoring pipeline: generate real AWS security events, ship CloudTrail logs into Splunk, and build scheduled detections for the activity that matters in a regulated (HITRUST / SOC 2 / PCI) environment.

The goal was not to follow a tutorial but to reproduce the actual workflow of a cloud SOC: an always-noisy AWS account, an ingestion pipeline with real-world lag, and detections that have to survive that lag without silently failing.

---

## Architecture

```
AWS account
  └─ CloudTrail (multi-region trail)
       └─ S3 bucket  (aws-cloudtrail-logs-…, us-east-2)
            └─ Splunk Add-on for AWS  (generic S3 input, inputs.conf)
                 └─ index=aws, sourcetype=aws:cloudtrail
                      └─ 5 scheduled detections → Triggered Alerts
```

**Stack**
- AWS free-tier account with a $1 budget guardrail
- CloudTrail multi-region trail delivering to S3
- Splunk Enterprise 10.4.1 (Windows, local)
- Splunk Add-on for AWS 8.1.2
- Dedicated IAM user (`splunker`) with programmatic access keys for the input

---

## Stage 1 — Generate events on purpose

A detection is only real if you can prove it fires. Before writing anything, I generated the events each detection is meant to catch:

- Created and deleted an IAM user, attached/detached a managed policy → `CreateUser`, `DeleteUser`, `AttachUserPolicy`, `DetachUserPolicy`
- Created a key pair → `CreateKeyPair`
- Failed console logins on purpose (valid IAM username, wrong password) → `ConsoleLogin` with `responseElements.ConsoleLogin=Failure`
- Logged in once as root → root-usage signal
- Toggled S3 Block Public Access off then on → `PutBucketPublicAccessBlock`

---

## Stage 2 — Ingestion pipeline

**Add-on GUI bug (Splunk 10.4.1).** The Splunk Add-on for AWS "Inputs" GUI throws *"something went wrong"* on this version due to a `structured_data_service` 404 — a UI-framework bug, not a config error. Rather than downgrade, I configured the input by hand in `inputs.conf`, which is the standard approach in any real deployment anyway.

**Working stanza (generic S3 input):**

```ini
[aws_s3://cloudtrail_lab]
sourcetype = aws:cloudtrail
index = aws
disabled = 0
```


**Validation:**
```spl
index=aws sourcetype=aws:cloudtrail
```
returned fully parsed CloudTrail events — both the seeded Stage 1 events and ongoing AWS service noise (e.g. Resource Explorer `DescribeSubnets`, `readOnly=true`).

---

## What CloudTrail is (and isn't)

CloudTrail logs **API / control-plane activity** — infrastructure changes — not application-layer data access. Application and PHI-access logs are separate sources that feed the SIEM alongside CloudTrail. A real AWS account is never quiet: the large majority of CloudTrail volume is automated service noise, and the core SOC skill is filtering that noise (e.g. `readOnly=false`) to surface human actions. Every detection below is built around that separation.

---

## Stage 3 — Detections

Five scheduled detections. Each was validated against events I generated in Stage 1, saved as a scheduled alert, and (for the flagship) triggered end-to-end and confirmed in **Triggered Alerts**.

### 1. Failed console logins (brute force / password spray)

```spl
index=aws sourcetype=aws:cloudtrail eventName=ConsoleLogin "responseElements.ConsoleLogin"=Failure
  _index_earliest=-16m@m _index_latest=now
| stats count min(_time) as first_seen max(_time) as last_seen by userIdentity.userName, sourceIPAddress
| where count>=3
| convert ctime(first_seen) ctime(last_seen)
```
**Fires when:** the same user + source IP fails console login 3+ times within one arrival window.
**MITRE:** T1110 (Brute Force).

### 2. Root account usage

```spl
index=aws sourcetype=aws:cloudtrail "userIdentity.type"=Root eventType!=AwsServiceEvent readOnly=false
| table _time, eventName, sourceIPAddress, userAgent, "responseElements.ConsoleLogin"
```
**Fires when:** the root account performs any non-service, write action. In a regulated environment root should never be used day-to-day, so any hit is reportable.
**MITRE:** T1078.004 (Valid Accounts: Cloud Accounts).

### 3. IAM privilege changes

```spl
index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com
  eventName IN (CreateUser, DeleteUser, CreateAccessKey, AttachUserPolicy, DetachUserPolicy,
                PutUserPolicy, CreatePolicyVersion, AttachRolePolicy, UpdateAssumeRolePolicy)
| table _time, eventName, userIdentity.arn, "requestParameters.userName", "requestParameters.policyArn"
```
**Fires when:** identity or permission boundaries change — privilege escalation and persistence signals.
**MITRE:** T1098 (Account Manipulation), T1136 (Create Account).

### 4. S3 bucket exposure

```spl
index=aws sourcetype=aws:cloudtrail eventSource=s3.amazonaws.com
  eventName=PutBucketPublicAccessBlock
| eval blocked=coalesce('requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls',
                        'requestParameters.PublicAccessBlockConfiguration.RestrictPublicBuckets')
| where blocked="false"
| table _time, eventName, "requestParameters.bucketName", userIdentity.arn, sourceIPAddress
```
**Fires when:** Block Public Access is disabled on a bucket — the classic data-exposure precursor. A broader version of the search also watches `PutBucketAcl`, `PutBucketPolicy`, `DeleteBucketPolicy`, and `DeletePublicAccessBlock`; the `blocked="false"` filter narrows to changes that actually move a bucket toward public.
**MITRE:** T1530 (Data from Cloud Storage Object).

### 5. CloudTrail tampering

```spl
index=aws sourcetype=aws:cloudtrail
  eventName IN (StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors)
| table _time, eventName, userIdentity.arn, sourceIPAddress
```
**Fires when:** logging itself is stopped, deleted, or reconfigured — a defense-evasion signal, since attackers disable logging early. Expected hit count in a healthy environment is zero; the control is that the search *exists* and is watched.
**MITRE:** T1562.008 (Impair Defenses: Disable Cloud Logs).

---

## The core engineering problem: ingestion lag vs. search windows

The most important thing this lab taught — and the one worth reading closely — is that a scheduled detection against a lagged log source will silently fail if it searches by event time.

**The bug.** CloudTrail delivers to S3 every ~5–15 minutes; the generic S3 input then polls on its own interval. So events arrive in Splunk 15–45 minutes *after* they happen. An alert scheduled every 15 minutes searching "last 15 minutes by `_time`" runs like this:

1. Event happens at 2:00 (`_time` = 2:00).
2. 2:15 run searches 2:00–2:15 by `_time` — event not ingested yet → **0 results**.
3. Event lands at 2:40, still stamped `_time` = 2:00.
4. 2:45 run searches 2:30–2:45 by `_time` — event exists but its `_time` is outside the window → **0 results, forever.**

The event falls into the gap between when the window looks and when the data arrives. The alert reports `status=success, result_count=0` every run — it looks healthy while catching nothing.

**The fix — search by index time, not event time.** `_index_earliest=-16m@m` / `_index_latest=now` gate on when events *arrived*, not when they occurred, with the alert's own time-range picker set wide (Last 24h) so it doesn't clip. Late-arriving data is now impossible to miss, with no duplicates.

**Related failure modes surfaced in the same lab:**
- **Unsaved edit.** Editing SPL in the search bar does not update a saved alert. The fix has to be saved *into the alert config* — verified by re-reading the config, not by assuming.
- **App-context scoping.** Fired alerts only appear on the Triggered Alerts page under the app they belong to (Search & Reporting). With the page defaulted to another app context, working alerts look like they never fired.
- **Scheduler lag on a non-server host.** On a laptop that sleeps, the scheduler wakes to a backlog of missed ticks and burns through them (observed lag up to ~21,000s), tripping the Search Lag health warning and skipping runs on the concurrency limit. Harmless in a lab; in production it means detection coverage has a hole the shape of the downtime — which is exactly why SIEMs run on always-on infrastructure, and why scheduler lag is itself a monitored signal.

---

## Skills demonstrated

- CloudTrail → S3 → Splunk ingestion, configured by hand in `inputs.conf`
- SPL: `stats`, `eval`, `where`, `coalesce`, `convert`, `table`, index-time field scoping
- Detection design mapped to MITRE ATT&CK, with noise-vs-signal filtering (`readOnly=false`)
- Scheduled alerting and the lag/windowing constraints that govern it
- Log-driven debugging via Splunk's internal scheduler logs (`index=_internal sourcetype=scheduler`)

## Notes / limitations

- Uses the generic S3 input; the production-grade pattern is SQS-based S3 (CloudTrail → S3 → SNS → SQS → Splunk), which scales better and avoids full-bucket re-listing.
- Splunk trial converts to Splunk Free after 60 days; Splunk Free does not support scheduled alerting, so the detections persist as reports run manually unless a developer license is applied.
