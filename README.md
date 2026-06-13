# sift

**Transparent, self-hosted alert triage that explains every decision and learns from your analysts.**

SOC analysts drown in alerts — thousands a day, most of them false alarms. The
two tools meant to help both have a catch: classic SOAR follows rigid
playbooks that break on anything new, and the AI triage products are
expensive, closed boxes that tell you *what* but never *why*. So analysts
don't trust them, and real threats stay buried in the noise.

sift is a small, opinionated answer to that gap:

- **It shows its work.** Every alert gets an itemised *receipt* — each signal,
  the points it added or removed, and a plain-English reason. An analyst can
  agree or overrule in five seconds. No black box.
- **It learns from you.** When an analyst marks an alert a false alarm, the
  rule that fired it is trusted a little less next time — automatically, and
  visibly on the receipt. No playbook to rewrite.
- **It runs anywhere.** Pure Python standard library. No `pip install`, no
  CDN, no web fonts. Clone it and run it — including on an air-gapped box.

> sift is a starting point, not a finished SIEM. It's built to be read,
> forked, and extended. See the [roadmap](#roadmap).

---

## Quickstart

Requires only Python 3.10+.

```bash
python3 sift.py
```

Then, in another terminal, push a sample alert through it:

```bash
python3 send_sample.py sample_alerts/real_attack.json
```

```
  verdict: ESCALATE   score: 93   (alert #1)
  receipt:
      +48  SIEM severity  —  Wazuh rule level 12 of 15
      +30  Critical asset  —  Target 'dc01' matches critical asset 'dc01'
      +15  Outside business hours  —  Activity at 03:00, outside 08:00-18:00
```

Open **http://127.0.0.1:8000/** to see the triage queue and click any alert
for its full receipt.

---

## How it works

```
   Wazuh alert ──POST──▶  /webhook/wazuh
                              │
                   normalize (flatten the JSON)
                              │
                   score  (run every signal check)
                              │
        ┌─────────────────────┼─────────────────────┐
   score < 20              20 – 59              score ≥ 60
     JUNK                   REVIEW               ESCALATE
  auto-closed,          a human judges        look at this now
  kept with reasons     when they can
```

Each alert is run through a set of independent **signals**. A signal either
stays silent or adds one line to the receipt: a label, a point value, and a
reason. The points are summed into a score, and the score picks the verdict.
That's the whole model — deliberately simple, because the value is in the
transparency, not in cleverness you can't audit.

### The signals

| Signal | Effect | Why |
| --- | --- | --- |
| SIEM severity | `+ level × 4` | trust the SIEM's own rating as a baseline |
| Critical asset | `+30` | the target is on your crown-jewels list |
| Malicious source IP | `+50` | AbuseIPDB flagged the source *(needs key)* |
| Malicious file hash | `+50` | VirusTotal flagged the file *(needs key)* |
| Outside business hours | `+15` | activity at an unusual time |
| Unfamiliar source for user | `+25` | this user has never alerted from this IP before |
| Historically noisy rule | up to `−45` | analysts keep marking this rule a false alarm |
| Repeated noise | `−20` | a flood of identical alerts (scanner-like) |
| Trusted source | `−60` | the source IP is on your allowlist |
| Trusted user | `−40` | the user is on your allowlist (e.g. a service account) |
| Trusted file hash | `−40` | the hash is on your allowlist (e.g. an internal tool) |

Every number lives in [`config.py`](config.py). Tune them to your environment.

### The learning loop

This is what keeps sift from going stale. On the alert page, an analyst marks
each handled alert **Confirm real threat** or **Mark false alarm**. sift keeps
a per-rule tally, and the *Historically noisy rule* signal reads from it:

```
First time a noisy rule fires:   REVIEW   (+20, no track record yet)
After 12 'false alarm' verdicts: JUNK     (+20 −45 = −25)
                                           └─ "false alarm 12/12 times (100%)"
```

The rule sinks on its own, the reason is on the receipt, and you never edited
a playbook. A rule needs a minimum number of decisions before its record is
trusted (so one early mistake can't mute it).

---

## Wiring it to Wazuh

Add an integration block to the Wazuh manager's `ossec.conf` so it forwards
alerts to sift, then restart the manager:

```xml
<integration>
  <name>custom-sift</name>
  <hook_url>http://YOUR_SIFT_HOST:8000/webhook/wazuh</hook_url>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

`<level>` sets the minimum Wazuh rule level to forward. sift accepts the raw
Wazuh alert JSON as-is. (A small wrapper script under
`/var/ossec/integrations/` is the usual way Wazuh delivers these — see the
Wazuh integration docs for the exact shape on your version.)

Not on Wazuh? `POST` any JSON to `/webhook/wazuh`; to support another SIEM's
shape, add a sibling function to [`normalize.py`](normalize.py). Nothing
downstream cares which SIEM an alert came from.

---

## Enrichment (optional)

Set either key as an environment variable (or in a local `.env` file) to turn
on reputation signals. Leave them unset and sift just skips those signals —
it still works.

```bash
export ABUSEIPDB_KEY=...      # source-IP reputation
export VIRUSTOTAL_KEY=...     # file-hash reputation
```

Lookups are cached in the database so the same IP or hash is never queried
twice.

---

## Configuration

Everything tunable is in [`config.py`](config.py), commented:

- `JUNK_BELOW` / `ESCALATE_AT` — the two thresholds between the three buckets
- `WEIGHTS` — how many points each signal is worth
- `CRITICAL_ASSETS` — substrings that mark a target as critical
- `ALLOWLIST_IPS` / `ALLOWLIST_USERS` / `ALLOWLIST_HASHES` — trusted IPs
  (or CIDR ranges), usernames, and file hashes
- `BUSINESS_START` / `BUSINESS_END` — your local business hours
- duplicate-flood and track-record thresholds

Edit, save, restart.

---

## Project layout

```
sift.py          HTTP server + routing (entry point)
config.py        all the dials you tune
normalize.py     raw Wazuh JSON  ->  flat internal alert
checks.py        the signals — each returns one receipt line or nothing
scorer.py        gather context, run checks, sum to a score + verdict
enrich.py        optional AbuseIPDB / VirusTotal lookups
db.py            SQLite: alerts, per-rule track record, enrichment cache
views.py         the dashboard and the receipt page
send_sample.py   push an alert file at a running sift
sample_alerts/   three alerts that land in each of the three buckets
```

---

## Roadmap

v1 deliberately does one thing well: explainable, learning triage on top of a
single SIEM. Every roadmap item is held to the same bar as v1: **no AI model,
no third-party API, no ongoing cost** — sift's signals and learning loop are
built entirely from data it already has (the alert itself and its own
history), so it works identically on an air-gapped box as it does online.
That's also sift's answer to the wave of "AI SOC analyst" products: explainable
and free to run, not a closed box with a per-alert bill. Natural next steps,
roughly in order:

- **Bulk actions & queue ergonomics** — the dashboard now has a search box
  (filter by rule, target, source IP, or user, combinable with the verdict
  chips); keyboard-driven triage, age filters, and snooze are still open.
- **More signals** — identity context (a user alerting from a source IP sift
  has never seen them use before) and allowlists for users/hashes are in.
  Still open: geo/ASN velocity, threat-intel beyond two feeds.
- **More sources** — Suricata, Elastic, GuardDuty, M365 — each a new normaliser.
- **Outbound actions** — push verdicts back to TheHive / a ticketing system,
  notify chat; keep the human in the loop for anything destructive.
- **Smarter noisy-rule modelling** — confidence intervals on the track record,
  per-asset rule tuning, drift alerts when a quiet rule turns noisy.

Contributions welcome — the codebase is small on purpose so a new signal or a
new SIEM is an afternoon, not a project.

---

## Honest limitations

- This is **triage, not detection**. sift prioritises the alerts your SIEM
  already produces; it doesn't find new ones.
- The scoring is intentionally simple and rule-based. That's a feature (every
  decision is auditable), but it means quality depends on good weights and an
  active feedback habit.
- A `JUNK` verdict auto-*closes*, it never *deletes* — every alert and its
  receipt is retained, so a wrong auto-close is always recoverable and
  reviewable. Set your thresholds conservatively until you trust it.
- SQLite and a threaded standard-library server are great for a team's volume,
  not for a global MSSP firehose. The roadmap notes where you'd grow out of it.

## License

MIT — do what you like, no warranty.
