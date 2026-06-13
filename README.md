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

> [!NOTE]
> **Full disclosure:** sift was built with an AI coding assistant — the kind
> whose "yearly" token quota has a way of evaporating in about a month of
> real use. Somewhere around the third top-up, the project came out the other
> side with strong feelings about software that needs a live AI subscription
> just to tell you a login looks weird at 3am. So sift doesn't have one.
> Every signal above runs on data it already owns, for the price of
> electricity. The irony is noted. The bill is not.

---

## For normal people

Skip this if you're already reaching for `config.py`. This bit is the
elevator-pitch version for anyone who clicked a link and wants to know what
this thing actually does.

**The problem:** every security tool — antivirus, firewalls, cloud logs —
fires off alerts. Most of them are nothing. A few of them are everything. The
hard part isn't *detecting* trouble, it's figuring out which of today's 500
alerts deserve five minutes of a human's attention.

**What sift does:** it reads every alert as it arrives and writes a little
*receipt* — a few lines explaining, in plain English, why the alert looks
scary or boring. Something like:

```
+48  SIEM severity            — the security tool rated this a 12 out of 15
+30  Critical asset           — this happened on your domain controller
+15  Outside business hours   — nobody should be doing this at 3am
```

Add those up, and sift sorts the alert into one of three piles: **ignore it**
(but keep the receipt, just in case), **someone should glance at this**, or
**look at this right now**. Whenever a human corrects it — "no, that one was
nothing" — sift remembers, and that kind of alert gets quieter on its own
next time.

**What it costs:** nothing, on an ongoing basis. No subscription, no
per-alert API fee, no "AI SOC analyst" bill that scales with how paranoid you
are. It's a small Python program and a database file — run it on a laptop, a
spare server, or an air-gapped box.

### Try it

You need Python 3.10 or newer and nothing else.

```bash
python3 sift.py
```

Then, in another terminal, feed it a sample alert:

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

Open **http://127.0.0.1:8000/** to see it land in the triage queue, and click
it to see the full receipt.

---

## For nerds

The rest of this document is the technical reference — architecture, the
scoring model, wiring sift up to real sources, and every dial in
`config.py`.

### How it works

```
   SIEM alert ──POST──▶  /webhook/<source>
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

#### The signals

| Signal | Effect | Why |
| --- | --- | --- |
| SIEM severity | `+ level × 4` | trust the SIEM's own rating as a baseline |
| Critical asset | `+30` | the target is on your crown-jewels list |
| Malicious source IP | `+50` | AbuseIPDB flagged the source *(needs key)* |
| Malicious file hash | `+50` | VirusTotal flagged the file *(needs key)* |
| Outside business hours | `+15` | activity at an unusual time |
| Unfamiliar source for user | `+25` | this user has never alerted from this IP before |
| Source-IP velocity | `+35` | this user alerted from 3+ different source IPs within an hour — impossible travel without needing a GeoIP database |
| Historically noisy rule | up to `−45` | analysts keep marking this rule a false alarm |
| Repeated noise | `−20` | a flood of identical alerts (scanner-like) |
| Trusted source | `−60` | the source IP is on your allowlist |
| Trusted user | `−40` | the user is on your allowlist (e.g. a service account) |
| Trusted file hash | `−40` | the hash is on your allowlist (e.g. an internal tool) |

Every number lives in [`config.py`](config.py). Tune them to your environment.

#### The learning loop

This is what keeps sift from going stale. On the alert page, an analyst marks
each handled alert **Confirm real threat** or **Mark false alarm**. sift keeps
a per-rule tally, and the *Historically noisy rule* signal reads from it:

```
First time a noisy rule fires:    REVIEW       (+20, no track record yet)
First 'false alarm' verdict:      JUNK         (+20 −9  = +11)
                                                └─ "false alarm 1/1 times (100%) —
                                                    21% confident it's at least that noisy"
After 12 'false alarm' verdicts:  deeper JUNK  (+20 −34 = −14)
                                                └─ "false alarm 12/12 times (100%) —
                                                    76% confident it's at least that noisy"
```

The rule sinks on its own, the reason is on the receipt, and you never edited
a playbook. The penalty is the lower bound of a confidence interval on the
rule's false-positive rate, not the raw rate — so one early "false alarm"
moves the score immediately but conservatively, and the penalty firms up as
more decisions come in. No arbitrary "wait for N observations" cliff.

---

### Wiring it to Wazuh

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

---

### Other sources

sift normalises a few other formats out of the box, each on its own webhook
route. Every route returns the same `{id, score, verdict, receipt}` JSON, and
an `ESCALATE` verdict triggers the [outbound notification](#outbound-notifications-optional)
just like a Wazuh alert.

| Route | What to send |
| --- | --- |
| `POST /webhook/suricata` | One line of Suricata's `eve.json` (an `"event_type": "alert"` record). Other event types (flow, dns, http, ...) are accepted but skipped — point sift at the whole `eve.json` without flooding the queue. |
| `POST /webhook/elastic` | An Elastic Common Schema (ECS) document — a Kibana detection alert via a webhook connector, or any ECS-shaped JSON from Beats/Elastic Agent/Logstash. |
| `POST /webhook/guardduty` | An AWS GuardDuty finding (e.g. forwarded from EventBridge via a small Lambda, or replayed from the console's "View finding JSON"). |
| `POST /webhook/m365` | A Microsoft Graph Security API alert (the `/security/alerts` shape) — e.g. forwarded from Defender for Endpoint, Defender for Identity, Defender for Cloud Apps, or Sentinel. |
| `POST /webhook/generic` | Any JSON at all — fields are pulled out using the dotted paths in `config.GENERIC_FIELD_MAP`, no Python required. |

Each source's severity is normalised onto sift's 0-15 scale (the same scale
Wazuh rule levels use), so the *SIEM severity* signal and all the thresholds
in [Configuration](#configuration) work identically no matter where an alert
came from. The receipt's first line always says exactly how that mapping was
done, e.g. `Suricata severity 1 (1=highest, 3=lowest) -> level 15 of 15` or
`Elastic risk score 85/100 -> level 13 of 15`.

Try any of them locally:

```bash
python3 send_sample.py sample_alerts/suricata_alert.json
python3 send_sample.py sample_alerts/elastic_alert.json
python3 send_sample.py sample_alerts/guardduty_finding.json
python3 send_sample.py sample_alerts/m365_alert.json
python3 send_sample.py sample_alerts/generic_alert.json
```

`send_sample.py` guesses the right endpoint from the JSON's shape, so all
six sample files (including the three Wazuh ones) work with the same
command.

None of these match your tool? `POST` any JSON to `/webhook/generic` and map
its fields in `config.GENERIC_FIELD_MAP` — or add a sibling `normalize_*`
function to [`normalize.py`](normalize.py) for a first-class integration.
Nothing downstream cares which source an alert came from.

---

### Enrichment (optional)

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

### Outbound notifications (optional)

Set `ESCALATE_WEBHOOK_URL` (env var or `.env`) to a Slack, Mattermost, or
Discord incoming-webhook URL and sift will POST a short summary there every
time an alert is scored ESCALATE:

```bash
export ESCALATE_WEBHOOK_URL=https://hooks.slack.com/services/...
```

```
sift ESCALATE -- alert #3 (score 93)
Rule: 92052 -- Suspicious process execution consistent with credential dumping
Target: dc01  Source: 45.146.165.37
Top signals: SIEM severity (+48); Critical asset (+30); Outside business hours (+15)
```

The POST runs on a background thread with a short timeout — a slow or
unreachable webhook never delays or breaks alert ingestion. Leave it unset
and sift stays exactly as before.

---

### Configuration

Everything tunable is in [`config.py`](config.py), commented:

- `JUNK_BELOW` / `ESCALATE_AT` — the two thresholds between the three buckets
- `WEIGHTS` — how many points each signal is worth
- `CRITICAL_ASSETS` — substrings that mark a target as critical
- `ALLOWLIST_IPS` / `ALLOWLIST_USERS` / `ALLOWLIST_HASHES` — trusted IPs
  (or CIDR ranges), usernames, and file hashes
- `BUSINESS_START` / `BUSINESS_END` — your local business hours
- `DUPLICATE_WINDOW_HOURS` / `DUPLICATE_FLOOD_COUNT` — duplicate-flood thresholds
- `NOISY_RULE_CONFIDENCE_Z` — how conservatively the learning loop reads a
  rule's false-positive track record
- `VELOCITY_WINDOW_HOURS` / `VELOCITY_IP_THRESHOLD` — how many distinct
  source IPs a user can alert from in how short a window before it looks
  like impossible travel
- `GENERIC_FIELD_MAP` — dotted-path field mapping for `POST /webhook/generic`,
  for wiring up a tool that doesn't have a dedicated normaliser
  (see [Other sources](#other-sources))

Edit, save, restart.

---

### Project layout

```
sift.py          HTTP server + routing (entry point)
config.py        all the dials you tune
normalize.py     raw alert JSON (Wazuh, Suricata, Elastic, GuardDuty, M365/Graph, generic) -> flat internal alert
checks.py        the signals — each returns one receipt line or nothing
scorer.py        gather context, run checks, sum to a score + verdict
enrich.py        optional AbuseIPDB / VirusTotal lookups
notify.py        optional chat webhook on ESCALATE
db.py            SQLite: alerts, per-rule track record, enrichment cache
views.py         the dashboard and the receipt page
send_sample.py   push an alert file at a running sift (guesses the endpoint)
sample_alerts/   one alert per source — the three Wazuh ones cover JUNK/REVIEW/ESCALATE
```

---

### Roadmap

v1 deliberately does one thing well: explainable, learning triage on top of a
single SIEM. Every roadmap item is held to the same bar as v1: **no AI model,
no third-party API, no ongoing cost** — sift's signals and learning loop are
built entirely from data it already has (the alert itself and its own
history), so it works identically on an air-gapped box as it does online.
That's also sift's answer to the wave of "AI SOC analyst" products: explainable
and free to run, not a closed box with a per-alert bill. Natural next steps,
roughly in order:

- **Bulk actions & queue ergonomics** — the dashboard has a search box (filter
  by rule, target, source IP, or user, combinable with the verdict chips), an
  age filter ("older than 1h/24h/7d"), per-alert snooze (hide it from the
  queue for a while, with a one-click "wake now"), checkbox-driven bulk
  feedback (select rows, mark them all real/false in one click — the learning
  loop catches up on a noisy rule immediately), and keyboard-driven triage
  (`j`/`k` to move through the queue, `t`/`f` to decide an alert and
  auto-advance to the next one in the same filter).
- **More signals** — identity context (a user alerting from a source IP sift
  has never seen them use before), source-IP velocity (impossible travel,
  derived from sift's own history — no GeoIP database needed), and allowlists
  for users/hashes are in. Still open: threat-intel beyond two feeds.
- **More sources** — Suricata, Elastic/ECS, AWS GuardDuty, M365/Microsoft
  Graph security alerts, and a config-driven generic JSON mapper are in (see
  [Other sources](#other-sources)). Still open: CrowdStrike, osquery.
- **Outbound actions** — sift can POST a short summary to a Slack/Mattermost/
  Discord webhook on ESCALATE (see [Outbound notifications](#outbound-notifications-optional)).
  Still open: push verdicts back to TheHive / a ticketing system; keep the
  human in the loop for anything destructive.
- **Smarter noisy-rule modelling** — the penalty now scales with a Wilson
  confidence interval on the track record (see [the learning loop](#the-learning-loop)).
  Still open: per-asset rule tuning, drift alerts when a quiet rule turns noisy.

Contributions welcome — the codebase is small on purpose so a new signal or a
new SIEM is an afternoon, not a project.

---

### Honest limitations

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
