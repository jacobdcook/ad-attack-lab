# Wazuh logtest — 2026-11-21

The [live run](run-2026-11-21.md) checked the rules by matching fields by hand.
This run feeds the same events through a real Wazuh engine and records the rule
ID that actually fired.

- Engine: `wazuh/wazuh-manager:4.9.1` container, `--network none` (no ports).
- Rules: every `detections/wazuh_*.xml` concatenated into
  `/var/ossec/etc/rules/local_rules.xml`, checked with `wazuh-analysisd -t`.
- Events: exported from DC01 after the run (`Get-WinEvent ... ToXml()`, only
  events from before the export boot), converted to the agent's `{"win":...}`
  JSON with [`tests/wazuh/to_wazuh.py`](../tests/wazuh/to_wazuh.py). 116 events:
  every 4768 with PreAuthType 0, every 4769 for `svc_*`, every 4728, every 4662
  with a replication GUID, every Sysmon 10 that touched lsass.

## How logtest was run

`wazuh-logtest` never routes input through the agent-only `windows_eventchannel`
decoder, so it decodes Windows JSON as `json` and rule 60000 never matches.
Wazuh's own ruleset test harness (`ruleset/testing/runtests.py`,
`enable_win_eventlog_tests`) handles this by editing rule 60000 to
`<decoded_as>json</decoded_as>` and dropping `<category>`. I did the same in the
container and nothing else.

```bash
docker run -d --name adlab-wazuh-logtest --network none wazuh/wazuh-manager:4.9.1
docker exec adlab-wazuh-logtest sed -i '/<rule id="60000"/,/<\/rule>/{/<category>ossec<\/category>/d;s/<decoded_as>windows_eventchannel</<decoded_as>json</}' /var/ossec/ruleset/rules/0575-win-base_rules.xml
cat detections/wazuh_*.xml > local_rules.xml   # then docker cp + wazuh-control restart
docker cp tests/wazuh adlab-wazuh-logtest:/tmp/wlt
docker exec adlab-wazuh-logtest /var/ossec/framework/python/bin/python3 /tmp/wlt/run_logtest.py \
  /tmp/wlt/main.jsonl /tmp/wlt/kerb_real.jsonl /tmp/wlt/kerb_replay3x.jsonl /tmp/wlt/kerb_plus4synthetic.jsonl
```

`run_logtest.py` uses the `WazuhLogtest` class from the manager's own
`wazuh_logtest.py` (what the `wazuh-logtest` CLI runs), one session per file so
frequency rules keep state. Single events piped into the plain CLI give the same
Phase 3 result.

## Results (final rules)

| Captured event | Count | Rule fired | Level |
|---|---|---|---|
| 4768 jsmith, PreAuthType 0, RC4 (AS-REP roast) | 2 | **100152** (new) | 12 |
| 4769 svc_sql + svc_backup, RC4 (Kerberoast) | 2 | **100153** (new, building block) | 3 |
| 4728 jsmith added to Domain Admins by rpatel (ACL abuse) | 1 | **100155** (new) | 12 |
| 4728 Administrator added to Domain Admins by ANONYMOUS LOGON (dcpromo) | 1 | **100155** | 12 |
| 4728 other groups during dcpromo | 2 | stock 60160 / 60168 | 5 / 10 |
| 4662 replication GUID by Administrator (secretsdump DCSync) | 45 | **100151** | 14 |
| Sysmon 10 powershell.exe -> lsass, 0x1010 (controlled read) | 1 | **100150** | 12 |
| Sysmon 10 MsMpEng.exe -> lsass, 0x101000 | 9 | stock 92900 | 12 |
| Sysmon 10 MsMpEng.exe / svchost.exe -> lsass, 0x1000 | 53 | stock 61612 | 0 |

Notes:

- One secretsdump produced 45 4662 events and 45 level-14 alerts. Real but noisy.
- 100155 also fired on the domain's own promotion (Administrator into Domain
  Admins at build time). Correct by the rule; it is the baseline change a
  production DC would have once.
- The Defender 0x101000 hits on stock 92900 are a stock-rule false positive, not
  one of mine. Its `C:\\\\Program Files` exclusion expects doubled backslashes
  and never matches the decoded path.

## Kerberoast threshold

The lab made 2 RC4 service-ticket requests. The Sigma rule and 100154 want more
than 5 distinct SPNs from one IP in 5 minutes.

| Replay | Events | Distinct SPNs | 100154 fired? |
|---|---|---|---|
| The 2 real events | 2 | 2 | no (both 100153 only) |
| The 2 real events, 3 times | 6 | 2 | no (`different_field` holds) |
| The 2 real + 4 clones with `ServiceName` changed to `svc_synth1..4` | 6 | 6 | **yes, on the 6th** |

The clones are synthetic: copies of the real svc_backup 4769 with only the
service name and record ID changed. They prove the
threshold logic, not that the lab produced a Kerberoast alert. On this two-SPN
domain the real attack only gets the level-3 100153.

## What logtest caught that field-matching missed

The first pass (rules exactly as committed) had two silent misses:

1. **100150 never fired.** The stock rule 92900 (also a child of Sysmon event
   10) is evaluated before local rules and claimed the powershell 0x1010 event.
   Fix: `<if_sid>61612, 92900</if_sid>` so 100150 sits under both.
2. **100150 matched Defender.** With the parent fixed, the unanchored
   `0x1010|0x1410` matched `0x101000` as a substring and fired on all 9 Defender
   events. The field-match check said this mask "correctly does not match"; in
   Wazuh it did. Fix: `^0x1010$|^0x1410$`.

100153 had the same parent problem as 100150 (stock 60106 -> 92651 claim 4769
first), fixed with `<if_sid>60106, 92651</if_sid>`. 100151, 100152 and 100155
fired with `if_group windows_security` as written.

## Rules added

| ID | File | Sigma equivalent |
|---|---|---|
| 100152 | `detections/wazuh_asrep.xml` | asrep_roast.yml |
| 100153, 100154 | `detections/wazuh_kerberoast.xml` | kerberoast.yml |
| 100155 | `detections/wazuh_da_group_change.xml` | da_group_change.yml |

Written by hand. sigma-cli is not installed here and pySigma has no official
Wazuh backend, so there was no converter to trust.

## WS01: a real LSASS dump (2026-11-21, later same day)

The LSASS result above used a stand-in: a PowerShell `OpenProcess(0x1010)` on the
DC, not a real dumper. To test the rule honestly I built WS01, a Windows 10 Pro
client (Win10 22H2 image; the Win10 Enterprise eval ISO is no longer offered post
end-of-support, and Win11 eval forces TPM/SecureBoot on the VM), joined it to
`CORP.LOCAL` on the isolated adlab network, installed the same Sysmon config, and
ran two real dumps against lsass:

- `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <pid> ... full`
- `procdump64.exe -accepteula -ma lsass.exe`

Both produced a ~51 MB dump. Sysmon logged 54 event-10 opens on lsass. The access
masks the real tools used, and what logtest fired:

| Source | GrantedAccess | Count | Rule fired |
|---|---|---|---|
| procdump64.exe | 0x1fffff | 2 | stock 61612, level 0 — **miss** |
| rundll32.exe (comsvcs) | 0x1fffff | 1 | stock 61612, level 0 — **miss** |
| rundll32.exe (comsvcs) | 0x1410 | 1 | **100150, level 12 — hit** |
| MsMpEng.exe (Defender) | 0x1000 | 41 | stock 61612, level 0 |
| svchost.exe | 0x1000 / 0x3000 | 9 | stock 61612, level 0 |

(Events in `tests/wazuh/ws01_events.jsonl`; the four dumper events in
`ws01_dumpers.jsonl`.)

### The honest result

**procdump -ma misses rule 100150 entirely.** A full `-ma` dump opens lsass with
`0x1fffff` (PROCESS_ALL_ACCESS), which is not in the rule's `^0x1010$|^0x1410$`
list, so logtest returns only the stock level-0 rule. No alert.

**comsvcs MiniDump is caught, but barely.** It opens lsass twice: once with
`0x1fffff` (missed) and once with `0x1410` (caught by 100150 at level 12). The
alert fires on the second open, not the first. If comsvcs had used only the
all-access handle, it would have slipped past too.

The Sigma rule `lsass_access.yml` keys on the same two masks (`0x1010`, `0x1410`),
so by its field logic it reaches the identical verdict: it matches the single
comsvcs `0x1410` open and misses every `0x1fffff` open, i.e. all of procdump.

So the part-1 stand-in (`0x1010`) flattered the rule. A real credential dumper
mostly uses `0x1fffff`, and the narrow two-mask list does not catch it. To catch
procdump the rule would need `0x1fffff` (and `0x1438`, another common procdump
mask) added, at the cost of more false positives, since backup and AV agents also
request broad access. That is a real tuning tradeoff, not a one-line win, so I am
recording the miss rather than quietly widening the rule.

### The fix (same day)

Rule 100150 and `lsass_access.yml` now match:

| Mask | Why |
|---|---|
| `0x1010`, `0x1410` | read memory (Mimikatz sekurlsa; comsvcs 2nd open) — kept |
| `0x1438`, `0x143a` | read + write/operation, + create thread (procdump, Mimikatz) |
| `0x1fffff` | PROCESS_ALL_ACCESS (procdump `-ma`, comsvcs 1st open) — the miss |
| `0x1f0fff`-`0x1f3fff` | all-access values on older builds and tools |

The Wazuh match is `pcre2` `(?i)^0x(1010|1410|1438|143a|1fffff|1f[0-3]fff)$`,
still anchored, still under `61612, 92900`.

**Exclusions, full path only:**

- `C:\Program Files\Windows Defender\MsMpEng.exe`
- `C:\ProgramData\Microsoft\Windows Defender\Platform\<one version dir>\MsMpEng.exe`

That is the whole list. Every benign lsass open captured on DC01 and WS01 was
Defender (`0x1000`, `0x101000`) or svchost (`0x1000`, `0x3000`). None of those
masks are in the new list, so no captured benign event needed an exclusion and
there is no other legit full-access open to list. svchost is deliberately **not**
excluded: it never asked for a high-risk mask here, and excluding it would hide a
dumper injected into svchost. The Defender exclusion is there because Defender
can request broad access during scans; it matches the full path, so a renamed
`MsMpEng.exe` dropped anywhere else still alerts.

No real Defender event exercises the exclusion, so
`tests/wazuh/lsass_defender_synthetic.jsonl` holds five clones of a real Defender
event with only `sourceImage` and `grantedAccess` changed (synthetic, like the
Kerberoast clones).

### Before / after (logtest, every captured Sysmon 10 on lsass)

| Event | Count | Before | After |
|---|---|---|---|
| WS01 procdump64.exe `0x1fffff` | 2 | 61612, level 0 — **miss** | **100150, level 12** |
| WS01 rundll32 comsvcs `0x1fffff` | 1 | 61612, level 0 — **miss** | **100150, level 12** |
| WS01 rundll32 comsvcs `0x1410` | 1 | 100150, level 12 | 100150, level 12 |
| DC01 powershell.exe `0x1010` (stand-in) | 1 | 100150, level 12 | 100150, level 12 |
| DC01 + WS01 MsMpEng.exe `0x1000` | 50 | 61612, level 0 | 61612, level 0 |
| DC01 MsMpEng.exe `0x101000` | 9 | stock 92900, level 12 | stock 92900, level 12 (not 100150) |
| DC01 + WS01 svchost.exe `0x1000` / `0x3000` | 53 | 61612, level 0 | 61612, level 0 |
| synthetic: Defender Program Files path, `0x1fffff` | 1 | — | 61612, level 0 (excluded) |
| synthetic: Defender Platform path, `0x1fffff` | 1 | — | 61612, level 0 (excluded) |
| synthetic: `C:\lab\MsMpEng.exe`, `0x1fffff` | 1 | — | **100150** (name alone does not exclude) |
| synthetic: `C:\Users\Public\Windows Defender\MsMpEng.exe`, `0x1410` | 1 | — | **100150** |
| synthetic: Platform path two dirs deep, `0x1fffff` | 1 | — | **100150** |

Non-LSASS events were unchanged (100151 x45, 100152 x2, 100155 x2, 100153/100154
on the Kerberoast sets). The Sigma rule, checked with the same field logic in
Python (no sigma-cli here), gives the same hit/no-hit on every row.

**The tradeoff.** Matching `0x1fffff` means anything that opens lsass with full
access alerts unless its exact path is allowlisted: backup agents, EDR and
non-Defender AV, crash dumpers like WER, and admins running procdump on purpose.
None appeared in this lab, so none are excluded; a real network will need its
own path allowlist built from a week of its own Sysmon 10 data. That is the price
of catching procdump, and it is worth paying for a level-12 credential-theft
rule.

Rerun: same container steps as above, then
`run_logtest.py /tmp/wlt/main.jsonl /tmp/wlt/ws01_events.jsonl /tmp/wlt/lsass_defender_synthetic.jsonl`.
