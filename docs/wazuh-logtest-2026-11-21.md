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
