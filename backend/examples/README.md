# CPEDS-X CLI — example logs

Sample CloudTrail-shaped files to try the `cpeds` CLI against. Run these from the
`backend` folder (so the `cpeds` launcher and the project venv are found).

| File | Format | Contents |
|------|--------|----------|
| `cloudtrail_sample.json` | CloudTrail export `{"Records":[…]}` | 7 events — mostly benign with a horizontal-escalation `AssumeRole`, a vertical-escalation `AttachUserPolicy`, an exfil `GetObject` (1.25 GB from a PII bucket), and a cross-account lateral `DescribeInstances`. |
| `single_event.json` | one JSON event | The vertical-escalation `AttachUserPolicy` on its own. |
| `events.jsonl` | JSON Lines | 4 events, one per line — shows the `.jsonl` path. |

## Try it

```powershell
# batch-score the whole export with a summary table
cpeds analyze examples\cloudtrail_sample.json

# score just the single event
cpeds predict examples\single_event.json

# JSON Lines works too
cpeds analyze examples\events.jsonl

# machine-readable output (JSON on stdout, human text on stderr)
cpeds analyze examples\cloudtrail_sample.json --json

# CI gate: exit code 2 if any threat is found
cpeds analyze examples\cloudtrail_sample.json --fail-on-threat

# pipe an event in from stdin
type examples\single_event.json | cpeds predict -
```

> On macOS/Linux use `./cpeds analyze examples/cloudtrail_sample.json` and
> `cat examples/single_event.json | ./cpeds predict -`.

These files are synthetic and safe to share — no real account IDs, keys, or PII.
