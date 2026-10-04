# Reserved captured-case validation

The password-spray v1 rule was frozen at commit
`2f8ec98a024e31205e945b2613128c80d059f5b7` before inspecting two independent
publisher-designated attack captures. The reservation was committed separately as
`6b20d9ec87cf6ff2fd5ca2d736bb4655d90049fc`. Capture metadata, original Git blob hashes,
SHA-256 digests, source commits, labels, and detector-file digests are in
`EVALUATION_RESERVATIONS.json`. Detector thresholds and accepted event types were not
changed after observing these samples.

## Reproduce on the Mac

From the repository, in a second Terminal with Python 3.12 or later:

```sh
git pull --ff-only
source .venv/bin/activate
python -m pip install -e '.[evtx]'
python -m adaptive_security.evtx_evaluation \
  docs/EVALUATION_RESERVATIONS.json artifacts/heldout-spray-v1
```

The command downloads only pinned original EVTX files, verifies both SHA-256 and Git
blob SHA before parsing, and writes a new private output directory. Existing destinations
are refused. It does not call the live API, access the live database, or change detectors.
The optional `evtx` extra provides python-evtx and defusedxml; live application installs
do not need those packages. To repeat, choose another output directory.

For downloaded copies, pass `--capture-directory PATH`; it must contain
`deepblue-password-spray.evtx` and `evtx-attack-kerberos-spray.evtx` with the pinned bytes.
The runner refuses detector files whose digests differ from the reservation. Do not
reuse these captures as held-out validation of a rule subsequently tuned on these results.

## Observed results

| Capture | Records preserved | Event IDs | v1 case result |
| --- | ---: | --- | --- |
| DeepBlueCLI password-spray | 295 | 294 × 4648; 1 × 1102 | False negative |
| EVTX-ATTACK-SAMPLES Kerberos password spray | 12 | 9 × 4768; 2 × 4771; 1 × 1102 | False negative |

The current rule accepts failed logons (4625), and neither sample contains a 4625
record. Explicit-credential events (4648) do not themselves report a failed logon.
Kerberos preauthentication failures (4771) are a separate observation, and this small
sample contains only two such records; simply counting them would still not meet the
five-account threshold. The adapter retains these unsupported events and their raw XML
instead of fabricating outcomes or converting them into 4625 failures.

These misses show **telemetry coverage gaps in the end-to-end pipeline**. They do not
prove the five-account/4625 rule fails when its required observations are available.
Add separate, correctly scoped detections for explicit credentials and Kerberos failures,
then develop them using these now-inspected samples and reserve fresh captures for
subsequent validation. Keep the historical v1 misses in reports.

## Labels, provenance, and limits

- [DeepBlueCLI's publisher documentation](https://github.com/sans-blue-team/DeepBlueCLI/tree/2eecc65698e8666408ece67525577c895676d579#examples)
  designates `evtx/password-spray.evtx` as its password-spraying example.
- [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/tree/4ceed2f4706daf601c212a8f91c113dd85349a2c)
  supplies `Credential Access/kerberos_pwd_spray_4771.evtx` under attack-associated
  samples. Its mapping is at technique level, not procedure-level ground truth.
- Each **case** is labeled as containing the publisher-designated attack. Individual
  records and background are not independently labeled malicious or benign. Labels are
  publisher assertions rather than independently verified enterprise incident outcomes.
- These are small, attack-associated samples from separate repositories. They are not
  representative customer traffic. No representative labeled benign capture was found
  or evaluated in this milestone, so false-alert performance remains unmeasured.
- Per-capture verdicts are reported separately. Precision and recall remain null for
  these positive-only captured cases; no combined production accuracy is claimed.
- The EVTX adapter scopes existing mappings to the Security Auditing provider, uses
  UTC `SystemTime` as event time, and explicitly marks observation time unavailable with
  an event-time fallback. Original XML, capture digest, ordinal, and EVTX record ID are
  retained. Named-field duplicates, unsafe XML, malformed records, checksum failures,
  and parsing errors fail the run. Counts reflect records yielded by the pinned parser,
  not a forensic guarantee that upstream capture collection contained every event.

Outputs include each original EVTX, normalized event JSONL, case JSONL,
`evaluation-suite.json`, and `report.json`. Reports contain inventories, declared
provenance, case verdicts, and limitations; event bodies and identities remain in the
separate private evidence files. Do not commit original captures or normalized telemetry.

## Representative benign validation still required

Obtain permissioned, analyst-reviewed capture windows for ordinary authentication,
mistyped passwords, shared kiosks, service accounts, and legacy Kerberos applications.
Record source, collection time range, labeling basis, and exclusions before evaluation.
Keep uncertain windows unlabeled. Reserve complete captures against a frozen rule;
do not split adjacent records across development and evaluation. The provenance-aware
suite accepts labeled benign cases once available, but these synthetic controls and
publisher attack samples cannot substitute for that collection.
