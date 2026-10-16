# Offline reasoning worksheet

The shared-scope development run completed all five tasks and its audit validated ten request
links. Its reasoning still requires review: mixed outcomes with equal timestamps do not
establish a failed-then-successful sequence, and speculative explanations are not established
by exact outcome citations. The assisted request review does not assess all hypothesis semantics.

`reasoning_audit` creates an offline HTML worksheet and a machine-readable JSON companion from
an existing pinned report. It makes no model requests and does not change prompts, run budgets,
reports, rubrics or reviews. There is no new scoring or rating workflow.

## Generate and open on the Mac

```bash
cd ~/adaptive-security-platform
git fetch origin
git switch investigation/offline-reasoning-worksheet
source .venv/bin/activate
python -m adaptive_security.reasoning_audit \
  artifacts/qwen25-shared-scope-v1 \
  artifacts/qwen25-shared-scope-v1/reasoning-review-v1
open artifacts/qwen25-shared-scope-v1/reasoning-review-v1/index.html
```

Use a fresh output directory. The original session manifest supplies the report digest. For a
standalone report, use its file path as the first argument and provide `--report-sha256`.

The output directory contains `index.html`, `worksheet.json` and a manifest binding output
hashes, report digest and source hashes. Outputs use owner-only file permissions, the directory
uses owner-only access, and existing output directories are refused. Partial output may remain
after a filesystem failure; use a new directory when retrying. The HTML page is self-contained,
uses no JavaScript or external resources, and renders untrusted content as escaped text.

## Read the worksheet

For each task, the left column shows bounded returned assertions, recorded timestamps and the
conclusion's citations. The right column shows each hypothesis and alternative explanation
verbatim, followed by questions for human review, collection limits and gap/request coverage.
Request proposals and shared context can be expanded for inspection.

Citations were recorded for the whole conclusion. The worksheet never invents a per-hypothesis
citation link. A citation's exact returned-field match does not establish that an explanation
is true, that a source is authentic, or that actions are authorized. Hidden task rubrics and
expected dispositions are not used to judge statements. No keyword rule decides their meaning.

Timestamp groups describe unique returned records only. Equal instants are grouped even if
the source timezone notation differs. At most ten timestamp groups and ten references per
group are displayed, with counts and explicit truncation indicators. Distinct recorded times
do not establish shared identity, complete collection, causation or actual event order.

Unrequested active gaps are shown only when structured request links and required scope are
valid. Legacy free text, absent conclusions and invalid request links receive distinct states;
they are not silently treated as a list of missed requests. Active gaps describe the current
returned fields and tool schema. Not every gap is relevant or needs collection. The worksheet
does not rank gaps, label omissions as errors, approve requests, or execute source queries.

For `mixed-auth-outcomes`, inspect the equal timestamps and ask what would establish account,
session and sequence relationships. Compare the model's identity/authorization requests with
the unrequested `event_relationship` gap. The page highlights the available context; an analyst
must judge whether a particular hypothesis is useful, overstated, or needs a different check.

Use the existing task review if recording formal semantic judgments. Keep assisted development
review separate from independent validation. Creating a worksheet establishes neither model
accuracy nor injection resistance or production readiness, and no additional model run is needed.
