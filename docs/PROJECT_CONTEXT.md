# Project Context

## Mission
Build an adaptive AI-assisted security correlation platform that turns Wazuh-first telemetry into coherent, evidence-backed incidents and supports governed investigation, adaptive detection, and response.

## POC target
Target a complete, high-quality POC in 7 days without deliberately reducing the previously agreed 4-week functional scope. If a blocker forces spillover, quality and security gates remain intact.

## Core architecture principles
- Modular monolith for the POC; preserve clean module boundaries for later extraction.
- Wazuh-first ingestion behind a generic connector contract so the core is not Wazuh-dependent.
- OCSF-aligned canonical event model.
- Event-time-aware processing with ingestion time and allowed lateness explicitly represented.
- Deterministic detection plus behavioral, graph, sequence, and novelty signals.
- Correlate signals into incidents before using an LLM.
- Score risk, confidence, and novelty separately.
- LLM/AI is an evidence-grounded investigator and rule proposer, not the primary detector or an unrestricted actuator.
- Detection-as-Code with versioning, historical replay, false-positive/noise evaluation, approval, and shadow mode.
- Policy-gated response with human approval for high-impact actions, verification, and audit trail.
- Secure SDLC / DevSecOps discipline throughout.

## POC modules
1. Connector framework and Wazuh adapter
2. Normalization / canonical event model
3. Entity extraction and resolution
4. Deterministic detection
5. Behavioral detection
6. Graph detection
7. Correlation and incident construction
8. Risk / confidence / novelty scoring
9. AI gateway and investigator
10. Adaptive rule proposal, replay, and shadow mode
11. Decision / policy engine
12. Response adapter and verification
13. Evaluation and replay harness
14. API and SOC-facing UI

## Killer scenarios
- Phishing / identity compromise chain
- Slow, multi-day lateral movement
- Previously unseen suspicious behavior without a matching known rule
- Novel incident -> AI candidate rule -> historical replay -> approval -> shadow mode

## Explicit POC non-goals
Do not add Kafka, Temporal, Kubernetes, GNNs, or full microservices merely for architectural prestige. They can be introduced later when scale or operational evidence justifies them.

## Source-of-truth hierarchy
1. Git repository implementation and tests
2. Current docs in `docs/`
3. ADRs / decisions
4. Historical planning transcript

When a new idea changes architecture, record the decision rather than silently drifting.