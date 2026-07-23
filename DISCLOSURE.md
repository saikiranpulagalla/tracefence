# Provenance and AI Assistance Disclosure

## Pre-existing conceptual work

The project builds on prior architectural thinking about:

- cancellation and correction propagation through dynamically spawned agent graphs;
- deterministic action vetoes;
- authority boundaries among root, parent and peer agents;
- safe retry and idempotency policy;
- intervention and correction lineage.

These concepts were explored before this implementation. The TraceFence repository, control-plane implementation, APIs, worker runtime, tests, UI, telemetry schema and SigNoz specifications are organized as a new hackathon project.

## Related prior projects

Architectural ideas were informed by earlier work including AgentProof OS and an Agentic Recovery Agent. This repository does not present those prior repositories as newly created work. Any code reuse should be explicitly listed here with source file and commit provenance before submission.

## AI tools

ChatGPT/GPT-5.6 Thinking was used for architecture review, implementation assistance, test design, documentation and adversarial reasoning. All generated implementation was executed and tested in the available environment. Live SigNoz/Foundry behavior is explicitly marked unverified where Docker, Foundry or MCP credentials were unavailable.
