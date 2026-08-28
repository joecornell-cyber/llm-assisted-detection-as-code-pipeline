# LLM-Assisted Detection-as-Code Lab

> **Status:** In Progress

A security engineering lab exploring how locally hosted large language models can assist the detection engineering lifecycle through security automation, telemetry analysis, detection generation, and validation.

## Project Overview

This project is designed to integrate a locally hosted LLM with a Splunk based security lab to create an AI assisted detection-as-code workflow.

Controlled attack activity is generated within an isolated Active Directory lab and collected by Splunk. A Python automation pipeline retrieves relevant security telemetry through the Splunk REST API, sanitizes the event data, and submits selected telemetry to a locally hosted LLM.

The LLM generates structured candidate detection logic that can then be reviewed, tuned, version controlled, and validated by replaying attack activity against the lab environment.

## Planned Architecture

- **Kali Linux** - Attack simulation and automation
- **Windows Server** - Active Directory Domain Controller
- **Windows** - Domain joined endpoint
- **Ubuntu Server** - Splunk Enterprise
- **Windows 11 Host** - Ollama / Local LLM
- **Python** - Security automation and API orchestration
- **GitHub** - Detection version control and CI/CD

## Planned Detection Pipeline

```text
Attack Simulation
       ↓
Windows / Active Directory
       ↓
     Splunk
       ↓
Splunk REST API
       ↓
Python Automation
       ↓
Telemetry Sanitization
       ↓
   Local LLM
       ↓
Candidate Detection
       ↓
  Human Review
       ↓
Detection Deployment
       ↓
Attack Replay & Validation
```

## Project Goals

- Build a Python based security automation pipeline
- Integrate Splunk telemetry through REST APIs
- Integrate a locally hosted LLM through the Ollama API
- Apply data minimization before LLM inference
- Generate structured detection candidates
- Map detections to MITRE ATT&CK
- Maintain human review before detection deployment
- Validate detections using controlled attack simulations
- Store detection content as code
- Explore CI/CD-based detection validation

## Repository Structure

```text
llm-detection-as-code-lab/
├── src/
│   ├── splunk_client.py
│   ├── ollama_client.py
│   ├── sanitizer.py
│   └── detection_generator.py
├── detections/
│   └── README.md
├── attack-simulations/
│   └── README.md
├── dashboards/
│   └── README.md
├── docs/
│   ├── architecture.md
│   ├── llm-setup.md
│   ├── splunk-setup.md
│   └── security-considerations.md
├── images/
├── tests/
├── .github/
│   └── workflows/
├── requirements.txt
├── .gitignore
└── README.md
```

## Security Considerations

This project is being developed in an isolated lab environment. The LLM is hosted locally rather than using an external cloud AI provider.

The architecture is designed around:

- Network isolation
- Restricted access to the local LLM API
- Telemetry sanitization and data minimization
- Secrets management
- No direct LLM access to Splunk credentials
- Human review of AI-generated detection content

## Current Progress

The project is currently under active development. Documentation, detection content, automation code, validation results, and architecture diagrams will be added as implementation progresses.

## Disclaimer

This project is intended for educational and authorized security research purposes within controlled lab environments.
