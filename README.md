# LLM-Assisted Detection-as-Code Pipeline

> **Status:** v1 Complete

A security engineering project exploring how a locally hosted large language model can assist the detection engineering lifecycle through telemetry analysis, candidate detection generation, analyst review, and validation.

The project combines an isolated Active Directory attack lab, Splunk Enterprise, Python automation, Ollama, and a locally hosted GPT-OSS model to evaluate where LLMs can accelerate detection engineering and where human validation remains necessary.

## Project Overview

This project implements an LLM-assisted detection-as-code workflow using telemetry generated from controlled attack simulations.

Attack activity is performed from Kali Linux against systems in an isolated Active Directory lab. Windows Security telemetry is collected by Splunk Enterprise and retrieved by a Python pipeline through the Splunk REST API.

Rather than sending large volumes of raw telemetry directly to the model, the pipeline selects and minimizes scenario relevant events before submitting them to a locally hosted LLM through the Ollama API.

The LLM analyzes the telemetry and produces candidate Splunk detection logic. These detections are then manually reviewed, corrected, tuned, and validated against the original attack telemetry.

The goal is not autonomous detection deployment. Instead, the project evaluates the LLM as an assistant within a human reviewed detection engineering workflow.

## Architecture

The project combines an isolated Active Directory security lab with Splunk telemetry collection, Python based API orchestration, and local LLM inference.

```text
                         PHYSICAL WINDOWS 11 HOST
                    ┌──────────────────────────────┐
                    │            Ollama            │
                    │     Local LLM: gpt-oss:20b   │
                    │        GPU Inference         │
                    └──────────────▲───────────────┘
                                   │
                          Ollama REST API
                    telemetry + detection prompt
                                   │
═══════════════════════════════════╪═══════════════════════════════════
                            VMware Boundary
                                   │
                          ┌────────┴────────┐
                          │      KALI       │
                          │                 │
                          │ Attack Platform │
                          │ Python Pipeline │
                          │                 │
                          └────┬───────┬────┘
                               │       │
                    Attack     │       │ Splunk REST API
                    Traffic    │       │
                               │       │
                ┌──────────────┘       └─────────────────┐
                │                                        │
                ▼                                        ▼
       ┌─────────────────┐                     ┌─────────────────┐
       │   Windows 11    │                     │ Ubuntu Server   │
       │     Target      │───── telemetry ────►│                 │
       │                 │                     │ Splunk          │
       │ Domain Joined   │                     │ Enterprise      │
       └────────▲────────┘                     └────────▲────────┘
                │                                       │
                │ Active Directory                      │
                │                                       │ telemetry
                │                                       │
       ┌────────┴────────┐                              │
       │  Windows Server │──────────────────────────────┘
       │                 │
       │ Domain          │
       │ Controller      │
       └─────────────────┘


                       DETECTION ENGINEERING FLOW

                 ┌──────────────────────────┐
                 │   Controlled Attacks     │
                 │                          │
                 │ Nmap / Hydra / Kerberos │
                 └────────────┬─────────────┘
                              │
                              ▼
                 ┌──────────────────────────┐
                 │ Windows Security Events  │
                 └────────────┬─────────────┘
                              │
                              ▼
                 ┌──────────────────────────┐
                 │    Splunk Enterprise     │
                 └────────────┬─────────────┘
                              │ REST API
                              ▼
                 ┌──────────────────────────┐
                 │     Python Pipeline      │
                 │                          │
                 │ Scenario Selection       │
                 │ Telemetry Extraction     │
                 │ Data Minimization        │
                 │ Prompt Construction      │
                 └────────────┬─────────────┘
                              │
                              ▼
                 ┌──────────────────────────┐
                 │     Local GPT-OSS        │
                 │                          │
                 │ Telemetry Analysis       │
                 │ Candidate SPL Generation │
                 └────────────┬─────────────┘
                              │
                              ▼
                 ┌──────────────────────────┐
                 │  Candidate Detection     │
                 └────────────┬─────────────┘
                              │
                              ▼
                 ┌──────────────────────────┐
                 │ Human Review & Tuning    │
                 │                          │
                 │ Validate Assumptions     │
                 │ Correct SPL              │
                 │ Tune Thresholds          │
                 │ Verify ATT&CK Mapping    │
                 └────────────┬─────────────┘
                              │
                              ▼
                 ┌──────────────────────────┐
                 │  Validated Detection     │
                 │        as Code           │
                 └──────────────────────────┘
```

### Architecture Goals

The architecture was designed around several core goals:

- **Keep LLM inference local** — Security telemetry is analyzed by a locally hosted model through Ollama rather than being submitted to an external cloud LLM.

- **Separate credentials from the LLM** — The Python pipeline communicates independently with Splunk and Ollama. Splunk API credentials are never provided to the model.

- **Minimize LLM context** — Instead of submitting thousands of unrelated Windows events, the pipeline retrieves and reduces telemetry relevant to a selected detection scenario.

- **Generate candidates, not autonomous detections** — LLM generated SPL is treated as candidate detection logic that requires analyst review.

- **Build reusable detections** — Known lab information can be used to locate ground truth attack telemetry, but final detections should identify behavioral patterns rather than hardcoded attacker IPs or lab-specific values.

- **Validate against real telemetry** — Candidate logic is compared with the Windows events generated during controlled attack simulations and tuned into working Splunk detections.

- **Maintain detections as code** — Analyst reviewed SPL is stored in Git alongside the pipeline, attack simulations, and supporting documentation.

### Design Philosophy

The LLM is intentionally positioned as an assistant inside the detection engineering lifecycle rather than as an autonomous security control.

```text
             LLM Assisted
                  │
                  ▼
Telemetry ──► Candidate Detection ──► Analyst ──► Validated Detection
                                           │
                              Human judgment remains
                              the final control point
```

This architecture allows the model to accelerate telemetry interpretation and initial detection development while keeping validation, tuning, and deployment decisions under human control.

### Lab Components

- **Kali Linux** — Attack simulation and Python orchestration
- **Windows Server** — Active Directory Domain Controller
- **Windows 11** — Domain joined target endpoint
- **Splunk Enterprise** — Security telemetry collection and analysis
- **Ollama** — Local LLM inference API
- **GPT-OSS 20B** — Local model used for telemetry analysis and detection generation
- **Python** — Splunk and Ollama API orchestration
- **GitHub** — Detection and project version control

For additional architecture details, see [`docs/architecture.md`](docs/architecture.md).

## Detection Pipeline

The Python pipeline supports scenario specific telemetry retrieval rather than sending arbitrary recent events to the LLM.

Example:

```bash
python3 src/pipeline.py --scenario failed_logons
```

Supported scenarios include:

```text
all
nmap_scan
failed_logons
rdp_logon
kerberos_service_ticket
```

The pipeline:

1. Queries Splunk for scenario relevant telemetry.
2. Extracts and minimizes relevant Windows event data.
3. Sends the selected telemetry to the local LLM.
4. Prompts the model to analyze only the provided evidence.
5. Requests generalizable Splunk SPL rather than lab specific detection logic.
6. Saves the resulting analysis for analyst review.
7. Allows candidate detections to be compared against analyst-tuned detections.

## Attack Chain

The lab generated a multi stage attack sequence:

```text
Nmap Reconnaissance
        ↓
RDP Password Attack
        ↓
Valid Domain Account Access
        ↓
Kerberoasting
        ↓
Offline Password Cracking
        ↓
Compromised Service Account
        ↓
RDP Service Account Access
        ↓
Local Administrator Access
```

Attack simulation documentation is available under [`attack-simulations/`](attack-simulations/).

### Simulations

| Simulation | Documentation |
|---|---|
| Nmap reconnaissance | [`nmap_scan.md`](attack-simulations/nmap_scan.md) |
| RDP password attack | [`hydra_rdp_spray.md`](attack-simulations/hydra_rdp_spray.md) |
| Kerberoasting | [`kerberoast_getuserspns.md`](attack-simulations/kerberoast_getuserspns.md) |
| Offline Kerberos password cracking | [`hashcat_pw_cracking.md`](attack-simulations/hashcat_pw_cracking.md) |

Credentials, recovered passwords, and other sensitive lab artifacts are intentionally excluded from the repository.

## Detection Content

The final analyst-reviewed detections are stored as Splunk SPL under [`detections/`](detections/).

| Detection | Primary Telemetry | ATT&CK Context |
|---|---|---|
| [`nmap_scan.spl`](detections/nmap_scan.spl) | Windows Filtering Platform events | Network service discovery / probing |
| [`failed_logons.spl`](detections/failed_logons.spl) | Event ID 4625 | T1110 — Brute Force |
| [`kerberoasting.spl`](detections/kerberoasting.spl) | Event ID 4769 | T1558.003 — Kerberoasting |
| [`suspicious_rdp_logon.spl`](detections/suspicious_rdp_logon.spl) | Event ID 4624 / Logon Type 10 | T1021.001 — Remote Desktop Protocol |

The detections stored in this directory represent analyst-tuned versions rather than unreviewed LLM output.

## Key Findings

The local LLM was useful for identifying suspicious behavior and quickly producing candidate detection ideas, but its output could not be treated as deployment ready detection content.

Several issues emerged during testing.

### Telemetry Selection Matters

An early Kerberos test supplied the model with a broad collection of Event ID `4769` events. Routine domain activity dominated the dataset and buried the Kerberoasting events that were relevant to the simulation.

After the pipeline was changed to retrieve more focused telemetry, the model received substantially better context.

This demonstrated that LLM performance in detection engineering depends heavily on the quality and relevance of the telemetry supplied to it.

### LLM Output Requires Validation

Candidate detections occasionally contained:

- Incorrect assumptions about available Splunk fields
- Hardcoded or overly specific values
- Thresholds overfit to the supplied sample
- Incorrect interpretations of event data
- Unsupported conclusions
- Incorrect or outdated MITRE ATT&CK mappings

Human review was required to identify and correct these issues.

### Raw Telemetry Schema Matters

The lab used:

```text
index=windows
sourcetype=XmlWinEventLog:Security
```

Useful Windows fields were not always available as convenient Splunk search time fields.

Final detections therefore use `rex` against `_raw` where necessary rather than assuming fields such as `TargetUserName`, `IpAddress`, or `LogonType` already exist.

### Detection Logic Should Generalize

The pipeline uses known lab information to retrieve ground truth attack telemetry, but the final detection logic should not depend on the known attacker IP address, exact usernames, or values unique to the demonstration.

The analyst reviewed detections instead focus on reusable behavioral patterns.

## Human-in-the-Loop Design

A central design decision in this project is that the LLM does **not** automatically deploy detections.

```text
Telemetry
   ↓
LLM Analysis
   ↓
Candidate Detection
   ↓
Human Validation
   ↓
Tuning
   ↓
Validated Detection
```

The model acts as a detection engineering assistant rather than an autonomous security control.

This separation helps reduce the risk of deploying hallucinated, overfit, or technically invalid detection logic.

## Repository Structure

```text
llm-detection-as-code-pipeline/
├── attack-simulations/
│   ├── README.md
│   ├── hashcat_pw_cracking.md
│   ├── hydra_rdp_spray.md
│   ├── kerberoast_getuserspns.md
│   └── nmap_scan.md
│
├── detections/
│   ├── README.md
│   ├── failed_logons.spl
│   ├── kerberoasting.spl
│   ├── nmap_scan.spl
│   └── suspicious_rdp_logon.spl
│
├── docs/
│   ├── architecture.md
│   ├── llm-setup.md
│   ├── security-considerations.md
│   └── splunk-setup.md
│
├── src/
│   ├── ollama_client.py
│   ├── pipeline.py
│   └── splunk_client.py
│
├── tests/
│   ├── test_ollama.py
│   └── test_splunk.py
│
├── requirements.txt
├── .gitignore
└── README.md
```

## Setup

Install the Python dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

The pipeline uses environment variables for service configuration and credentials.

Example configuration:

```bash
export SPLUNK_URL="https://<splunk-host>:8089"
export SPLUNK_TOKEN="<splunk-token>"
export SPLUNK_VERIFY_TLS="false"

export OLLAMA_URL="http://<ollama-host>:11434/api/generate"
export OLLAMA_MODEL="gpt-oss:20b"
```

Secrets should never be committed to the repository.

See the documentation under [`docs/`](docs/) for the full lab configuration.

## Usage

Verify connectivity to Splunk:

```bash
python3 tests/test_splunk.py
```

Verify connectivity to Ollama:

```bash
python3 tests/test_ollama.py
```

View the pipeline options:

```bash
python3 src/pipeline.py --help
```

Run analysis for a specific scenario:

```bash
python3 src/pipeline.py --scenario nmap_scan
```

```bash
python3 src/pipeline.py --scenario failed_logons
```

```bash
python3 src/pipeline.py --scenario kerberos_service_ticket
```

```bash
python3 src/pipeline.py --scenario rdp_logon
```

Generated pipeline output should be treated as candidate detection content requiring analyst review.

## Security Considerations

The project was developed in an isolated lab environment.

Security controls and design considerations include:

- Local LLM inference rather than sending telemetry to a third party AI service
- Restricted access to Splunk and Ollama APIs
- Environment variables for API credentials
- Data minimization before LLM inference
- Scenario specific telemetry selection
- No LLM access to Splunk credentials
- Human review before detection deployment
- Exclusion of passwords, tokens, hashes, and generated attack artifacts from version control

Additional details are available in [`docs/security-considerations.md`](docs/security-considerations.md).

## Limitations

This project is a controlled proof of concept rather than a production detection platform.

Current limitations include:

- Small lab environment
- Limited attack scenarios
- Lab-specific telemetry sources
- Manual analyst validation
- No automated SPL execution or validation of LLM generated detections
- No automated detection deployment
- No production baselining or false positive analysis
- Model performance evaluated against a limited set of controlled scenarios

These limitations are intentional for the initial version and provide opportunities for future development.

## Future Improvements

Potential future work includes:

- Automated SPL syntax and execution validation
- Detection-as-code CI/CD workflows
- Sigma rule generation
- Automated ATT&CK mapping validation
- Detection quality scoring
- Regression testing against known attack telemetry
- Additional Windows and Active Directory attack scenarios
- Multi-event attack-chain correlation
- Comparison of multiple local models

## Conclusion

This project demonstrated that a locally hosted LLM can accelerate parts of the detection engineering process, particularly telemetry interpretation and initial detection development.

However, the experiments also demonstrated that useful results depend heavily on telemetry selection, prompt design, understanding the underlying event schema, and analyst validation.

The resulting workflow therefore treats the LLM as an engineering assistant rather than an autonomous detection system:

> **LLMs can accelerate detection engineering, but telemetry selection, prompt design, and analyst validation determine whether the resulting detections are actually useful.**

## Disclaimer

This project is intended solely for educational, defensive security research, and authorized testing within controlled lab environments.

Attack simulations documented in this repository were performed against systems specifically configured for the project.
