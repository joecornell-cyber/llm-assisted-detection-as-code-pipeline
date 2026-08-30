# Nmap Scan Simulation

## Objective

Generate network reconnaissance telemetry against the Windows 11 target for ingestion into Splunk and analysis by the LLM-assisted detection pipeline.

This activity was performed in an isolated, authorized lab environment.

## Lab Systems

| Role | IP Address |
|---|---|
| Kali Linux attacker | `192.168.100.50` |
| Windows 11 target | `192.168.100.30` |

## Command

```bash
sudo nmap -p 3389 -sC -sV -Pn -sS -n -T4 --reason \
  -oA "output/nmap_scan_$(date -u +%Y%m%dT%H%M%SZ)" \
  192.168.100.30
```

## Command Breakdown

- `-p 3389` — Scan the RDP port.
- `-sC` — Run Nmap's default NSE scripts.
- `-sV` — Perform service/version detection.
- `-Pn` — Treat the target as online without host discovery.
- `-sS` — Perform a TCP SYN scan.
- `-n` — Disable DNS resolution.
- `-T4` — Use faster timing appropriate for the controlled lab.
- `--reason` — Display why Nmap considers the port open, closed, or filtered.
- `-oA` — Save results in Nmap's normal, XML, and grepable output formats.

## Expected Telemetry

The scan generates network connection activity between the Kali attacker and the Windows target.

Windows Filtering Platform (WFP) Security events collected by Splunk can provide evidence of this activity, including:

- Event ID `5156` — Connection permitted
- Event ID `5152` — Packet dropped
- Event ID `5157` — Connection blocked

The available WFP telemetry should be treated as evidence of network probing rather than a complete representation of every probe performed by Nmap.

## Detection Pipeline

The corresponding analyst-tuned Splunk detection is located at:

`detections/nmap_scan.spl`

The detection looks for high-volume, multi-port network probing behavior using Windows Filtering Platform telemetry rather than hardcoding the known lab attacker IP.

## ATT&CK Context

This simulation represents network service discovery/reconnaissance behavior that can be used by an attacker to identify exposed services before attempting further access.

## Project Role

This simulation is the reconnaissance stage of the lab attack chain:

**Nmap Reconnaissance → RDP Password Attack → Valid Account Access → Kerberoasting → Offline Password Cracking → Service Account Access → Administrator Access**
