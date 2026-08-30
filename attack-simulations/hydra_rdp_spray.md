# Hydra RDP Password Attack Simulation

## Objective

Generate failed and successful Windows authentication telemetry by performing a controlled RDP password attack against a domain user account.

This activity was performed in an isolated, authorized lab environment using intentionally configured lab credentials.

## Lab Systems

| Role | Value |
|---|---|
| Kali Linux attacker | `192.168.100.50` |
| Windows 11 target | `192.168.100.30` |
| Domain | `CORP` |
| Target user | `jdoe` |

## Command

```bash
hydra -l jdoe -P common_passwords.txt -t 1 -W 1 rdp://192.168.100.30/CORP
```

## Command Breakdown

- `-l jdoe` — Specify the target username.
- `-P common_passwords.txt` — Use the lab password list for authentication attempts.
- `-t 1` — Use a single parallel task.
- `-W 1` — Wait one second between connection attempts.
- `rdp://192.168.100.30/CORP` — Target the RDP service on the Windows 11 system using the `CORP` domain.

## Expected Telemetry

Repeated authentication attempts generate Windows Security events that can be collected and analyzed in Splunk.

The primary event used for detection is:

- Event ID `4625` — Failed account logon

During this lab, the failed RDP authentication attempts appeared as:

- `LogonType=3`
- NTLM authentication
- Source IP `192.168.100.50`
- Target account `jdoe`
- Status `0xc000006d`
- SubStatus `0xc000006a`

A subsequent successful RDP session can generate:

- Event ID `4624` — Successful account logon
- `LogonType=10` — RemoteInteractive logon

## Detection Pipeline

The corresponding analyst-tuned Splunk detection is located at:

`detections/failed_logons.spl`

The detection groups failed authentication activity into five-minute windows and evaluates characteristics such as:

- Number of failed logons
- Number of targeted accounts
- Source IP address
- Authentication package
- Logon type
- Windows status and substatus codes

The final detection does not hardcode the known lab attacker IP, allowing the logic to identify similar authentication attacks from other sources.

## ATT&CK Context

This simulation represents password guessing against a remote authentication service and aligns with:

**MITRE ATT&CK T1110 — Brute Force**

The resulting telemetry can be used to identify repeated authentication failures that may indicate password guessing or other credential-access activity.

## Project Role

This simulation follows reconnaissance and attempts to obtain valid credentials for remote access:

**Nmap Reconnaissance → RDP Password Attack → Valid Account Access → Kerberoasting → Offline Password Cracking → Service Account Access → Administrator Access**
