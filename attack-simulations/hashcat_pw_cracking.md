# Kerberoasting Password Cracking with Hashcat

## Objective

Perform controlled offline password cracking against the Kerberos service ticket material collected during the Kerberoasting simulation.

This activity was performed in an isolated, authorized lab environment using intentionally configured service accounts and passwords.

## Input Files

| File | Purpose |
|---|---|
| `kerberoasting.out` | Kerberos service ticket hashes collected during the lab |
| `common_passwords.txt` | Small lab wordlist containing intentionally configured test passwords |

## Command

```bash
hashcat -m 19700 -a 0 kerberoasting.out common_passwords.txt
```

## Command Breakdown

- `hashcat` — Password recovery tool used for offline hash cracking.
- `-m 19700` — Select the Hashcat mode for Kerberos 5 TGS-REP etype 18 (AES256).
- `-a 0` — Use a straight dictionary attack.
- `kerberoasting.out` — Kerberos service ticket material obtained during the GetUserSPNs simulation.
- `common_passwords.txt` — Lab-specific wordlist used for the cracking attempt.

## Why Mode 19700 Was Used

The service accounts in this lab supported AES encryption, and the Kerberos service tickets collected during the simulation used AES256 rather than RC4.

Because the captured TGS-REP material used Kerberos etype 18 (AES256), Hashcat mode `19700` was used.

This also demonstrates that Kerberoasting is not limited to RC4-encrypted service tickets.

## Result

The controlled dictionary attack successfully recovered the passwords for the intentionally vulnerable service accounts configured for the lab.

Recovered passwords are intentionally omitted from this repository.

The successful offline cracking demonstrated how weak service account passwords can turn Kerberos service ticket access into usable credentials.

## Detection Considerations

Hashcat performs the password cracking locally against previously collected ticket material.

As a result, the offline cracking process itself does not generate authentication attempts against Active Directory that Splunk can directly detect.

The primary opportunity for detection occurs earlier in the attack chain when the attacker requests Kerberos service tickets. In this project, that activity is detected using Windows Security Event ID `4769`.

The corresponding analyst-tuned Splunk detection is located at:

`detections/kerberoasting.spl`

## ATT&CK Context

The ticket acquisition and subsequent offline password cracking are part of the Kerberoasting technique:

**MITRE ATT&CK T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting**

An attacker can request service tickets for SPN-enabled accounts and then attempt to recover the associated service account passwords offline.

## Project Role

Successful offline cracking provided credentials for the next stage of the simulated attack chain:

**Nmap Reconnaissance → RDP Password Attack → Valid Account Access → Kerberoasting → Offline Password Cracking → Service Account Access → Administrator Access**
