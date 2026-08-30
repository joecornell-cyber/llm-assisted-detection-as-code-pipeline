# Kerberoasting with GetUserSPNs

## Objective

Generate Kerberos service ticket telemetry by requesting service tickets for accounts with registered Service Principal Names (SPNs).

This activity was performed in an isolated, authorized lab environment using intentionally configured lab accounts.

## Lab Systems

| Role | Value |
|---|---|
| Kali Linux attacker | `192.168.100.50` |
| Domain Controller | `192.168.100.10` |
| Domain | `corp.local` |
| Authenticated user | `jdoe` |

## Command

```bash
GetUserSPNs.py -dc-ip 192.168.100.10 -no-rc4 -request \
  -outputfile kerberoasting.out \
  'corp.local/jdoe:<LAB_PASSWORD>'
```

> The password used during the lab has been replaced with a placeholder to avoid publishing credentials in the repository.

## Command Breakdown

- `GetUserSPNs.py` — Impacket utility used to identify accounts with registered SPNs and request Kerberos service tickets.
- `-dc-ip 192.168.100.10` — Specify the IP address of the domain controller.
- `-no-rc4` — Do not request RC4-encrypted service tickets.
- `-request` — Request Kerberos service tickets for discovered SPN accounts.
- `-outputfile kerberoasting.out` — Save the returned ticket material to a file for controlled offline analysis.
- `corp.local/jdoe:<LAB_PASSWORD>` — Authenticate to the lab domain using the designated test account.

## Expected Telemetry

Requesting Kerberos service tickets generates Windows Security events on the domain controller.

The primary event used for detection is:

- Event ID `4769` — A Kerberos service ticket was requested

Useful fields include:

- `TargetUserName`
- `TargetDomainName`
- `ServiceName`
- `TicketEncryptionType`
- `TicketOptions`
- `Status`
- `IpAddress`

During the lab, service tickets were requested for intentionally configured service accounts from the Kali system.

Because the service accounts supported AES encryption, the requested tickets used AES rather than RC4. Kerberoasting is not limited to RC4 tickets; service tickets using supported encryption types can still be obtained for offline password analysis.

## Detection Pipeline

The corresponding analyst-tuned Splunk detection is located at:

`detections/kerberoasting.spl`

The detection analyzes Kerberos service ticket requests and looks for behavioral indicators such as:

- Multiple service ticket requests
- Multiple distinct service accounts
- Non-machine accounts requesting service tickets
- Source IP address
- Ticket encryption types
- Bursts of service ticket activity within a short time window

The final detection does not hardcode the known lab attacker IP or specific service account names, making the logic more reusable outside the lab environment.

## Detection Engineering Lesson

Initial broad telemetry retrieval returned a large number of routine Kerberos events, causing the relevant service ticket requests to be buried among normal domain activity.

The pipeline was subsequently refined to provide the LLM with more focused telemetry.

This demonstrated an important part of the project:

**LLM detection quality depends heavily on telemetry selection and context, not just the model itself.**

## ATT&CK Context

This simulation represents Kerberoasting and aligns with:

**MITRE ATT&CK T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting**

Kerberoasting allows an authenticated domain user to request service tickets associated with SPN-enabled accounts. The resulting ticket material can then be analyzed offline in an attempt to recover the service account password.

## Project Role

This simulation occurs after obtaining valid domain credentials and is used to target service accounts:

**Nmap Reconnaissance → RDP Password Attack → Valid Account Access → Kerberoasting → Offline Password Cracking → Service Account Access → Administrator Access**
