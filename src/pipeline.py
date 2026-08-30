import argparse
import json
import os
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET

from splunk_client import SplunkClient
from ollama_client import OllamaClient


# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------

DEFAULT_INDEX = os.getenv("SPLUNK_INDEX", "windows")
DEFAULT_SOURCETYPE = os.getenv(
    "SPLUNK_SOURCETYPE",
    "XmlWinEventLog:Security"
)

DEFAULT_ATTACK_SOURCE = os.getenv(
    "LAB_ATTACK_SOURCE_IP",
    "192.168.100.50"
)

MAX_RAW_EVENTS = 25

OUTPUT_DIR = Path("output")


# ----------------------------------------------------------------------
# Windows XML parsing
# ----------------------------------------------------------------------

def parse_windows_event(event):
    """
    Convert a raw XmlWinEventLog event returned by Splunk into a smaller
    dictionary that is easier for the LLM to analyze.
    """

    parsed = {
        "time": event.get("_time"),
        "host": event.get("host"),
        "source": event.get("source"),
        "sourcetype": event.get("sourcetype"),
    }

    raw = event.get("_raw")

    if not raw:
        parsed["parse_error"] = "No _raw field present"
        return parsed

    try:
        root = ET.fromstring(raw)

        namespace = {
            "e": "http://schemas.microsoft.com/win/2004/08/events/event"
        }

        system = root.find("e:System", namespace)

        if system is not None:
            event_id = system.find("e:EventID", namespace)
            channel = system.find("e:Channel", namespace)
            computer = system.find("e:Computer", namespace)

            if event_id is not None:
                parsed["event_id"] = event_id.text

            if channel is not None:
                parsed["channel"] = channel.text

            if computer is not None:
                parsed["computer"] = computer.text

        event_data = root.find("e:EventData", namespace)

        if event_data is not None:
            for data in event_data.findall("e:Data", namespace):
                name = data.attrib.get("Name")

                if name:
                    parsed[name] = data.text

    except ET.ParseError as exc:
        parsed["parse_error"] = str(exc)

    return parsed


def clean_splunk_result(event):
    """
    Remove Splunk metadata fields that provide little value to the LLM.
    Used for searches that already aggregate the raw telemetry.
    """

    ignore_fields = {
        "_serial",
        "_si",
        "_bkt",
        "splunk_server",
        "splunk_server_group",
    }

    return {
        key: value
        for key, value in event.items()
        if key not in ignore_fields
    }


# ----------------------------------------------------------------------
# Search helpers
# ----------------------------------------------------------------------

def escape_spl_string(value):
    """
    Basic escaping for values inserted into SPL quoted strings.
    """

    return value.replace("\\", "\\\\").replace('"', '\\"')


def time_clause(earliest=None, latest=None):
    """
    Return optional Splunk earliest/latest search modifiers.
    """

    parts = []

    if earliest:
        parts.append(f'earliest="{escape_spl_string(earliest)}"')

    if latest:
        parts.append(f'latest="{escape_spl_string(latest)}"')

    return " ".join(parts)


def build_searches(index, sourcetype, source_ip, earliest=None, latest=None):
    """
    Build scenario-specific Splunk searches.

    The known lab source IP is used only for telemetry selection so the LLM
    receives ground-truth attack events. GPT is explicitly instructed not
    to hardcode the IP into the resulting production-style detection.
    """

    index = escape_spl_string(index)
    sourcetype = escape_spl_string(sourcetype)
    source_ip = escape_spl_string(source_ip)

    time_filter = time_clause(earliest, latest)

    base = (
        f'search index="{index}" '
        f'sourcetype="{sourcetype}" '
        f'{time_filter}'
    ).strip()

    return {
        "nmap_scan": {
            "description": """
Windows Filtering Platform telemetry associated with the known lab attack
source. The objective is to identify behavior consistent with automated
network/service reconnaissance.

The retrieval search is intentionally using the known attack source only
to select ground-truth telemetry. The final detection must NOT hardcode
that source IP.
""",
            "raw": False,
            "search": f'''
{base}
| rex field=_raw "<EventID>(?<EventCode>\\d+)</EventID>"
| rex field=_raw "<Data Name='SourceAddress'>(?<SourceAddress>[^<]*)</Data>"
| rex field=_raw "<Data Name='DestAddress'>(?<DestAddress>[^<]*)</Data>"
| rex field=_raw "<Data Name='DestPort'>(?<DestPort>[^<]*)</Data>"
| where EventCode="5152" OR EventCode="5156" OR EventCode="5157"
| where SourceAddress="{source_ip}" OR SourceAddress="::ffff:{source_ip}"
| stats
    count
    dc(DestPort) as unique_destination_ports
    values(DestPort) as destination_ports
    by SourceAddress DestAddress EventCode
| sort - count
'''
        },

        "rdp_logon": {
            "description": """
Successful Remote Desktop activity associated with the known lab attack
source.

Look for behavior such as:
- Windows Event ID 4624
- LogonType 10
- unusual interactive use of service accounts
- multiple successful RDP logons
- authentication characteristics
- differences between normal user and service-account activity

A successful RDP logon is not automatically malicious. Explain what makes
an event normal or suspicious.

The retrieval search uses the known attack source only to isolate
ground-truth telemetry. The final detection must NOT hardcode that source
IP.
- The source IP shown in this ground-truth dataset is the lab attack source.
  Do NOT describe it as the target host's own IP.

- Prioritize the COMPLETE runnable SPL detection over lengthy narrative.
  Keep sections 1-5 concise so section 6 is always completed.

A COMPLETE Splunk SPL detection query must be included in the response.
""",
            "raw": True,
            "search": f'''
{base}
| rex field=_raw "<EventID>(?<EventCode>\\d+)</EventID>"
| rex field=_raw "<Computer>(?<Computer>[^<]+)</Computer>"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]*)</Data>"
| rex field=_raw "<Data Name='TargetDomainName'>(?<TargetDomainName>[^<]*)</Data>"
| rex field=_raw "<Data Name='LogonType'>(?<LogonType>[^<]*)</Data>"
| rex field=_raw "<Data Name='IpAddress'>(?<IpAddress>[^<]*)</Data>"
| rex field=_raw "<Data Name='AuthenticationPackageName'>(?<AuthenticationPackageName>[^<]*)</Data>"
| rex field=_raw "<Data Name='LogonProcessName'>(?<LogonProcessName>[^<]*)</Data>"
| where EventCode="4624"
| where LogonType="10"
| where IpAddress="{source_ip}" OR IpAddress="::ffff:{source_ip}"
| table
    _time
    host
    Computer
    TargetUserName
    TargetDomainName
    LogonType
    IpAddress
    LogonProcessName
    AuthenticationPackageName
    _raw
    source
    sourcetype
| sort _time
'''
        },

        "kerberos_service_ticket": {
            "description": """
Kerberos service-ticket activity associated with the known lab attack
source.

Analyze whether the behavior is consistent with Kerberoasting.

Pay particular attention to:
- Windows Event ID 4769
- requesting user
- requested service account
- multiple service-account ticket requests
- source address
- TicketEncryptionType
- TicketOptions
- machine-account versus user/service-account tickets

Do NOT assume Kerberoasting requires RC4. AES service tickets may also be
obtained and attacked offline.

The retrieval query uses the known attack source only to isolate
ground-truth telemetry. The final detection must NOT hardcode that source
IP.

A COMPLETE Splunk SPL detection query must be included in the response.
""",
            "raw": True,
            "search": f'''
{base}
| rex field=_raw "<EventID>(?<EventCode>\\d+)</EventID>"
| rex field=_raw "<Computer>(?<Computer>[^<]+)</Computer>"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]*)</Data>"
| rex field=_raw "<Data Name='TargetDomainName'>(?<TargetDomainName>[^<]*)</Data>"
| rex field=_raw "<Data Name='ServiceName'>(?<ServiceName>[^<]*)</Data>"
| rex field=_raw "<Data Name='TicketEncryptionType'>(?<TicketEncryptionType>[^<]*)</Data>"
| rex field=_raw "<Data Name='TicketOptions'>(?<TicketOptions>[^<]*)</Data>"
| rex field=_raw "<Data Name='Status'>(?<Status>[^<]*)</Data>"
| rex field=_raw "<Data Name='IpAddress'>(?<IpAddress>[^<]*)</Data>"
| where EventCode="4769"
| where IpAddress="{source_ip}" OR IpAddress="::ffff:{source_ip}"
| where NOT match(ServiceName, "\\\\$$")
| table
    _time
    host
    Computer
    TargetUserName
    TargetDomainName
    ServiceName
    TicketEncryptionType
    TicketOptions
    Status
    IpAddress
    _raw
    source
    sourcetype
| sort _time
'''
        },

        "failed_logons": {
            "description": """
Repeated failed Windows authentication events associated with the known
lab attack source.

Analyze whether the behavior is consistent with brute force, password
guessing, or password spraying.

Pay particular attention to:
- Windows Event ID 4625
- number and rate of failures
- number of targeted accounts
- source IP
- LogonType
- NTLM/Kerberos authentication package
- Status and SubStatus values

The retrieval search uses the known attack source only to isolate
ground-truth telemetry. The final detection must NOT hardcode that source
IP.
""",
            "raw": False,
            "search": f'''
{base}
| rex field=_raw "<EventID>(?<EventCode>\\d+)</EventID>"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]*)</Data>"
| rex field=_raw "<Data Name='LogonType'>(?<LogonType>[^<]*)</Data>"
| rex field=_raw "<Data Name='IpAddress'>(?<IpAddress>[^<]*)</Data>"
| rex field=_raw "<Data Name='Status'>(?<Status>[^<]*)</Data>"
| rex field=_raw "<Data Name='SubStatus'>(?<SubStatus>[^<]*)</Data>"
| rex field=_raw "<Data Name='AuthenticationPackageName'>(?<AuthenticationPackageName>[^<]*)</Data>"
| where EventCode="4625"
| where IpAddress="{source_ip}" OR IpAddress="::ffff:{source_ip}"
| stats
    count
    earliest(_time) as first_seen
    latest(_time) as last_seen
    dc(TargetUserName) as unique_users_from_source
    values(Status) as statuses
    values(SubStatus) as substatuses
    values(AuthenticationPackageName) as auth_packages
    by host TargetUserName IpAddress LogonType
| where count >= 5
| sort - count
'''
        },
    }


# ----------------------------------------------------------------------
# Prompt construction
# ----------------------------------------------------------------------

def build_prompt(
    category,
    description,
    events,
    index,
    sourcetype,
):
    telemetry = json.dumps(events, indent=2)

    return f"""
You are assisting a detection engineer analyzing telemetry from an
authorized isolated cybersecurity lab.

SCENARIO:
{category}

SCENARIO DESCRIPTION:
{description.strip()}

SPLUNK ENVIRONMENT:
- Index: {index}
- Sourcetype: {sourcetype}
- Windows events are stored as raw XML.
- Search-time field extraction may require rex against _raw.

IMPORTANT RULES:

1. Analyze ONLY the telemetry provided below.
2. Do not claim an attack occurred unless the evidence supports it.
3. Distinguish normal activity from suspicious activity.
4. Do not invent Splunk fields that are not present in the telemetry.
5. The final SPL MUST use:
       index="{index}"
       sourcetype="{sourcetype}"
6. If a required field is not automatically extracted in this environment,
   use rex against _raw to extract it.
7. Do not hardcode the known lab attacker IP into the final behavioral
   detection.
8. Do not simply reproduce the telemetry-selection query.
9. Design a behavioral detection that could generalize beyond this lab.
10. Avoid selecting thresholds solely because they exactly match this
    sample. Explain how thresholds should be tuned in production.
11. If the evidence does not support a useful detection, explicitly say so.
12. Include a COMPLETE, runnable Splunk SPL candidate detection.

Provide the following sections:

1. Activity Summary

2. Security-Relevant Evidence

3. Suspicion Assessment
   - what looks suspicious
   - what could be benign

4. Important Windows Event IDs and Fields

5. MITRE ATT&CK Mapping
   - only map techniques supported by the evidence

6. Candidate Splunk Detection
   - complete SPL
   - behavioral rather than IOC-specific

7. Detection Logic Explanation

8. Potential False Positives

9. Production Tuning Recommendations

10. Detection Confidence
    - Low, Medium, or High
    - explain why

TELEMETRY:

{telemetry}
""".strip()


# ----------------------------------------------------------------------
# Output handling
# ----------------------------------------------------------------------

def save_output(category, telemetry, analysis):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    telemetry_path = OUTPUT_DIR / f"{timestamp}_{category}_telemetry.json"
    analysis_path = OUTPUT_DIR / f"{timestamp}_{category}_analysis.md"

    with telemetry_path.open("w", encoding="utf-8") as handle:
        json.dump(telemetry, handle, indent=2)

    with analysis_path.open("w", encoding="utf-8") as handle:
        handle.write(f"# LLM Detection Analysis: {category}\n\n")
        handle.write(analysis)
        handle.write("\n")

    return telemetry_path, analysis_path


# ----------------------------------------------------------------------
# Scenario runner
# ----------------------------------------------------------------------

def run_scenario(
    category,
    config,
    splunk,
    ollama,
    index,
    sourcetype,
):
    print("\n" + "=" * 72)
    print(f"ANALYZING: {category.upper()}")
    print("=" * 72)

    print("[+] Querying Splunk...")

    results = splunk.search(config["search"])

    print(f"[+] Retrieved {len(results)} result(s)")

    if not results:
        print("[!] No matching telemetry found.")
        return

    if config["raw"]:
        cleaned_events = [
            parse_windows_event(event)
            for event in results
        ]

        if len(cleaned_events) > MAX_RAW_EVENTS:
            print(
                f"[!] {len(cleaned_events)} raw events returned. "
                f"Limiting LLM input to {MAX_RAW_EVENTS}."
            )

            cleaned_events = cleaned_events[-MAX_RAW_EVENTS:]

    else:
        cleaned_events = [
            clean_splunk_result(event)
            for event in results
        ]

    print(
        f"[+] Sending {len(cleaned_events)} telemetry "
        "record(s) to GPT-OSS"
    )

    print("\n[+] Telemetry:")
    print(json.dumps(cleaned_events, indent=2))

    prompt = build_prompt(
        category=category,
        description=config["description"],
        events=cleaned_events,
        index=index,
        sourcetype=sourcetype,
    )

    print("\n[+] Requesting detection analysis from GPT-OSS...")

    try:
        analysis = ollama.generate(prompt)

    except Exception as exc:
        print(f"[!] GPT-OSS request failed: {exc}")
        return

    print("\n" + "-" * 72)
    print(f"LLM DETECTION ANALYSIS: {category.upper()}")
    print("-" * 72)

    print(analysis)

    telemetry_path, analysis_path = save_output(
        category,
        cleaned_events,
        analysis,
    )

    print("\n[+] Saved artifacts:")
    print(f"    Telemetry: {telemetry_path}")
    print(f"    Analysis:  {analysis_path}")


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Retrieve targeted Windows telemetry from Splunk and send it "
            "to a local GPT-OSS model for detection-engineering analysis."
        )
    )

    parser.add_argument(
        "--scenario",
        choices=[
            "all",
            "nmap_scan",
            "rdp_logon",
            "kerberos_service_ticket",
            "failed_logons",
        ],
        default="all",
        help="Scenario to analyze (default: all)",
    )

    parser.add_argument(
        "--source-ip",
        default=DEFAULT_ATTACK_SOURCE,
        help=(
            "Known lab attack-source IP used only for ground-truth "
            "telemetry selection"
        ),
    )

    parser.add_argument(
        "--index",
        default=DEFAULT_INDEX,
        help=f"Splunk index (default: {DEFAULT_INDEX})",
    )

    parser.add_argument(
        "--sourcetype",
        default=DEFAULT_SOURCETYPE,
        help=f"Splunk sourcetype (default: {DEFAULT_SOURCETYPE})",
    )

    parser.add_argument(
        "--earliest",
        help=(
            'Optional Splunk earliest value, e.g. "-2h", '
            '"08/29/2026:19:30:00"'
        ),
    )

    parser.add_argument(
        "--latest",
        help='Optional Splunk latest value, e.g. "now"',
    )

    return parser.parse_args()


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():
    args = parse_args()

    searches = build_searches(
        index=args.index,
        sourcetype=args.sourcetype,
        source_ip=args.source_ip,
        earliest=args.earliest,
        latest=args.latest,
    )

    splunk = SplunkClient()
    ollama = OllamaClient()

    if args.scenario == "all":
        selected = searches.items()
    else:
        selected = [
            (args.scenario, searches[args.scenario])
        ]

    for category, config in selected:
        run_scenario(
            category=category,
            config=config,
            splunk=splunk,
            ollama=ollama,
            index=args.index,
            sourcetype=args.sourcetype,
        )


if __name__ == "__main__":
    main()
