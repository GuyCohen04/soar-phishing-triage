# SOAR Phishing Triage Playbook

An automated phishing triage workflow built in **Tines Stories** (SOAR platform). When a user reports a suspicious email, the playbook extracts the link's domain, checks its reputation with the **VirusTotal API**, decides whether it is malicious, and emails the security team a verdict with a recommended action.

The same logic is also included as a standalone **Python script** (`triage.py`).

![Workflow](screenshots/workflow.png)

## How it works

```
Receive Phishing Report (Webhook)
            |
     Extract Domain (Event Transform)
            |
    Check VirusTotal (HTTP Request, VirusTotal API v3)
         /                \
 Malicious (3+ vendors)   Clean (0-2 vendors)
        |                     |
 Alert - Malicious        Alert - Clean
   (Send Email)            (Send Email)
```

| Step | Tines action | What it does |
|---|---|---|
| 1 | Webhook | Receives a phishing report as JSON: `url`, `sender`, `subject` |
| 2 | Event Transform | Pulls the domain out of the reported URL and carries the report details forward |
| 3 | HTTP Request | Queries `GET /api/v3/domains/{domain}` on VirusTotal and reads `last_analysis_stats.malicious` |
| 4 | Condition (x2) | Routes to **Malicious** if 3 or more vendors flag the domain, otherwise **Clean** |
| 5 | Send Email (x2) | Sends the analyst a verdict, the report details, the vendor count and a recommended action |

### Example report sent to the webhook

```json
{
  "url": "http://malware.wicar.org/data/",
  "sender": "it-support@yu-helpdesk.net",
  "subject": "Your password expires today"
}
```

## Test results

| Reported URL | Vendors flagging | Verdict | Recommended action |
|---|---|---|---|
| `http://example.com/login` | 0 | CLEAN | No action, close the report |
| `http://malware.wicar.org/data/` (public AV test site) | 17 | MALICIOUS | Block the domain and quarantine the email |

![Malicious alert](screenshots/alert-malicious.png)
![Clean alert](screenshots/alert-clean.png)

## Security design

- **API key stored as a Tines credential**, never in the workflow or this repo.
- **Credential restricted to `www.virustotal.com`**, so the key can only be sent to that domain.
- **Webhook URL kept private.** It is not published here, since anyone with it could send events into the workflow.

## Files

| File | Description |
|---|---|
| `phishing-triage.json` | Exported Tines story (import it into any Tines tenant) |
| `triage.py` | Python version of the same playbook |
| `screenshots/` | Workflow canvas and example alerts |

## Python version

```bash
pip install requests
export VT_API_KEY="your-virustotal-key"      # PowerShell: $env:VT_API_KEY="your-key"
python triage.py "http://malware.wicar.org/data/"
```

## Ideas for next iterations

- Look up the full URL as well as the domain (`/api/v3/urls`), and add a second source such as urlscan.io or AbuseIPDB
- Pull reports straight from a phishing mailbox instead of a webhook
- Open a ticket automatically (ServiceNow, Jira) for malicious verdicts
- Auto-block the domain on the email gateway or firewall after analyst approval
- Deduplicate repeat reports of the same domain

## Tools

Tines Stories (Community Edition), VirusTotal API v3, Python, PowerShell for testing
