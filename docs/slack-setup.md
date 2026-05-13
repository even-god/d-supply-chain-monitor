# Slack Integration Setup

The monitor can post alerts to a Slack channel whenever a malicious release is detected. Alerts include the package name, version, rank, registry link, and a truncated LLM analysis summary.

Alerts are **disabled by default** — pass `--slack` to enable them. Without `--slack`, any malicious finding is still logged to stdout and the daily log file.

## Prerequisites

- A Slack workspace where you have permission to install apps
- Python `requests` package installed (`pip install -r requirements.txt`)

## Step 1 — Create a Slack App

1. Go to [https://api.slack.com/apps](https://api.slack.com/apps) and click **Create New App**.
2. Choose **From scratch**.
3. Give it a name (e.g. `supply-chain-monitor`) and select your workspace.

## Step 2 — Enable Incoming Webhooks

1. In the left sidebar, click **Incoming Webhooks**.
2. Toggle **Activate Incoming Webhooks** on.
3. Click **Add New Webhook to Workspace**.
4. Select the channel where alerts should be posted and click **Allow**.
5. Copy the generated webhook URL — it looks like:
   ```
   https://hooks.slack.com/services/T.../B.../...
   ```
   This goes into the `"url"` field of `etc/slack.json`.

## Step 3 — Add Bot Token Scopes

1. In the left sidebar, click **OAuth & Permissions**.
2. Scroll to **Scopes → Bot Token Scopes**.
3. Click **Add an OAuth Scope** and add:
   - `chat:write`
4. Scroll back to the top and click **Install to Workspace** (or **Reinstall** if already installed). Confirm with **Allow**.
5. Copy the **Bot User OAuth Token** — it starts with `xoxb-`.
   This goes into the `"bot_token"` field of `etc/slack.json`.

## Step 4 — Get the Channel ID

The monitor needs the channel's ID (not its name) to post messages.

1. In Slack, open the alert channel.
2. Click the channel name at the top to open channel details.
3. Scroll to the bottom of the **About** tab — the Channel ID is shown there (e.g. `C01XXXXXXXX`).

Alternatively, right-click the channel in the sidebar → **View channel details** → scroll to the bottom.

## Step 5 — Create `etc/slack.json`

```bash
mkdir -p etc
```

Create `etc/slack.json`:

```json
{
    "url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
    "bot_token": "xoxb-YOUR-BOT-TOKEN",
    "channel": "C01XXXXXXXX"
}
```

The file is gitignored — it will never be committed.

## Step 6 — Test the Integration

Run this one-liner to verify the credentials before starting the monitor:

```bash
python3 -c "
from slack import Slack
s = Slack()
s.SendMessage(s.channel, ':white_check_mark: Supply chain monitor Slack integration test')
"
```

You should see the message appear in your alert channel within a few seconds. If it doesn't:

- Check that the `bot_token` starts with `xoxb-` and is copied in full.
- Check that the `channel` value is the channel ID, not the channel name.
- Check that the app has `chat:write` scope and is installed to the workspace.
- Check that the app is a **member** of the channel — invite it with `/invite @supply-chain-monitor` in Slack if needed.

## Step 7 — Run the Monitor with Slack Alerts

```bash
# One-shot scan (last ~10 min), Slack alerts on
python3 monitor.py --once --slack

# Continuous monitoring, top 5000 packages per ecosystem, Slack on
python3 monitor.py --top 5000 --interval 300 --slack

# Cursor Agent backend (free plan needs --model auto)
python3 monitor.py --top 5000 --slack --analyzer cursor --model auto

# Claude Code backend (default model, Slack on)
python3 monitor.py --top 5000 --slack --analyzer claude-code
```

## What an Alert Looks Like

```
🚨 Supply Chain Alert: telnyx 4.87.2

Rank: #5,481 of top PyPI packages
Verdict: MALICIOUS
PyPI: https://pypi.org/project/telnyx/4.87.2/

Analysis summary (truncated):
The changes to src/telnyx/_client.py implement obfuscated
download-decrypt-execute behavior. A _d() function decodes base64
strings; a massive _p blob contains an exfiltration script that
downloads a .wav file from http://83.142.209.203:8080/ringtone.wav
and extracts a hidden payload via steganography...
```

Analysis summaries are truncated to 2,800 characters in the Slack message. The full output is always written to the daily log file (`logs/monitor_YYYYMMDD.log`).

## Troubleshooting

| Symptom | Likely cause |
|---------|-------------|
| `Slack not configured` on startup | `etc/slack.json` is missing or in the wrong directory |
| `POST failed` in logs | Invalid `bot_token`, missing scope, or app not installed to workspace |
| Message not appearing | App not a member of the channel — run `/invite @<app-name>` in Slack |
| `KeyError: 'url'` | `etc/slack.json` is missing the `"url"` field (required even if you only use the bot token path) |
| Alerts fire but `--slack` not passed | Expected — `--slack` is required to send alerts; without it, findings are logged only |
