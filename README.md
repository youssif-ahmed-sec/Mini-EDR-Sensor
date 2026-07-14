# 🛡 Mini EDR Sensor — Deception-Based Intrusion Detection

<p align="center">
  <strong>A lightweight, host-based intrusion detection tool that uses Deception Technology to catch attackers in the act.</strong>
</p>

---

## 📖 What Is Deception Technology?

**Deception Technology** is a cybersecurity strategy that deploys **fake assets** — files, credentials, services, or even entire systems — designed to lure attackers into interacting with them. Because no legitimate user or process should ever touch these decoys, **any interaction is a high-confidence indicator of compromise (IoC)**.

### Core Principles

| Concept | Description |
|---|---|
| **Honeypot** | A decoy system or service that mimics a real target to attract attackers. |
| **Honeytoken** | A fake credential, file, or data record planted where only an intruder would find it. |
| **Canary File** | A tripwire file — such as `passwords.txt` — that triggers an alert when accessed. |
| **Zero False-Positive Design** | Because decoys have no legitimate use, alerts carry extremely high fidelity. |

### Why It Matters

Traditional detection relies on signature matching or anomaly baselines — both produce noise. Deception flips the model: instead of looking for *bad*, you plant something *irresistible* and wait. The result is:

- ✅ **Near-zero false positives** — legitimate users never touch decoy files
- ✅ **Early warning** — attackers often look for credential files first
- ✅ **Low overhead** — a single Python script, no agents or kernel modules
- ✅ **Attacker profiling** — timestamps and actions reveal adversary TTPs

---

## 🏗 How This Tool Works

```
┌─────────────────────────────────────────────┐
│              Mini EDR Sensor                │
│                                             │
│   1. Deploy a canary file (passwords.txt)   │
│   2. Monitor it with watchdog (inotify)     │
│   3. On ANY interaction:                    │
│        → Print high-priority terminal alert │
│        → Send Discord Webhook notification  │
└─────────────────────────────────────────────┘
```

The script uses Python's [`watchdog`](https://github.com/gorakhargosh/watchdog) library, which wraps the OS-native file-system notification API (`inotify` on Linux, `FSEvents` on macOS, `ReadDirectoryChangesW` on Windows) to detect:

| Event | Trigger |
|---|---|
| **CREATED** | The decoy file is recreated after deletion |
| **MODIFIED** | The file contents or metadata are changed |
| **DELETED** | The file is removed |
| **MOVED** | The file is renamed or relocated |

---

## 🚀 Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/your-username/Mini-EDR-Sensor.git
cd Mini-EDR-Sensor
pip install -r requirements.txt
```

### 2. Run the Sensor

```bash
# Basic — monitor the default 'passwords.txt' in the current directory
python3 edr_sensor.py

# Custom decoy file
python3 edr_sensor.py --file /home/user/Documents/secret_keys.txt

# With Discord alerting
python3 edr_sensor.py --webhook https://discord.com/api/webhooks/YOUR_WEBHOOK_URL
```

### 3. Test It

Open a second terminal and interact with the decoy file:

```bash
# Trigger a MODIFIED alert
echo "test" >> passwords.txt

# Trigger a DELETED alert
rm passwords.txt

# Trigger a CREATED alert (recreate it)
touch passwords.txt
```

You should see output like:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🚨  HIGH-PRIORITY INTRUSION ALERT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Timestamp : 2026-07-14T18:40:00Z
  Action    : MODIFIED
  File      : /home/kali/passwords.txt
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 🔧 Configuration

| Flag | Default | Description |
|---|---|---|
| `--file` | `passwords.txt` | Path to the honeypot decoy file to monitor |
| `--webhook` | *None* | Discord Webhook URL for remote alert delivery |

### Discord Webhook Setup

1. Open your Discord server → **Server Settings → Integrations → Webhooks**
2. Click **New Webhook**, name it (e.g., `EDR Alerts`), and choose a channel
3. Copy the Webhook URL
4. Pass it via `--webhook`:

```bash
python3 edr_sensor.py --webhook "https://discord.com/api/webhooks/1234567890/abcdefg"
```

---

## 📂 Project Structure

```
Mini-EDR-Sensor/
├── edr_sensor.py        # Main sensor script (~95 lines)
├── requirements.txt     # Python dependencies
├── passwords.txt        # Auto-generated honeypot decoy file
└── README.md            # You are here
```

---

## 🔒 Security Considerations

> **⚠ This is an educational / lab tool.** For production deployments, consider:

- **File-level auditing** — Combine with `auditd` (Linux) or Sysmon (Windows) to capture the PID and user of the accessing process.
- **Immutable decoys** — Use `chattr +i` to prevent deletion of the canary file itself.
- **Encrypted webhook secrets** — Store the Discord URL in an environment variable, not on the command line.
- **Multiple canaries** — Deploy decoy files across sensitive directories (`/etc/`, `/home/`, database backups).
- **SIEM integration** — Forward alerts to Splunk, Elastic, or Wazuh for correlation.

---

## 🗺 MITRE ATT&CK Mapping

This tool detects adversary behaviours mapped to:

| Technique ID | Name | Phase |
|---|---|---|
| T1083 | File and Directory Discovery | Discovery |
| T1005 | Data from Local System | Collection |
| T1552.001 | Credentials in Files | Credential Access |
| T1485 | Data Destruction | Impact |

---

## 📜 License

MIT — free for personal, educational, and commercial use.
