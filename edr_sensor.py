#!/usr/bin/env python3
"""Mini EDR Sensor — Deception-based intrusion detection via honeypot file monitoring."""

import os, sys, time, argparse, logging, requests
from datetime import datetime, timezone
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ── Terminal colours & Windows compatibility ────────────────────────────
R, Y, C, B, X = "\033[91m", "\033[93m", "\033[96m", "\033[1m", "\033[0m"
if sys.platform == "win32":
    os.system("")  # enables VT100 escape sequences in Windows CMD

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S")
log = logging.getLogger("edr")


def discord_alert(url: str, msg: str) -> None:
    """POST an alert payload to a Discord Webhook (fire-and-forget)."""
    try:
        requests.post(url, json={"content": f"🚨 **EDR ALERT**\n```\n{msg}\n```"}, timeout=5)
    except requests.RequestException as e:
        log.warning(f"Discord send failed: {e}")


class HoneypotHandler(FileSystemEventHandler):
    """Fires high-priority alerts when the decoy canary file is touched."""
    ACTIONS = {"modified": "MODIFIED", "deleted": "DELETED",
               "created": "CREATED", "moved": "MOVED"}

    def __init__(self, decoy: str, webhook: str | None = None):
        super().__init__()
        self.decoy, self.webhook = os.path.abspath(decoy), webhook

    def _match(self, path: str) -> bool:
        return os.path.abspath(path) == self.decoy

    def _alert(self, etype: str, path: str) -> None:
        action = self.ACTIONS.get(etype, etype.upper())
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        msg = f"[{ts}] HONEYPOT {action} → {path}"
        # High-priority terminal banner
        print(f"\n{R}{B}{'━' * 60}\n  🚨  HIGH-PRIORITY INTRUSION ALERT\n{'━' * 60}{X}")
        print(f"  {C}Timestamp :{X} {ts}\n  {Y}Action    :{X} {action}\n  {Y}File      :{X} {path}")
        print(f"{R}{B}{'━' * 60}{X}\n")
        log.info(msg)
        if self.webhook:
            discord_alert(self.webhook, msg)

    # ── Watchdog callbacks ──────────────────────────────────────────────
    def on_modified(self, e):
        if self._match(e.src_path): self._alert("modified", e.src_path)

    def on_deleted(self, e):
        if self._match(e.src_path): self._alert("deleted", e.src_path)

    def on_created(self, e):
        if self._match(e.src_path): self._alert("created", e.src_path)

    def on_moved(self, e):
        if self._match(e.src_path): self._alert("moved", e.src_path)


def main() -> None:
    ap = argparse.ArgumentParser(description="Mini EDR Honeypot Sensor")
    ap.add_argument("--file", default="passwords.txt", help="Decoy file path")
    ap.add_argument("--webhook", default=None, help="Discord Webhook URL")
    args = ap.parse_args()

    decoy = os.path.abspath(args.file)
    watch_dir = os.path.dirname(decoy) or "."

    # Create decoy file if missing
    if not os.path.exists(decoy):
        with open(decoy, "w") as f:
            f.write("# HONEYPOT — DO NOT TOUCH\n")
        log.info(f"Created decoy: {decoy}")

    observer = Observer()
    observer.schedule(HoneypotHandler(decoy, args.webhook), watch_dir, recursive=False)
    observer.start()

    print(f"\n{C}{B}🛡  Mini EDR Sensor Active{X}")
    print(f"   Monitoring : {decoy}")
    print(f"   Webhook    : {'Enabled' if args.webhook else 'Disabled'}")
    print(f"   Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print(f"\n{Y}Sensor stopped.{X}")
    observer.join()


if __name__ == "__main__":
    main()
