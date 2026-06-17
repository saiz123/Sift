"""Server startup — ThreadingHTTPServer setup and main()."""

from http.server import ThreadingHTTPServer

import config
from .storage import db
from .routes import Handler, WEBHOOK_NORMALIZERS


def main():
    db.init_db()
    server = ThreadingHTTPServer((config.HOST, config.PORT), Handler)
    print("\n  sift is listening")
    print(f"  dashboard : http://{config.HOST}:{config.PORT}/")
    sources = ", ".join(sorted(p.rsplit("/", 1)[1] for p in WEBHOOK_NORMALIZERS))
    print(f"  webhooks  : http://{config.HOST}:{config.PORT}/webhook/<source>  ({sources})")
    keys = []
    if config.ABUSEIPDB_KEY:
        keys.append("AbuseIPDB")
    if config.VIRUSTOTAL_KEY:
        keys.append("VirusTotal")
    if config.ENABLE_THREAT_FEEDS:
        keys.append(f"{len(config.THREAT_FEEDS)} threat feed(s)")
    if config.LOCAL_BLOCKLIST_PATH:
        keys.append("local blocklist")
    print(f"  enrichment: {', '.join(keys) if keys else 'off (no API keys set — that is fine)'}")
    if config.THEHIVE_URL and not config.THEHIVE_URL.startswith("https://"):
        print("  WARNING: THEHIVE_URL is not https — API token will be sent in cleartext\n")
    if not db.has_any_user():
        print("  AUTH: no users configured — run `python cli.py init-user` to add one")
    print("  Ctrl-C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped")
        server.shutdown()
