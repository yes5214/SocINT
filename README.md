# SocInt

A Discord bot that scans messages, attachments, and URLs in real time for malware, phishing, and other threats. Combines YARA rules, custom signatures, VirusTotal, Google Safe Browsing, URLhaus, and Hybrid Analysis. Includes encrypted quarantine of detected files.

## Features

- **Multi-engine scanning** — YARA + custom signatures + VirusTotal + GSB + URLhaus + Hybrid Analysis
- **Real-time message + attachment + URL scanning** with parallel execution and result caching
- **Encrypted quarantine** — AES-256 (Fernet) for malicious file storage
- **Tunable detection thresholds** — separate URL / file thresholds backed by accuracy testing (see `FINAL_TEST_RESULTS.md`)
- **Audit logging** to a designated Discord channel
- **Slash commands + classic prefix commands**
- **Optional alert webhook** for external SIEM/alerting

## Tested Performance

| Scanner | Accuracy | Precision | Recall | F1 |
|---------|----------|-----------|--------|-----|
| URL (threshold 25)  | 90% | 90%   | 90% | 90% |
| File (threshold 15) | 65% | 66.7% | 60% | 63% |

See `FINAL_TEST_RESULTS.md` and `THRESHOLD_TEST_RESULTS.md` for full numbers.

## Requirements

- Python 3.8+
- Discord bot token ([Discord Developer Portal](https://discord.com/developers/applications))
- VirusTotal API key (free tier OK)
- Optional: Google Safe Browsing key, URLhaus auth key, Hybrid Analysis key
- Bot permissions: View Channels, Send Messages, Manage Messages, Embed Links, Attach Files, Read Message History

## Quick Start (Docker — recommended)

```bash
git clone https://github.com/<your-username>/discord-security-bot.git
cd discord-security-bot
cp .env.example .env
# edit .env with your real tokens
chmod +x deploy.sh
./deploy.sh
```

Pick option 1 ("Build and start bot"). Tail logs:
```bash
docker-compose logs -f
```

## Quick Start (Native Python)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edit .env with your real tokens
python3 discord_security_bot.py
```

## Configuration

All configuration lives in `.env`. Copy `.env.example` and fill in the required values:

| Variable | Required | Description |
|----------|----------|-------------|
| `DISCORD_TOKEN` | yes | Discord bot token |
| `VT_API_KEY` | yes | VirusTotal API key |
| `GSB_API_KEY` | no | Google Safe Browsing |
| `URLHAUS_AUTH_KEY` | no | URLhaus / abuse.ch |
| `HYBRID_ANALYSIS_API_KEY` | no | Hybrid Analysis |
| `QUARANTINE_ENCRYPTION_KEY` | no | Fernet key — generate with `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `URL_DETECTION_THRESHOLD` | no | default 25 |
| `FILE_DETECTION_THRESHOLD` | no | default 15 |

Full list and tuning notes in `.env.example`.

## Files

| File | Purpose |
|------|---------|
| `discord_security_bot.py` | Main bot |
| `standalone_scanner.py` | Run scans without Discord (CLI) |
| `quarantine_db.py` / `quarantine_ui.py` | Encrypted quarantine + management |
| `rules.yar` | YARA detection rules |
| `custom_signatures.json` | Custom malware signatures |
| `whitelist.json` | Whitelisted domains |
| `test_real_samples.py` / `test_real_urls.py` | Accuracy test harness |
| `Dockerfile` / `docker-compose.yml` / `deploy.sh` | Container deployment |

## Documentation

- [`DEPLOYMENT_README.md`](DEPLOYMENT_README.md) — full deployment walkthrough
- [`DOCKER_DEPLOYMENT.md`](DOCKER_DEPLOYMENT.md) — Docker reference
- [`DOCKER_UPDATE_SUMMARY.md`](DOCKER_UPDATE_SUMMARY.md) — migration notes
- [`FINAL_TEST_RESULTS.md`](FINAL_TEST_RESULTS.md) — accuracy results
- [`THRESHOLD_TEST_RESULTS.md`](THRESHOLD_TEST_RESULTS.md) — threshold tuning

## Security Notes

- Never commit `.env` — it is excluded by `.gitignore`
- Rotate your tokens if `.env` is leaked
- Quarantined files are encrypted at rest; lose the encryption key and you lose access
- Bot is intended for use on Discord servers you own or administer

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

Provided for educational and defensive security research. Detection accuracy varies with rule set freshness and threshold configuration. Not a replacement for endpoint AV / EDR.
