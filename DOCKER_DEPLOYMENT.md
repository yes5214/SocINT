# 🐳 Docker Deployment Guide

Complete guide for deploying the Discord Security Bot using Docker.

---

## 📋 Prerequisites

- Docker Engine 20.10+ installed
- Docker Compose 2.0+ installed
- Discord Bot Token
- VirusTotal API Key (optional but recommended)

---

## 🚀 Quick Start

### 1. Clone and Setup

```bash
cd /home/oui5214/APU/FYP/SocINT

# Copy environment template
cp .env.example .env

# Edit with your credentials
nano .env
```

### 2. Configure Environment Variables

Edit `.env` and set:

```bash
DISCORD_TOKEN=your_discord_bot_token_here
VT_API_KEY=your_virustotal_api_key_here

# Optional: Adjust thresholds (defaults shown)
URL_DETECTION_THRESHOLD=25
FILE_DETECTION_THRESHOLD=15
```

### 3. Build and Run

```bash
# Build the Docker image
docker-compose build

# Start the bot
docker-compose up -d

# View logs
docker-compose logs -f
```

### 4. Stop the Bot

```bash
docker-compose down
```

---

## 🎯 Detection Threshold Configuration

Based on extensive testing with 40 real samples, we recommend different thresholds for URLs vs Files.

### URL Detection (Threshold: 25) ✅

**Testing Results:**
- Accuracy: 90.00%
- Precision: 90.00%
- Recall: 90.00%
- F1 Score: 90.00%
- **Status: PRODUCTION READY**

**Why 25?**
- Catches 9 out of 10 phishing URLs
- Only 1 false positive (discord.com - can be whitelisted)
- Patterns detect correctly at this level

**Configure in .env:**
```bash
URL_DETECTION_THRESHOLD=25
```

### File Detection (Threshold: 15) ⚠️

**Testing Results at Threshold 25:**
- Accuracy: 65.00%
- Recall: 60.00% (missed 4/10 malware) 🚨

**Testing Results at Threshold 15 (Recommended):**
- Better malware detection
- May increase false positives on security tools

**Why Lower?**
- Real malware often scores 7-20 points (single signatures)
- VBA macro documents score only 12 points
- Archive malware scores 13 points
- Lower threshold catches more threats

**Configure in .env:**
```bash
FILE_DETECTION_THRESHOLD=15
```

---

## 📁 Volume Mounts

The following directories/files are mounted for persistence:

| Host Path | Container Path | Purpose | Mode |
|-----------|----------------|---------|------|
| `./logs` | `/app/logs` | Bot logs | rw |
| `./quarantine_storage` | `/app/quarantine_storage` | Encrypted quarantine files | rw |
| `./quarantine.db` | `/app/quarantine.db` | Quarantine database | rw |
| `./rules.yar` | `/app/rules.yar` | YARA rules | ro |
| `./custom_signatures.json` | `/app/custom_signatures.json` | Signature database | ro |
| `./whitelist.json` | `/app/whitelist.json` | Domain whitelist | ro |
| `./malware_samples` | `/app/malware_samples` | Testing samples (optional) | ro |

**Note:** Read-only (ro) files require container rebuild to update.

---

## 🔄 Updating Rules and Signatures

### Update YARA Rules

```bash
# Stop the bot
docker-compose down

# Update rules.yar on host
# (e.g., run build_yara_rules.sh or manual edits)

# Rebuild and restart
docker-compose build
docker-compose up -d
```

### Update Custom Signatures

```bash
# Stop the bot
docker-compose down

# Edit custom_signatures.json on host

# Rebuild and restart
docker-compose build
docker-compose up -d
```

---

## 🧪 Testing Inside Container

The Docker image includes testing scripts for validation.

### Test URL Scanner

```bash
docker-compose exec discord-security-bot python test_real_urls.py
```

### Test File Scanner

```bash
docker-compose exec discord-security-bot python test_real_samples.py
```

### Run Standalone Scanner

```bash
# Scan a specific file
docker-compose exec discord-security-bot python standalone_scanner.py /app/malware_samples/testing/malware/suspicious.exe
```

---

## 📊 Monitoring

### View Live Logs

```bash
docker-compose logs -f
```

### Check Bot Status

```bash
docker-compose ps
```

### Access Quarantine Database

```bash
# Enter container shell
docker-compose exec discord-security-bot /bin/bash

# Query quarantine
python -c "from quarantine_db import QuarantineDB; db = QuarantineDB(); print(db.list_quarantined())"
```

---

## 🔧 Troubleshooting

### Bot Not Starting

**Check logs:**
```bash
docker-compose logs discord-security-bot
```

**Common issues:**
- Missing `DISCORD_TOKEN` in `.env`
- Invalid token format
- Network connectivity issues

### YARA Rules Not Loading

**Symptoms:** Bot starts but no YARA detections

**Solutions:**
1. Check rules.yar exists and is valid
2. Rebuild container: `docker-compose build`
3. Verify volume mount: `docker-compose exec discord-security-bot ls -la /app/rules.yar`

### Quarantine Not Persisting

**Problem:** Quarantined files disappear after restart

**Solution:** Ensure `quarantine_storage/` directory exists:
```bash
mkdir -p quarantine_storage
chmod 700 quarantine_storage
```

### Permission Denied Errors

**Problem:** Cannot write to quarantine or logs

**Solution:**
```bash
# Fix permissions on host
sudo chown -R $USER:$USER quarantine_storage logs
chmod 700 quarantine_storage
chmod 755 logs
```

---

## 🔐 Security Best Practices

### 1. Protect .env File

```bash
chmod 600 .env
```

Never commit `.env` to version control!

### 2. Quarantine Storage

The `quarantine_storage/` directory contains encrypted malware:
- Keep permissions at 700 (owner only)
- Regular backups recommended
- Store encryption key securely

### 3. Network Isolation

The bot runs in isolated Docker network `security-net`:
- No external ports exposed (bot connects to Discord)
- Quarantine files cannot escape container
- YARA rules read-only

### 4. Keep Rules Updated

```bash
# Regular updates (e.g., weekly cron job)
0 0 * * 0 cd /home/oui5214/APU/FYP/SocINT && ./build_yara_rules.sh && docker-compose restart
```

---

## 📈 Performance Tuning

### Adjust Thresholds Based on Your Needs

**High Security (Catch Everything):**
```bash
URL_DETECTION_THRESHOLD=20
FILE_DETECTION_THRESHOLD=10
```
⚠️ Warning: May increase false positives

**Balanced (Recommended):**
```bash
URL_DETECTION_THRESHOLD=25
FILE_DETECTION_THRESHOLD=15
```
✅ Based on testing results

**Low False Positives:**
```bash
URL_DETECTION_THRESHOLD=30
FILE_DETECTION_THRESHOLD=25
```
⚠️ Warning: May miss some malware

---

## 🆘 Support

### View Testing Results

See detailed testing analysis:
- `FINAL_TEST_RESULTS.md` - Complete testing breakdown
- `THRESHOLD_TEST_RESULTS.md` - Threshold comparison
- `malware_samples/testing/real_test_results.json` - Raw test data

### Re-run Tests

To validate your threshold configuration:

```bash
# Test with your current settings
docker-compose exec discord-security-bot python test_real_samples.py
docker-compose exec discord-security-bot python test_real_urls.py
```

---

## 🎯 Production Deployment Checklist

- [ ] `.env` file configured with valid tokens
- [ ] YARA rules updated and compiled
- [ ] Custom signatures reviewed
- [ ] Domain whitelist configured
- [ ] Thresholds set based on testing
- [ ] Quarantine storage directory created (700 permissions)
- [ ] Logs directory created (755 permissions)
- [ ] Docker image built successfully
- [ ] Test run completed without errors
- [ ] Monitoring/alerting configured
- [ ] Backup strategy for quarantine database

---

## 📝 Example docker-compose Commands

```bash
# Build without cache (force fresh build)
docker-compose build --no-cache

# Start in foreground (see logs immediately)
docker-compose up

# Start in background
docker-compose up -d

# Restart after config change
docker-compose restart

# Stop and remove containers
docker-compose down

# Stop, remove, and delete volumes
docker-compose down -v

# View resource usage
docker stats discord_security_bot

# Execute command in container
docker-compose exec discord-security-bot python --version
```

---

## 🔄 Update Workflow

### Standard Update Process

1. **Pull latest code:**
   ```bash
   git pull origin main
   ```

2. **Rebuild image:**
   ```bash
   docker-compose build
   ```

3. **Restart bot:**
   ```bash
   docker-compose down
   docker-compose up -d
   ```

### Quick Restart (no rebuild needed)

```bash
docker-compose restart
```

---

## 📊 Testing Results Summary

### URL Scanner: Grade A 🎯
- 90% accuracy at threshold 25
- **Production ready** with minor tweaks
- Add domain whitelist for discord.com

### File Scanner: Grade D ⚠️
- 65% accuracy at threshold 25
- Missed 40% of malware
- **Recommend threshold 15** for better detection
- Needs whitelist for security tools (FTK Imager, IDA Pro)

**Full analysis:** See `FINAL_TEST_RESULTS.md`

---

## 🎓 What Testing Taught Us

1. **URLs and Files need different thresholds**
   - URLs: 25 works perfectly
   - Files: Need lower (15) for better coverage

2. **Single signatures score low**
   - 1 signature at 'high' severity = only 7 points total
   - Many real malware samples trigger just 1-2 signatures

3. **Legitimate tools trigger many rules**
   - FTK Imager: 18 YARA matches (forensics tool)
   - Discord client: 25 YARA matches (official app)
   - Need intelligent whitelisting

4. **Coverage gaps exist**
   - Some malware scores 0 points (blind spots)
   - Continuous YARA rule updates essential

---

**Ready to deploy? Start with Quick Start section above! 🚀**
