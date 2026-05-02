#!/usr/bin/env python3
"""
Standalone Local Malware Scanner
Test your local detection engine against VirusTotal

Usage:
    python standalone_scanner.py <file_path> [--compare-vt]
    python standalone_scanner.py <directory> --batch [--compare-vt]
"""

import os
import sys
import json
import yara
import hashlib
import re
import argparse
import time
import zipfile
import tarfile
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from datetime import datetime
import requests

# ============================================================================
# CONFIGURATION
# ============================================================================

YARA_RULES_PATH = os.getenv('YARA_RULES_PATH', 'rules.yar')
CUSTOM_SIGNATURES_FILE = os.getenv('CUSTOM_SIGNATURES_FILE', 'custom_signatures.json')
VT_API_KEY = os.getenv('VT_API_KEY', '')

# Scoring weights
YARA_WEIGHT = 40
SIGNATURE_WEIGHT = 35
ARCHIVE_WEIGHT = 25

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class ThreatScore:
    yara_score: float = 0.0
    signature_score: float = 0.0
    archive_score: float = 0.0
    total_score: float = 0.0
    threat_level: str = "safe"

@dataclass
class ScanResult:
    filename: str
    file_hash: str
    file_size: int
    file_type: str
    is_malicious: bool
    threat_score: ThreatScore
    yara_matches: List[str] = field(default_factory=list)
    detections: List[str] = field(default_factory=list)
    malware_categories: List[str] = field(default_factory=list)
    scan_time: float = 0.0
    vt_detections: Optional[int] = None
    vt_total: Optional[int] = None
    vt_link: Optional[str] = None

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def detect_file_type_magic_bytes(data: bytes) -> Tuple[str, str]:
    """Detect file type using magic bytes"""
    if len(data) < 4:
        return ("unknown", "File too small")

    # Special handling for PK (ZIP-based) files
    if data.startswith(b'PK\x03\x04'):
        if len(data) >= 8192:
            if b'[Content_Types].xml' in data[:8192]:
                if b'word/' in data[:8192]:
                    return ('docx', 'Word document (DOCX)')
                elif b'xl/' in data[:8192]:
                    return ('xlsx', 'Excel spreadsheet (XLSX)')
                elif b'ppt/' in data[:8192]:
                    return ('pptx', 'PowerPoint presentation (PPTX)')
            if b'META-INF/' in data[:8192]:
                return ('jar', 'Java Archive (JAR)')
            if b'AndroidManifest.xml' in data[:8192]:
                return ('apk', 'Android Package (APK)')
        return ('zip', 'ZIP archive')

    # Magic bytes dictionary
    magic_bytes = {
        # Executables
        b'MZ': ('exe', 'Windows executable (PE)'),
        b'\x7fELF': ('elf', 'Linux executable (ELF)'),
        b'\xfe\xed\xfa\xce': ('macho', 'macOS executable (Mach-O 32-bit)'),
        b'\xfe\xed\xfa\xcf': ('macho', 'macOS executable (Mach-O 64-bit)'),

        # Images
        b'\x89PNG': ('png', 'PNG image'),
        b'\xff\xd8\xff': ('jpeg', 'JPEG image'),
        b'GIF87a': ('gif', 'GIF image (87a)'),
        b'GIF89a': ('gif', 'GIF image (89a)'),

        # Archives
        b'Rar!\x1a\x07': ('rar', 'RAR archive'),
        b'\x1f\x8b': ('gz', 'GZIP archive'),
        b'7z\xbc\xaf\x27\x1c': ('7z', '7-Zip archive'),

        # Documents
        b'%PDF': ('pdf', 'PDF document'),
        b'\xd0\xcf\x11\xe0': ('doc', 'Microsoft Office document (OLE)'),

        # Scripts
        b'#!/bin/bash': ('script', 'Bash script'),
        b'#!/bin/sh': ('script', 'Shell script'),
        b'#!/usr/bin/python': ('script', 'Python script'),
        b'<?php': ('php', 'PHP script'),
    }

    for magic, (file_type, description) in magic_bytes.items():
        if data.startswith(magic):
            return (file_type, description)

    return ("unknown", "Unknown file type")

def categorize_malware_type(yara_matches: List[str], detections: List[str],
                            archive_results: List[Dict] = None) -> List[str]:
    """Categorize the type of malware"""
    categories = []
    all_text = " ".join(yara_matches + detections).lower()

    # Check for Zip Bomb
    if archive_results:
        for result in archive_results:
            if result.get('zipbomb'):
                categories.append('💣 Zip Bomb')
                break

    # Check archive encryption
    if 'encrypted' in all_text or 'password protected' in all_text:
        categories.append('🔒 Encrypted Malicious Archive')

    # Ransomware
    if any(x in all_text for x in ['ransom', 'crypto_locker', 'wannacry', 'petya', 'ryuk']):
        categories.append('🔐 Ransomware')

    # Trojan
    if any(x in all_text for x in ['trojan', 'backdoor', 'rat_', 'remote access']):
        categories.append('🐴 Trojan')

    # Infostealer
    if any(x in all_text for x in ['stealer', 'password', 'credential', 'keylog', 'redline', 'raccoon']):
        categories.append('🕵️ Infostealer')

    # Cryptocurrency Miner
    if any(x in all_text for x in ['miner', 'cryptominer', 'xmrig', 'monero', 'stratum']):
        categories.append('⛏️ Cryptocurrency Miner')

    # Worm
    if 'worm' in all_text:
        categories.append('🐛 Worm')

    # Rootkit
    if 'rootkit' in all_text:
        categories.append('👤 Rootkit')

    # Downloader/Dropper
    if any(x in all_text for x in ['downloader', 'dropper', 'loader']):
        categories.append('⬇️ Downloader/Dropper')

    # Adware/PUP
    if any(x in all_text for x in ['adware', 'pup', 'potentially unwanted']):
        categories.append('📢 Adware/PUP')

    # Spyware
    if 'spyware' in all_text or 'spy_' in all_text:
        categories.append('👁️ Spyware')

    # Exploit
    if 'exploit' in all_text or 'cve-' in all_text:
        categories.append('💥 Exploit')

    # Webshell
    if any(x in all_text for x in ['webshell', 'web_shell', 'c99', 'r57']):
        categories.append('🌐 Webshell')

    # Phishing Kit
    if any(x in all_text for x in ['phish', 'fake_login', 'credential_harvest']):
        categories.append('🎣 Phishing Kit')

    # Botnet
    if any(x in all_text for x in ['botnet', 'mirai', 'ddos', 'c2', 'command and control']):
        categories.append('🤖 Botnet')

    # Banking Malware
    if any(x in all_text for x in ['banker', 'banking', 'zeus', 'dridex', 'trickbot']):
        categories.append('🏦 Banking Malware')

    # Mobile Malware
    if any(x in all_text for x in ['android', 'apk', 'mobile']):
        categories.append('📱 Mobile Malware')

    return categories[:5]  # Return top 5

def calculate_threat_level(score: float) -> str:
    """Calculate threat level from score"""
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    elif score >= 20:
        return "low"
    else:
        return "safe"

# ============================================================================
# SCANNER CLASS
# ============================================================================

class LocalMalwareScanner:
    """Standalone malware scanner using YARA + custom signatures"""

    def __init__(self, yara_rules_path: str, custom_sigs_path: str):
        print(f"[*] Initializing Local Malware Scanner...")

        # Load YARA rules
        self.yara_rules = None
        if os.path.exists(yara_rules_path):
            try:
                start = time.time()
                self.yara_rules = yara.compile(filepath=yara_rules_path)
                elapsed = time.time() - start
                print(f"[+] Loaded YARA rules from {yara_rules_path} ({elapsed:.2f}s)")
            except Exception as e:
                print(f"[-] Could not load YARA rules: {e}")
        else:
            print(f"[-] YARA rules file not found: {yara_rules_path}")

        # Built-in Signatures (fast, always active)
        self.signatures = {
            'powershell_encoded': rb'powershell.+(-enc|-encodedcommand)',
            'suspicious_vbs': rb'WScript\.Shell|CreateObject\("Shell\.Application"\)',
            'base64_executable': rb'TVqQAAMAAAAEAAAA',
            'discord_webhook': rb'discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+',
            'keylogger': rb'GetAsyncKeyState|SetWindowsHookEx',
            'ransomware': rb'CryptEncrypt|bitcoin|decrypt.*ransom',
            'cryptominer': rb'stratum\+tcp|xmrig|cpuminer',
            'obfuscated': rb'eval\(atob\(|FromBase64String'
        }

        # Load Custom Signatures from JSON
        self.custom_binary_patterns = {}
        self.custom_regex_patterns = {}
        self.signature_severities = {}

        if os.path.exists(custom_sigs_path):
            try:
                with open(custom_sigs_path, 'r') as f:
                    custom_sigs = json.load(f)

                # Load binary patterns
                for name, sig_data in custom_sigs.get('binary_patterns', {}).items():
                    pattern = sig_data.get('pattern', '')
                    severity = sig_data.get('severity', 'medium')
                    try:
                        clean_pattern = pattern.replace(' ', '').replace('?', '0')
                        self.custom_binary_patterns[name] = bytes.fromhex(clean_pattern)
                        self.signature_severities[name] = severity
                    except ValueError as e:
                        print(f"[-] Invalid hex pattern for {name}: {e}")

                # Load regex patterns
                for name, sig_data in custom_sigs.get('regex_patterns', {}).items():
                    pattern = sig_data.get('pattern', '')
                    severity = sig_data.get('severity', 'medium')
                    self.custom_regex_patterns[name] = pattern
                    self.signature_severities[name] = severity

                print(f"[+] Loaded {len(self.custom_binary_patterns)} binary + {len(self.custom_regex_patterns)} regex custom signatures")
            except Exception as e:
                print(f"[-] Could not load custom signatures: {e}")
        else:
            print(f"[!] Custom signatures file not found: {custom_sigs_path}")

    def scan_file(self, file_path: str) -> ScanResult:
        """Scan a file and return detailed results"""
        start_time = time.time()

        print(f"\n{'='*70}")
        print(f"Scanning: {file_path}")
        print(f"{'='*70}")

        # Read file
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            print(f"[-] Error reading file: {e}")
            return None

        filename = os.path.basename(file_path)
        file_size = len(data)
        file_hash = hashlib.sha256(data).hexdigest()

        # Detect file type
        file_type, file_type_desc = detect_file_type_magic_bytes(data)

        print(f"[*] Filename: {filename}")
        print(f"[*] Size: {file_size:,} bytes")
        print(f"[*] SHA-256: {file_hash}")
        print(f"[*] Type: {file_type_desc}")

        # Initialize scores
        yara_score = 0.0
        signature_score = 0.0
        archive_score = 0.0
        yara_matches = []
        detections = []
        archive_results = []

        # YARA Scanning
        if self.yara_rules:
            try:
                matches = self.yara_rules.match(data=data)
                if matches:
                    yara_matches = [m.rule for m in matches]
                    yara_score = min(100, len(matches) * 15)  # 15 points per rule
                    print(f"\n[!] YARA Matches ({len(matches)}):")
                    for match in matches:
                        print(f"    🎯 {match.rule}")
                        if match.tags:
                            print(f"       Tags: {', '.join(match.tags)}")
            except Exception as e:
                print(f"[-] YARA scan error: {e}")

        # Custom Signature Scanning
        print(f"\n[*] Scanning with custom signatures...")

        # Binary patterns
        for sig_name, sig_pattern in self.signatures.items():
            if re.search(sig_pattern, data, re.IGNORECASE):
                detections.append(f"builtin:{sig_name}")
                severity = 'high'
                score = {'critical': 30, 'high': 20, 'medium': 10, 'low': 5}.get(severity, 10)
                signature_score += score

        for sig_name, sig_pattern in self.custom_binary_patterns.items():
            if sig_pattern in data:
                detections.append(f"binary:{sig_name}")
                severity = self.signature_severities.get(sig_name, 'medium')
                score = {'critical': 30, 'high': 20, 'medium': 10, 'low': 5}.get(severity, 10)
                signature_score += score

        # Regex patterns
        for sig_name, sig_pattern in self.custom_regex_patterns.items():
            try:
                if re.search(sig_pattern.encode(), data, re.IGNORECASE):
                    detections.append(f"regex:{sig_name}")
                    severity = self.signature_severities.get(sig_name, 'medium')
                    score = {'critical': 30, 'high': 20, 'medium': 10, 'low': 5}.get(severity, 10)
                    signature_score += score
            except:
                pass

        if detections:
            print(f"[!] Custom Signature Matches ({len(detections)}):")
            for det in detections:
                print(f"    🔍 {det}")
        else:
            print(f"[+] No custom signature matches")

        # Archive Scanning
        if file_type in ['zip', 'tar', 'gz', '7z', 'rar']:
            print(f"\n[*] Analyzing archive...")
            archive_results = self._scan_archive(file_path, data)
            if archive_results:
                for result in archive_results:
                    if result.get('zipbomb'):
                        archive_score += 100
                    elif result.get('malicious'):
                        archive_score += result.get('threat_score', 50)

        # Cap individual scores at 100
        yara_score = min(100, yara_score)
        signature_score = min(100, signature_score)
        archive_score = min(100, archive_score)

        # Calculate weighted total score
        total_score = (
            (yara_score * YARA_WEIGHT / 100) +
            (signature_score * SIGNATURE_WEIGHT / 100) +
            (archive_score * ARCHIVE_WEIGHT / 100)
        )

        threat_level = calculate_threat_level(total_score)
        is_malicious = total_score >= 25  # Lowered threshold for testing

        # Categorize malware
        malware_categories = categorize_malware_type(yara_matches, detections, archive_results)

        scan_time = time.time() - start_time

        # Create threat score object
        threat_score = ThreatScore(
            yara_score=yara_score,
            signature_score=signature_score,
            archive_score=archive_score,
            total_score=total_score,
            threat_level=threat_level
        )

        # Print results
        print(f"\n{'='*70}")
        print(f"SCAN RESULTS")
        print(f"{'='*70}")
        print(f"Threat Level: {threat_level.upper()} ({total_score:.1f}/100)")
        print(f"Status: {'🚨 MALICIOUS' if is_malicious else '✅ SAFE'}")
        print(f"\nScore Breakdown:")
        print(f"  YARA:       {yara_score:>6.1f}/100  (weight: {YARA_WEIGHT}%)")
        print(f"  Signatures: {signature_score:>6.1f}/100  (weight: {SIGNATURE_WEIGHT}%)")
        print(f"  Archive:    {archive_score:>6.1f}/100  (weight: {ARCHIVE_WEIGHT}%)")
        print(f"  {'─'*40}")
        print(f"  TOTAL:      {total_score:>6.1f}/100")

        if malware_categories:
            print(f"\n☢️  Threat Categories:")
            for cat in malware_categories:
                print(f"    {cat}")

        print(f"\nScan Time: {scan_time:.3f}s")
        print(f"{'='*70}")

        return ScanResult(
            filename=filename,
            file_hash=file_hash,
            file_size=file_size,
            file_type=file_type_desc,
            is_malicious=is_malicious,
            threat_score=threat_score,
            yara_matches=yara_matches,
            detections=detections,
            malware_categories=malware_categories,
            scan_time=scan_time
        )

    def _scan_archive(self, file_path: str, data: bytes) -> List[Dict]:
        """Scan archive contents for threats"""
        results = []

        try:
            # Try ZIP
            if zipfile.is_zipfile(file_path):
                with zipfile.ZipFile(file_path, 'r') as zf:
                    # Check for zip bomb
                    total_compressed = sum(info.compress_size for info in zf.filelist)
                    total_uncompressed = sum(info.file_size for info in zf.filelist)

                    if total_compressed > 0:
                        ratio = total_uncompressed / total_compressed
                        if ratio > 100:
                            print(f"    ⚠️  High compression ratio: {ratio:.0f}:1")
                            if ratio > 1000:
                                print(f"    💣 ZIP BOMB DETECTED!")
                                results.append({'zipbomb': True, 'compression_ratio': ratio})

                    print(f"    📦 Archive contains {len(zf.filelist)} files")

        except Exception as e:
            print(f"    [-] Archive scan error: {e}")

        return results

    def compare_with_virustotal(self, file_hash: str) -> Optional[Tuple[int, int, str]]:
        """Compare results with VirusTotal"""
        if not VT_API_KEY:
            return None

        print(f"\n[*] Checking VirusTotal...")

        try:
            headers = {'x-apikey': VT_API_KEY}
            url = f'https://www.virustotal.com/api/v3/files/{file_hash}'

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                total = sum(stats.values())

                vt_link = f"https://www.virustotal.com/gui/file/{file_hash}"

                print(f"[+] VirusTotal: {malicious}/{total} engines detected malware")
                print(f"[+] Link: {vt_link}")

                return (malicious, total, vt_link)
            elif response.status_code == 404:
                print(f"[!] File not found in VirusTotal database")
                return (0, 0, None)
            else:
                print(f"[-] VirusTotal API error: {response.status_code}")
                return None

        except Exception as e:
            print(f"[-] VirusTotal check error: {e}")
            return None

# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Standalone Local Malware Scanner - Test against VirusTotal',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python standalone_scanner.py malware.exe
  python standalone_scanner.py malware.exe --compare-vt
  python standalone_scanner.py /path/to/samples/ --batch --compare-vt
  python standalone_scanner.py suspicious.zip --output results.json
        '''
    )

    parser.add_argument('path', help='File or directory to scan')
    parser.add_argument('--compare-vt', action='store_true',
                       help='Compare results with VirusTotal')
    parser.add_argument('--batch', action='store_true',
                       help='Batch scan all files in directory')
    parser.add_argument('--output', '-o', help='Save results to JSON file')
    parser.add_argument('--yara-rules', default=YARA_RULES_PATH,
                       help=f'Path to YARA rules file (default: {YARA_RULES_PATH})')
    parser.add_argument('--custom-sigs', default=CUSTOM_SIGNATURES_FILE,
                       help=f'Path to custom signatures (default: {CUSTOM_SIGNATURES_FILE})')

    args = parser.parse_args()

    # Banner
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║         Standalone Local Malware Scanner v1.0                     ║
║         Test Your Detection Engine Against VirusTotal             ║
╚═══════════════════════════════════════════════════════════════════╝
    """)

    # Initialize scanner
    scanner = LocalMalwareScanner(args.yara_rules, args.custom_sigs)

    # Get files to scan
    files_to_scan = []
    if os.path.isfile(args.path):
        files_to_scan.append(args.path)
    elif os.path.isdir(args.path) and args.batch:
        for root, dirs, files in os.walk(args.path):
            for file in files:
                files_to_scan.append(os.path.join(root, file))
        print(f"[*] Found {len(files_to_scan)} files to scan\n")
    else:
        print(f"[-] Invalid path or missing --batch flag for directory")
        sys.exit(1)

    # Scan files
    results = []
    for file_path in files_to_scan:
        result = scanner.scan_file(file_path)
        if result:
            # Compare with VirusTotal if requested
            if args.compare_vt:
                vt_result = scanner.compare_with_virustotal(result.file_hash)
                if vt_result:
                    result.vt_detections = vt_result[0]
                    result.vt_total = vt_result[1]
                    result.vt_link = vt_result[2]

            results.append(result)

    # Summary
    if len(results) > 1:
        print(f"\n{'='*70}")
        print(f"SUMMARY - Scanned {len(results)} files")
        print(f"{'='*70}")

        malicious = sum(1 for r in results if r.is_malicious)
        safe = len(results) - malicious

        print(f"🚨 Malicious: {malicious}")
        print(f"✅ Safe: {safe}")

        if args.compare_vt:
            print(f"\nVirusTotal Comparison:")
            for r in results:
                if r.vt_detections is not None:
                    local = "MALICIOUS" if r.is_malicious else "SAFE"
                    vt = f"{r.vt_detections}/{r.vt_total}"
                    match = "✓" if (r.is_malicious and r.vt_detections > 0) or (not r.is_malicious and r.vt_detections == 0) else "✗"
                    print(f"  {match} {r.filename[:40]:40} | Local: {local:9} | VT: {vt}")

    # Save to JSON if requested
    if args.output:
        output_data = []
        for r in results:
            output_data.append({
                'filename': r.filename,
                'file_hash': r.file_hash,
                'file_size': r.file_size,
                'file_type': r.file_type,
                'is_malicious': r.is_malicious,
                'threat_level': r.threat_score.threat_level,
                'total_score': r.threat_score.total_score,
                'yara_score': r.threat_score.yara_score,
                'signature_score': r.threat_score.signature_score,
                'archive_score': r.threat_score.archive_score,
                'yara_matches': r.yara_matches,
                'detections': r.detections,
                'malware_categories': r.malware_categories,
                'scan_time': r.scan_time,
                'vt_detections': r.vt_detections,
                'vt_total': r.vt_total,
                'vt_link': r.vt_link
            })

        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)

        print(f"\n[+] Results saved to {args.output}")

if __name__ == '__main__':
    main()
