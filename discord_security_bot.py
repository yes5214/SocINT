import asyncio
import hashlib
import re
import aiohttp
import yara
import json
import logging
import os
import zipfile
import tarfile
import math
from io import BytesIO
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import urlparse
from collections import defaultdict
import time
from dotenv import load_dotenv

import discord
from discord.ext import commands, tasks

# Import quarantine system
from quarantine_db import QuarantineDB
from quarantine_ui import ThreatActionView, URLActionView, QuarantinePaginator, RetrieveConfirmView

# Load environment variables
load_dotenv()

# Core Settings
DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')
VT_API_KEY = os.getenv('VT_API_KEY')
YARA_RULES_PATH = os.getenv('YARA_RULES_PATH', 'rules.yar')

# External APIs
HYBRID_ANALYSIS_API_KEY = os.getenv('HYBRID_ANALYSIS_API_KEY', '')
GSB_API_KEY = os.getenv('GSB_API_KEY', '')
URLHAUS_AUTH_KEY = os.getenv('URLHAUS_AUTH_KEY', '')
QUARANTINE_ENCRYPTION_KEY = os.getenv('QUARANTINE_ENCRYPTION_KEY', '')

# Scanning Settings
AUTO_DELETE_MALICIOUS = os.getenv('AUTO_DELETE_MALICIOUS', 'false').lower() == 'true'
ENABLE_QUARANTINE = os.getenv('ENABLE_QUARANTINE', 'true').lower() == 'true'
AUTO_QUARANTINE_TIMEOUT = int(os.getenv('AUTO_QUARANTINE_TIMEOUT', '300'))  # 5 minutes
QUARANTINE_CLEANUP_DAYS = int(os.getenv('QUARANTINE_CLEANUP_DAYS', '30'))
VT_THRESHOLD = int(os.getenv('VT_THRESHOLD', '3'))
YARA_THRESHOLD = int(os.getenv('YARA_THRESHOLD', '1'))
MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', '100')) * 1024 * 1024  # Convert to bytes

# Features
ENABLE_URL_SCANNING = os.getenv('ENABLE_URL_SCANNING', 'true').lower() == 'true'
ENABLE_ATTACHMENT_SCANNING = os.getenv('ENABLE_ATTACHMENT_SCANNING', 'true').lower() == 'true'
MAX_URLS_PER_MESSAGE = int(os.getenv('MAX_URLS_PER_MESSAGE', '5'))

# File Extensions
BLOCKED_EXTENSIONS = set([ext.strip() for ext in os.getenv('BLOCKED_EXTENSIONS', '').split(',') if ext.strip()])
ALLOWED_EXTENSIONS = set([ext.strip() for ext in os.getenv('ALLOWED_EXTENSIONS', '').split(',') if ext.strip()])
TRUSTED_DOMAINS = set([dom.strip() for dom in os.getenv('TRUSTED_DOMAINS', '').split(',') if dom.strip()])

# Notifications
AUDIT_CHANNEL_ID = int(os.getenv('AUDIT_CHANNEL_ID')) if os.getenv('AUDIT_CHANNEL_ID') else None
ALERT_WEBHOOK_URL = os.getenv('ALERT_WEBHOOK_URL', '')
MENTION_USER_ON_DELETE = os.getenv('MENTION_USER_ON_DELETE', 'true').lower() == 'true'
SEND_DM_ON_MALICIOUS = os.getenv('SEND_DM_ON_MALICIOUS', 'false').lower() == 'true'
WARNING_DELETE_DELAY = int(os.getenv('WARNING_DELETE_DELAY', '15'))

# Performance
ENABLE_CACHING = os.getenv('ENABLE_CACHING', 'true').lower() == 'true'
CACHE_TTL_HOURS = int(os.getenv('CACHE_TTL_HOURS', '24'))
VT_RATE_LIMIT = int(os.getenv('VT_RATE_LIMIT', '4'))
MAX_CONCURRENT_SCANS = int(os.getenv('MAX_CONCURRENT_SCANS', '10'))

# Logging
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
DEBUG_MODE = os.getenv('DEBUG_MODE', 'false').lower() == 'true'

# Setup logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SecurityBot')

logger.info("=" * 60)
logger.info("Discord Security Bot - FULLY ENHANCED")
logger.info("=" * 60)
logger.info(f"Auto Delete: {AUTO_DELETE_MALICIOUS}")
logger.info(f"VT Threshold: {VT_THRESHOLD}")
logger.info(f"Audit Channel: {AUDIT_CHANNEL_ID}")
logger.info(f"Hybrid Analysis: {'Enabled' if HYBRID_ANALYSIS_API_KEY else 'Disabled'}")
logger.info(f"Google Safe Browsing: {'Enabled' if GSB_API_KEY else 'Disabled'}")
logger.info(f"URLhaus: {'Enabled' if URLHAUS_AUTH_KEY else 'Disabled'}")
logger.info(f"VirusTotal: Enabled (Files + URLs)")
logger.info("=" * 60)


# Utility Functions
def defang_url(url: str) -> str:
    """Defang URL to prevent accidental clicks"""
    defanged = url.replace('http://', 'hxxp://').replace('https://', 'hxxps://')
    defanged = defanged.replace('.', '[.]')
    return defanged


def categorize_malware_type(yara_matches: List[str], detections: List[str],
                            archive_scan_results: List[Dict] = None,
                            hybrid_verdict: str = "") -> List[str]:
    """
    Categorize the type of malware based on detections
    Returns list of malware categories like ['Ransomware', 'Trojan', 'Zip Bomb']
    """
    categories = []
    all_text = " ".join(yara_matches + detections).lower()

    # Check for Zip Bomb
    if archive_scan_results:
        for result in archive_scan_results:
            if result.get('zipbomb'):
                categories.append('💣 Zip Bomb')
                break
            if result.get('encrypted') and result.get('malicious'):
                categories.append('🔒 Encrypted Malicious Archive')
                break

    # Ransomware
    if any(keyword in all_text for keyword in ['ransom', 'encrypt', 'crypto', 'locker', 'crypt']):
        categories.append('🔐 Ransomware')

    # Trojan
    if any(keyword in all_text for keyword in ['trojan', 'backdoor', 'rat', 'remote access']):
        categories.append('🐴 Trojan')

    # Stealer/Infostealer
    if any(keyword in all_text for keyword in ['stealer', 'clipper', 'keylog', 'credentials', 'password']):
        categories.append('🕵️ Infostealer')

    # Miner (Cryptocurrency)
    if any(keyword in all_text for keyword in ['miner', 'mining', 'xmrig', 'monero', 'coinminer']):
        categories.append('⛏️ Cryptocurrency Miner')

    # Worm
    if any(keyword in all_text for keyword in ['worm', 'spreader', 'propagat']):
        categories.append('🐛 Worm')

    # Rootkit
    if any(keyword in all_text for keyword in ['rootkit', 'bootkitget', 'kernel']):
        categories.append('👤 Rootkit')

    # Downloader/Dropper
    if any(keyword in all_text for keyword in ['download', 'dropper', 'loader', 'stager']):
        categories.append('⬇️ Downloader/Dropper')

    # Adware/PUP
    if any(keyword in all_text for keyword in ['adware', 'pup', 'potentially unwanted', 'bundler']):
        categories.append('📢 Adware/PUP')

    # Spyware
    if any(keyword in all_text for keyword in ['spyware', 'monitor', 'surveillance', 'tracking']):
        categories.append('👁️ Spyware')

    # Exploit
    if any(keyword in all_text for keyword in ['exploit', 'cve-', 'vulnerability', 'shellcode']):
        categories.append('💥 Exploit')

    # Webshell
    if any(keyword in all_text for keyword in ['webshell', 'php shell', 'backdoor php', 'c99', 'r57']):
        categories.append('🌐 Webshell')

    # Phishing
    if any(keyword in all_text for keyword in ['phish', 'credential', 'fake login', 'scam page']):
        categories.append('🎣 Phishing Kit')

    # Botnet
    if any(keyword in all_text for keyword in ['botnet', 'mirai', 'ddos', 'c2', 'command and control']):
        categories.append('🤖 Botnet')

    # Banking malware
    if any(keyword in all_text for keyword in ['banker', 'banking', 'carder', 'pos malware']):
        categories.append('🏦 Banking Malware')

    # Mobile malware
    if any(keyword in all_text for keyword in ['android', 'mobile', 'apk malware', 'sms trojan']):
        categories.append('📱 Mobile Malware')

    # Check hybrid verdict
    if hybrid_verdict and hybrid_verdict.lower() not in ['no-verdict', 'unknown']:
        if 'malicious' in hybrid_verdict.lower():
            if not categories:  # Only add generic if no specific category found
                categories.append('⚠️ Malicious File')

    # If no specific category found but we have detections
    if not categories and (yara_matches or detections):
        categories.append('⚠️ Suspicious Activity')

    return categories[:5]  # Return top 5 categories


def detect_file_type_magic_bytes(data: bytes) -> Tuple[str, str]:
    """
    Detect file type using magic bytes instead of extension
    Returns: (file_type, description)
    """
    if len(data) < 4:
        return ("unknown", "File too small")

    # Special handling for PK (ZIP-based) files
    if data.startswith(b'PK\x03\x04') or data.startswith(b'\x50\x4b\x03\x04'):
        # Check if it's an Office document by looking for specific internal files
        try:
            # Office documents contain these files in the ZIP:
            # - [Content_Types].xml for all Office docs
            # - word/ for DOCX
            # - xl/ for XLSX
            # - ppt/ for PPTX
            if b'[Content_Types].xml' in data[:8192]:
                if b'word/' in data[:8192]:
                    return ('docx', 'Word document (DOCX)')
                elif b'xl/' in data[:8192]:
                    return ('xlsx', 'Excel spreadsheet (XLSX)')
                elif b'ppt/' in data[:8192]:
                    return ('pptx', 'PowerPoint presentation (PPTX)')
                else:
                    return ('office', 'Office document (DOCX/XLSX/PPTX)')
            # Check for JAR (Java Archive)
            elif b'META-INF/' in data[:8192] or b'META-INF/MANIFEST.MF' in data[:8192]:
                return ('jar', 'Java Archive (JAR)')
            # Check for APK (Android Package)
            elif b'AndroidManifest.xml' in data[:8192]:
                return ('apk', 'Android Package (APK)')
            else:
                return ('zip', 'ZIP archive')
        except:
            return ('zip', 'ZIP archive')

    # Check other magic bytes signatures
    magic_signatures = {
        b'\x89PNG': ('png', 'PNG image'),
        b'GIF8': ('gif', 'GIF image'),
        b'\xff\xd8\xff': ('jpeg', 'JPEG image'),
        b'BM': ('bmp', 'BMP image'),
        b'PK\x05\x06': ('zip', 'ZIP archive (empty)'),
        b'PK\x07\x08': ('zip', 'ZIP archive (spanned)'),
        b'Rar!\x1a\x07': ('rar', 'RAR archive'),
        b'\x1f\x8b': ('gzip', 'GZIP archive'),
        b'BZh': ('bzip2', 'BZIP2 archive'),
        b'\xd0\xcf\x11\xe0': ('ole', 'Microsoft Office document (DOC/XLS/PPT)'),
        b'%PDF': ('pdf', 'PDF document'),
        b'\x7fELF': ('elf', 'Linux executable'),
        b'MZ': ('exe', 'Windows executable'),
        b'\xca\xfe\xba\xbe': ('macho', 'macOS executable'),
        b'\xfe\xed\xfa': ('macho', 'macOS executable (32-bit)'),
        b'\xcf\xfa\xed\xfe': ('macho', 'macOS executable (64-bit)'),
        b'#!/': ('script', 'Shell script'),
        b'<?php': ('php', 'PHP script'),
        b'<html': ('html', 'HTML document'),
        b'<!DOCTYPE': ('html', 'HTML document'),
    }

    for signature, (file_type, description) in magic_signatures.items():
        if data.startswith(signature):
            return (file_type, description)

    # Check if it's text
    try:
        data[:512].decode('utf-8', errors='strict')
        return ('text', 'Text file')
    except UnicodeDecodeError:
        return ('binary', 'Unknown binary file')


@dataclass
class ThreatScore:
    """Comprehensive threat scoring"""
    yara_score: float = 0.0
    signature_score: float = 0.0
    virustotal_score: float = 0.0
    heuristic_score: float = 0.0
    reputation_score: float = 0.0
    hybrid_analysis_score: float = 0.0  # NEW
    
    total_score: float = 0.0
    threat_level: str = "safe"
    confidence: float = 0.0
    score_breakdown: Dict[str, float] = field(default_factory=dict)
    
    def calculate_total(self, weights: Dict[str, float] = None):
        """Calculate weighted total score"""
        if weights is None:
            weights = {
                'yara': 0.20,              # Reduced from 0.25 → Strong local detection
                'signature': 0.12,         # Reduced from 0.15 → Specific patterns
                'virustotal': 0.45,        # INCREASED from 0.30 → Most accurate (70+ engines)
                'heuristic': 0.08,         # Reduced from 0.10 → Supplementary analysis
                'reputation': 0.05,        # Unchanged → Least reliable
                'hybrid_analysis': 0.10    # Reduced from 0.15 → Behavioral analysis
            }
        
        self.total_score = (
            self.yara_score * weights['yara'] +
            self.signature_score * weights['signature'] +
            self.virustotal_score * weights['virustotal'] +
            self.heuristic_score * weights['heuristic'] +
            self.reputation_score * weights['reputation'] +
            self.hybrid_analysis_score * weights['hybrid_analysis']
        )
        
        self.score_breakdown = {
            'YARA Rules': self.yara_score,
            'Signatures': self.signature_score,
            'VirusTotal': self.virustotal_score,
            'Heuristics': self.heuristic_score,
            'Reputation': self.reputation_score,
            'Hybrid Analysis': self.hybrid_analysis_score
        }
        
        if self.total_score >= 80:
            self.threat_level = "critical"
            self.confidence = 95.0
        elif self.total_score >= 60:
            self.threat_level = "high"
            self.confidence = 85.0
        elif self.total_score >= 40:
            self.threat_level = "medium"
            self.confidence = 75.0
        elif self.total_score >= 20:
            self.threat_level = "low"
            self.confidence = 65.0
        else:
            self.threat_level = "safe"
            self.confidence = 90.0
        
        return self.total_score

    def _recalculate_total(self):
        """Recalculate total score after manual adjustments"""
        return self.calculate_total()


@dataclass
class EnhancedScanResult:
    """Enhanced scan result"""
    file_hash: str
    file_name: str
    file_size: int
    threat_score: ThreatScore
    detections: List[str]
    yara_matches: List[str]
    vt_positives: int
    vt_total: int
    hybrid_verdict: str = ""
    scan_time: float = 0.0
    cached: bool = False
    scan_timestamp: datetime = field(default_factory=datetime.utcnow)
    # New fields for enhanced analysis
    entropy: float = 0.0
    md5_hash: str = ""
    sha1_hash: str = ""
    is_archive: bool = False
    archive_files: List[str] = field(default_factory=list)
    archive_scan_results: List[Dict] = field(default_factory=list)
    # Magic bytes detection
    detected_file_type: str = ""
    file_type_description: str = ""
    file_command_output: str = ""
    # Malware categorization
    malware_categories: List[str] = field(default_factory=list)

    @property
    def is_malicious(self) -> bool:
        return self.threat_score.threat_level in ['high', 'critical']
    
    def to_embed(self) -> discord.Embed:
        """Convert to Discord embed"""
        score = self.threat_score.total_score
        threat = self.threat_score.threat_level
        
        color_map = {
            'safe': discord.Color.green(),
            'low': discord.Color.blue(),
            'medium': discord.Color.orange(),
            'high': discord.Color.red(),
            'critical': discord.Color.dark_red()
        }
        color = color_map.get(threat, discord.Color.greyple())
        
        emoji_map = {
            'safe': '✅',
            'low': '🟦',
            'medium': '⚠️',
            'high': '🚨',
            'critical': '☠️'
        }
        emoji = emoji_map.get(threat, '❓')
        
        title_map = {
            'safe': 'File Cleared - Safe',
            'low': 'Low Risk Detection',
            'medium': 'Medium Risk - Suspicious',
            'high': 'High Risk - Malicious',
            'critical': 'CRITICAL THREAT DETECTED'
        }
        title = f"{emoji} {title_map.get(threat, 'Scan Complete')}"

        # Determine detection sources (like URL scans)
        detection_sources = []
        if self.yara_matches:
            detection_sources.append("🔍 YARA Rules")
        if self.detections:
            detection_sources.append("🔎 Signatures")
        if self.vt_positives > 0:
            detection_sources.append("🦠 VirusTotal")
        if self.hybrid_verdict and self.hybrid_verdict != 'no-verdict':
            detection_sources.append("🔬 Hybrid Analysis")

        # Build description with detection sources
        description = f"**File:** `{self.file_name}` ({self._format_size(self.file_size)})"
        if detection_sources and threat not in ['safe', 'low']:
            sources_text = " + ".join(detection_sources)
            description += f"\n**Detected by:** {sources_text}"

        embed = discord.Embed(
            title=title,
            description=description,
            color=color,
            timestamp=self.scan_timestamp
        )

        # Malware Categories (PROMINENT - Show what type of malware this is)
        if self.malware_categories:
            categories_text = " | ".join(self.malware_categories)
            embed.add_field(
                name="☢️ Threat Type",
                value=categories_text,
                inline=False
            )

        # Threat Score
        score_bar = self._create_score_bar(score)
        embed.add_field(
            name="🎯 Threat Score",
            value=f"```\n{score_bar}\n{score:.1f}/100 | {threat.upper()} Risk```",
            inline=False
        )
        
        # Score Breakdown
        breakdown_text = "```\n"
        for component, component_score in self.threat_score.score_breakdown.items():
            bar = self._create_mini_bar(component_score, width=10)
            breakdown_text += f"{component:<17} {bar} {component_score:>5.1f}\n"
        breakdown_text += "```"
        
        embed.add_field(
            name="📈 Score Breakdown",
            value=breakdown_text,
            inline=False
        )
        
        # Detection Details
        if self.yara_matches:
            # Classify YARA matches by severity
            LOW_SEVERITY_RULES = {
                'Big_Numbers1', 'Big_Numbers2', 'Big_Numbers3', 'Big_Numbers',
                'invalid_trailer_structure', 'multiple_versions', 'CRC32_poly_Constant',
                'BASE64_table', 'network_http', 'network_tcp', 'network_dns',
                'win_files_operation', 'Str_Win32_Wininet_Library',
                'Str_Win32_Internet_API', 'Str_Win32_Http_API',
                'SEH_Save', 'SEH_Init', 'anti_dbg', 'maldoc_getEIP_method_1',
                'IsPE32', 'HasOverlay', 'HasDigitalSignature',
                # File format detections (not necessarily malicious)
                'Contains_VBA_macro_code', 'Contains_UserForm_Object',
                'Contains_VBE_File', 'Contains_DDE_Protocol',
                # Common capabilities (informational only)
                'inject_thread', 'create_process', 'win_registry', 'win_mutex',
                'antivirusdetector', 'check_sandbox', 'VM_detect'
            }

            high_severity = [m for m in self.yara_matches if m not in LOW_SEVERITY_RULES]
            low_severity = [m for m in self.yara_matches if m in LOW_SEVERITY_RULES]

            matches_text = ""
            if high_severity:
                matches_text += "**🚨 Suspicious:**\n"
                matches_text += "\n".join([f"• `{match}`" for match in high_severity[:3]])
                if len(high_severity) > 3:
                    matches_text += f"\n• *... and {len(high_severity) - 3} more*"

            if low_severity:
                if matches_text:
                    matches_text += "\n\n"
                matches_text += "**ℹ️ Informational:**\n"
                matches_text += "\n".join([f"• `{match}`" for match in low_severity[:3]])
                if len(low_severity) > 3:
                    matches_text += f"\n• *... and {len(low_severity) - 3} more*"

            embed.add_field(
                name=f"🔍 YARA Detections ({len(high_severity)} critical)",
                value=matches_text,
                inline=True
            )

        # Signature Detections with Enhanced Categories
        if self.detections:
            custom_sigs = [d.replace('custom_', '') for d in self.detections if d.startswith('custom_')]
            builtin_sigs = [d for d in self.detections if not d.startswith('custom_')]
            all_sigs = custom_sigs + builtin_sigs

            # Enhanced categorization with more specific threat types
            categories = {
                'ransomware': [s for s in all_sigs if any(x in s.lower() for x in ['ransomware', 'wannacry', 'ryuk', 'lockbit', 'encrypt'])],
                'trojan': [s for s in all_sigs if any(x in s.lower() for x in ['trojan', 'backdoor', 'rat', 'cobalt', 'beacon'])],
                'stealer': [s for s in all_sigs if any(x in s.lower() for x in ['stealer', 'keylog', 'credential', 'mimikatz', 'token'])],
                'malware': [s for s in all_sigs if any(x in s.lower() for x in ['malware', 'emotet', 'trickbot', 'dridex', 'meterpreter'])],
                'attack': [s for s in all_sigs if any(x in s.lower() for x in ['powershell', 'cmd', 'injection', 'exploit', 'shell', 'bypass', 'escalation'])],
                'suspicious': []
            }

            # Anything not categorized goes to suspicious
            categorized = set(sum(categories.values(), []))
            categories['suspicious'] = [s for s in all_sigs if s not in categorized]

            # Build threat type summary for description
            threat_types = []
            if categories['ransomware']:
                threat_types.append("Ransomware")
            if categories['trojan']:
                threat_types.append("Trojan/Backdoor")
            if categories['stealer']:
                threat_types.append("Info Stealer")
            if categories['malware']:
                threat_types.append("Malware")
            if categories['attack']:
                threat_types.append("Attack Pattern")

            # Add threat type to description if detected
            if threat_types and threat not in ['safe', 'low']:
                classification = " | ".join(threat_types[:2])  # Show top 2 categories
                if len(threat_types) > 2:
                    classification += f" +{len(threat_types) - 2}"
                embed.description += f"\n**Threat Type:** `{classification}`"

            # Build detailed signature display
            sig_text = ""

            if categories['ransomware']:
                sig_text += "**💀 Ransomware:**\n"
                sig_text += "\n".join([f"• `{sig}`" for sig in categories['ransomware'][:3]])
                if len(categories['ransomware']) > 3:
                    sig_text += f"\n• *...+{len(categories['ransomware']) - 3} more*"
                sig_text += "\n\n"

            if categories['trojan']:
                sig_text += "**🦠 Trojan/Backdoor:**\n"
                sig_text += "\n".join([f"• `{sig}`" for sig in categories['trojan'][:3]])
                if len(categories['trojan']) > 3:
                    sig_text += f"\n• *...+{len(categories['trojan']) - 3} more*"
                sig_text += "\n\n"

            if categories['stealer']:
                sig_text += "**🔑 Info Stealer:**\n"
                sig_text += "\n".join([f"• `{sig}`" for sig in categories['stealer'][:3]])
                if len(categories['stealer']) > 3:
                    sig_text += f"\n• *...+{len(categories['stealer']) - 3} more*"
                sig_text += "\n\n"

            if categories['malware']:
                sig_text += "**☠️ Malware:**\n"
                sig_text += "\n".join([f"• `{sig}`" for sig in categories['malware'][:3]])
                if len(categories['malware']) > 3:
                    sig_text += f"\n• *...+{len(categories['malware']) - 3} more*"
                sig_text += "\n\n"

            if categories['attack']:
                sig_text += "**⚔️ Attack Pattern:**\n"
                sig_text += "\n".join([f"• `{sig}`" for sig in categories['attack'][:3]])
                if len(categories['attack']) > 3:
                    sig_text += f"\n• *...+{len(categories['attack']) - 3} more*"
                sig_text += "\n\n"

            if categories['suspicious']:
                sig_text += "**⚠️ Suspicious:**\n"
                sig_text += "\n".join([f"• `{sig}`" for sig in categories['suspicious'][:3]])
                if len(categories['suspicious']) > 3:
                    sig_text += f"\n• *...+{len(categories['suspicious']) - 3} more*"

            embed.add_field(
                name=f"🔎 Signature Detections ({len(self.detections)} total)",
                value=sig_text.strip(),
                inline=True
            )

        if self.vt_positives > 0:
            vt_percentage = (self.vt_positives / self.vt_total * 100) if self.vt_total > 0 else 0
            embed.add_field(
                name="🦠 VirusTotal",
                value=f"{self.vt_positives}/{self.vt_total} engines ({vt_percentage:.1f}%)",
                inline=True
            )
        
        if self.hybrid_verdict:
            embed.add_field(
                name="🔬 Hybrid Analysis",
                value=f"`{self.hybrid_verdict}`",
                inline=True
            )

        # File Hashes with VirusTotal Link (Full SHA256)
        hash_text = f"**SHA-256:**\n`{self.file_hash}`\n"
        if self.md5_hash:
            hash_text += f"**MD5:** `{self.md5_hash}`\n"
        if self.sha1_hash:
            hash_text += f"**SHA-1:** `{self.sha1_hash}`\n"

        # Add VirusTotal link
        vt_link = f"https://www.virustotal.com/gui/file/{self.file_hash}"
        hash_text += f"\n[🔗 View on VirusTotal]({vt_link})"

        embed.add_field(
            name="🔐 File Hashes",
            value=hash_text,
            inline=False
        )

        # Entropy Analysis
        if self.entropy > 0:
            entropy_emoji = "🔴" if self.entropy > 7.2 else "🟡" if self.entropy > 6.8 else "🟢"
            entropy_desc = "High (Packed/Encrypted)" if self.entropy > 7.2 else "Medium" if self.entropy > 6.8 else "Normal"

            # Add context for archives - high entropy is expected
            if self.is_archive and self.entropy > 7.2:
                entropy_desc = "High (Expected for ZIP)"
                entropy_emoji = "🟡"  # Change to yellow since it's normal for archives

            embed.add_field(
                name="📊 Entropy",
                value=f"{entropy_emoji} `{self.entropy:.2f}/8.0` - {entropy_desc}",
                inline=True
            )

        # File Type Detection (Magic Bytes)
        if self.detected_file_type or self.file_command_output:
            file_type_text = ""
            if self.detected_file_type:
                file_type_text += f"**Detected:** `{self.file_type_description}`\n"
            if self.file_command_output:
                file_type_text += f"**file:** `{self.file_command_output}`"

            embed.add_field(
                name="🔬 File Type (Magic Bytes)",
                value=file_type_text.strip(),
                inline=True
            )

        # Archive Information
        if self.is_archive:
            archive_text = f"**Files:** {len(self.archive_files)}\n"
            if self.archive_files:
                archive_text += "**Contents:**\n"
                archive_text += "\n".join([f"• `{f}`" for f in self.archive_files[:5]])
                if len(self.archive_files) > 5:
                    archive_text += f"\n• *... and {len(self.archive_files) - 5} more*"

            if self.archive_scan_results:
                malicious_count = sum(1 for r in self.archive_scan_results if r.get('malicious', False))
                if malicious_count > 0:
                    archive_text += f"\n\n⚠️ **{malicious_count} malicious file(s) found!**"

                    # Show details of malicious files found
                    malicious_files = [r for r in self.archive_scan_results if r.get('malicious', False)]
                    for i, mal_file in enumerate(malicious_files[:3]):  # Show first 3 malicious files
                        file_name = mal_file.get('filename', 'unknown')
                        score = mal_file.get('threat_score', 0)
                        level = mal_file.get('threat_level', 'UNKNOWN')

                        # Check if it's a zipbomb
                        if mal_file.get('zipbomb'):
                            ratio = mal_file.get('compression_ratio', 0)
                            encrypted = mal_file.get('encrypted', False)
                            encryption_tag = " 🔒" if encrypted else ""
                            archive_text += f"\n🎈 **ZIPBOMB** ({ratio:.0f}:1 ratio){encryption_tag}"
                        elif mal_file.get('encrypted'):
                            archive_text += f"\n🔒 **Encrypted Archive** ({mal_file.get('reason', 'Password protected')})"
                        else:
                            archive_text += f"\n🚨 `{file_name[:30]}` → {score:.0f}/100 ({level})"

                            # Show malware categories if available
                            categories = mal_file.get('malware_categories', [])
                            if categories:
                                archive_text += f"\n   ☢️ {' | '.join(categories[:2])}"

                            # Show YARA matches if available
                            yara_matches = mal_file.get('yara_matches', [])
                            if yara_matches:
                                archive_text += f"\n   🎯 YARA: {', '.join(yara_matches[:2])}"
                                if len(yara_matches) > 2:
                                    archive_text += f" (+{len(yara_matches) - 2} more)"

                            # Show custom detections if available
                            detections = mal_file.get('detections', [])
                            if detections:
                                archive_text += f"\n   🔍 Custom: {', '.join(detections[:2])}"
                                if len(detections) > 2:
                                    archive_text += f" (+{len(detections) - 2} more)"

                    if malicious_count > 3:
                        archive_text += f"\n*... and {malicious_count - 3} more malicious files*"

            embed.add_field(
                name="📦 Archive Analysis",
                value=archive_text,
                inline=True
            )

        scan_info = f"⏱️ {self.scan_time:.2f}s"
        if self.cached:
            scan_info += " (cached)"
        embed.add_field(name="Scan Time", value=scan_info, inline=True)
        
        embed.set_footer(text="Security Audit System v3.0 - Enhanced Edition")
        return embed
    
    @staticmethod
    def _format_size(bytes_size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.1f}{unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.1f}TB"
    
    @staticmethod
    def _create_score_bar(score: float, width: int = 20) -> str:
        filled = int((score / 100) * width)
        empty = width - filled
        
        if score >= 80:
            char = '█'
        elif score >= 60:
            char = '▓'
        elif score >= 40:
            char = '▒'
        elif score >= 20:
            char = '░'
        else:
            char = '·'
        
        bar = char * filled + '·' * empty
        return f"[{bar}]"
    
    @staticmethod
    def _create_mini_bar(percentage: float, width: int = 10) -> str:
        filled = int((percentage / 100) * width)
        empty = width - filled
        return '█' * filled + '░' * empty


class EnhancedSecurityScanner:
    """Enhanced scanner with multiple APIs"""
    
    def __init__(self, vt_api_key: str, yara_rules_path: Optional[str] = None):
        self.vt_api_key = vt_api_key
        self.yara_rules = None

        # Load YARA rules
        if yara_rules_path and os.path.exists(yara_rules_path):
            try:
                self.yara_rules = yara.compile(filepath=yara_rules_path)
                logger.info(f"Loaded YARA rules from {yara_rules_path}")
            except Exception as e:
                logger.error(f"Could not load YARA rules: {e}")

        # Rate limiting
        self.vt_requests: List[float] = []
        self.vt_rate_limit = VT_RATE_LIMIT

        # Statistics
        self.stats = {
            'total_scans': 0,
            'avg_threat_score': 0.0,
            'threat_distribution': defaultdict(int)
        }

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
        self.signature_severities = {}  # Track severity for scoring

        custom_sig_file = os.getenv('CUSTOM_SIGNATURES_FILE', 'custom_signatures.json')
        if os.path.exists(custom_sig_file):
            try:
                with open(custom_sig_file, 'r') as f:
                    custom_sigs = json.load(f)

                # Load binary patterns
                for name, sig_data in custom_sigs.get('binary_patterns', {}).items():
                    pattern = sig_data.get('pattern', '')
                    severity = sig_data.get('severity', 'medium')
                    # Convert hex string to bytes pattern (replace wildcards ?? with 00 for simple matching)
                    try:
                        # Remove spaces and handle wildcards
                        clean_pattern = pattern.replace(' ', '').replace('?', '0')
                        self.custom_binary_patterns[name] = bytes.fromhex(clean_pattern)
                        self.signature_severities[name] = severity
                    except ValueError as e:
                        logger.error(f"Invalid hex pattern for {name}: {e}")

                # Load regex patterns
                for name, sig_data in custom_sigs.get('regex_patterns', {}).items():
                    pattern = sig_data.get('pattern', '')
                    severity = sig_data.get('severity', 'medium')
                    self.custom_regex_patterns[name] = pattern
                    self.signature_severities[name] = severity

                logger.info(f"Loaded {len(self.custom_binary_patterns)} binary + {len(self.custom_regex_patterns)} regex custom signatures")
            except Exception as e:
                logger.error(f"Could not load custom signatures: {e}")

        # URL-specific patterns for phishing and malicious sites
        self.url_signatures = {
            # ============================================================
            # CATEGORY 1: BRAND IMPERSONATION & TYPOSQUATTING
            # ============================================================
            'typosquatting_tech': r'(?i)(g00gle|micros0ft|yah00|faceb00k|appl3|amaz0n|netfl1x|paypa1|tw1tter|1nstagram|l1nkedin|redd1t|discоrd|telegrаm|slаck|dropb0x|spo+tify|youtub3|twi+ch)',

            'typosquatting_crypto': r'(?i)(bin[a4]nce|co[i1]nbase|kr[a4]ken|metam[a4]sk|un[i1]swap|pancak[e3]swap|openS[e3]a|crypt0\.com|blockch[a4]in|b[i1]tfinex)',

            'typosquatting_gaming': r'(?i)(st[e3]am-?community|ep[i1]c-?games|r[i1]ot-?games|r0blox|min[e3]craft|fort+nite|val0rant|le[a4]gue.*legends)',

            'brand_dash_abuse': r'(?i)(paypal|amazon|microsoft|apple|google|facebook|instagram|twitter|discord|netflix|spotify|steam|coinbase|binance|metamask)[-_](verify|secure|support|login|update|account|wallet|recovery|unlock|suspend|alert|warning|help|team)',

            'brand_keyword_combo': r'(?i)(official|secure|verified|support|help|recovery|unlock|restore)[-_]?(paypal|amazon|microsoft|apple|google|facebook|instagram|twitter|discord|netflix|spotify|steam|coinbase|binance|metamask)',

            'subdomain_brand_abuse': r'(?i)^https?://(paypal|amazon|microsoft|apple|google|facebook|instagram|twitter|discord|netflix|spotify|steam|coinbase|binance|metamask)[.-]',

            'lookalike_domains': r'(?i)(g[o0]{2}gle|micr[o0]s[o0]ft|fac[e3]b[o0]{2}k|[a4]pple|tw[i1]tter|[i1]nst[a4]gr[a4]m|p[a4]yp[a4]l|netfl[i1]x|yout[u]be|am[a4]z[o0]n|[a4]dob[e3]|oracl[e3]|nvidi[a4]|int[e3]l)',

            # ============================================================
            # CATEGORY 2: CRYPTO & WEB3 SCAMS
            # ============================================================
            'crypto_giveaway': r'(?i)(free|claim|airdrop|giveaway)[-_\s]*(btc|eth|usdt|bnb|ada|xrp|doge|shib|crypto|token|coin|nft)',

            'crypto_doubler': r'(?i)(double|multiply|10x|100x|1000x)[-_\s]*(your|btc|eth|crypto|investment|profits?)',

            'nft_scam': r'(?i)(free[-_\s]*(mint|nft|whitelist)|claim[-_\s]*nft|nft[-_\s]*(giveaway|airdrop|presale)|mint[-_\s]*(now|free|live))',

            'crypto_recovery': r'(?i)(recover|restore|unlock|reset)[-_\s]*(wallet|seed|phrase|private[-_\s]*key|metamask|trust[-_\s]*wallet|ledger)',

            'fake_dex': r'(?i)(pancake|uniswap|sushiswap|1inch|quickswap|trader[-_\s]*joe|curve|balancer)[-_\s]*(swap|finance|dex|exchange|claim|connect)',

            'web3_phishing': r'(?i)(connect[-_\s]*wallet|verify[-_\s]*wallet|wallet[-_\s]*(validation|verification|migration|upgrade)|dapp[-_\s]*connect|web3[-_\s]*auth)',

            'crypto_support_scam': r'(?i)(binance|coinbase|kraken|crypto\.com|metamask|ledger|trezor)[-_\s]*(support|help|recovery|unlock|suspended|security|verify)',

            # ============================================================
            # CATEGORY 3: SOCIAL ENGINEERING & URGENCY
            # ============================================================
            'urgency_keywords': r'(?i)(urgent|immediately|asap|now|quick|fast|expire[ds]?|deadline|limited[-_\s]*time|act[-_\s]*now|hurry|last[-_\s]*chance|final[-_\s]*(warning|notice)|today[-_\s]*only)',

            'security_alert': r'(?i)(alert|warning|notice|notification)[-_\s]*(security|suspicious|unusual|unauthorized|breach|compromised|hacked|locked)',

            'account_threat': r'(?i)(account|profile)[-_\s]*(suspend|lock|freeze|disable|close|terminate|ban|restricted|limited|deactivate|cancel)',

            'action_required': r'(?i)(action[-_\s]*required|confirm|verify|validate|update|review|complete|finish)[-_\s]*(your|account|profile|identity|information|details|payment|billing)',

            'prize_scam': r'(?i)(congratulations|winner|won|prize|reward|gift|claim|selected|eligible|lucky)[-_\s]*(you|your|free|iphone|ipad|macbook|ps5|xbox|samsung|crypto|bitcoin)',

            'fake_support': r'(?i)(customer|technical|account)[-_\s]*(support|service|help|assistance)[-_\s]*(team|center|desk|portal)',

            'impersonation_keywords': r'(?i)(official|verified|authentic|legitimate|authorized|certified)[-_\s]*(site|website|page|portal|login|account)',

            # ============================================================
            # CATEGORY 4: CREDENTIAL HARVESTING
            # ============================================================
            'login_page_suspicious': r'(?i)(login|signin|sign[-_\s]*in|log[-_\s]*in|signon)[-_\s]*.*\.(php|asp|aspx|jsp|cgi)',

            'auth_page_suspicious': r'(?i)(auth|authenticate|authentication|verify|verification|validate|validation).*\.(php|asp|aspx|jsp)',

            'password_reset_phish': r'(?i)(reset|change|recover|forgot)[-_\s]*(password|pass|pwd).*\.(php|asp|aspx|jsp)',

            'credential_input': r'(?i)(enter|submit|provide)[-_\s]*(username|password|credentials|login|email|account)',

            'billing_phish': r'(?i)(billing|payment|invoice|receipt)[-_\s]*(update|verify|confirm|method|details|information|problem|issue|failed)',

            'payment_method_phish': r'(?i)(credit[-_\s]*card|debit[-_\s]*card|payment[-_\s]*method|card[-_\s]*details|billing[-_\s]*info)[-_\s]*(update|expired|invalid|verify)',

            # ============================================================
            # CATEGORY 5: TECHNICAL EVASION
            # ============================================================
            'ip_address_url': r'https?://(?:\d{1,3}\.){3}\d{1,3}',

            'localhost_abuse': r'(?i)https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])',

            'data_uri': r'^data:',

            'javascript_uri': r'^javascript:',

            'obfuscated_url': r'(?:%[0-9a-fA-F]{2}){3,}',

            'punycode_idn': r'xn--',  # Internationalized domain names

            'base64_in_url': r'[A-Za-z0-9+/]{40,}={0,2}',

            'html_entities': r'&#\d{2,4};',

            'excessive_subdomains': r'^https?://([^/]+\.){4,}',

            'suspicious_params': r'(?i)[?&](redirect|return|url|next|continue|dest|destination|ref|link|goto|target|redir|forward|callback|returnurl|returnpath)=',

            'double_slash_redirect': r'https?://[^/]+//[^/]',  # Protocol smuggling

            'at_symbol_trick': r'https?://[^/]*@',  # User info abuse

            # ============================================================
            # CATEGORY 6: MALICIOUS INFRASTRUCTURE
            # ============================================================
            'suspicious_tld': r'\.(tk|ml|ga|cf|gq|pw|buzz|top|wang|work|xyz|club|loan|download|racing|review|science|party|accountant|date|faith|stream|trade|cricket|win|bid|kim|men|webcam)$',

            'free_hosting': r'(?i)\.(blogspot|wordpress|wixsite|weebly|squarespace|webnode|ucoz|000webhostapp|netlify\.app|vercel\.app|github\.io|gitlab\.io|herokuapp|repl\.it|glitch\.me|surge\.sh)/',

            'url_shortener': r'(?i)(bit\.ly|tinyurl|goo\.gl|ow\.ly|t\.co|is\.gd|cli\.gs|pic\.gd|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl|short\.to|ping\.fm|post\.ly|rebrand\.ly|bl\.ink|cutt\.ly|shorturl\.at|s\.id|clc\.am)/',

            'dyndns_abuse': r'(?i)\.(duckdns|no-ip|ddns|zapto|hopto|myftp|serveftp|sytes|dynu)\.',

            'suspicious_ports': r'https?://[^/]+(:[0-9]{2,5})(?!/)',  # Non-standard ports

            'ngrok_tunnel': r'\.ngrok\.io',

            'temp_email': r'(?i)(tempmail|guerrillamail|10minutemail|throwaway|disposable|temp-?mail|fake-?mail)\.',

            # ============================================================
            # CATEGORY 7: FILE & MALWARE DISTRIBUTION
            # ============================================================
            'double_extension': r'\.(pdf|doc|docx|xls|xlsx|jpg|png|zip|rar|txt)\.(exe|scr|bat|cmd|vbs|js|jar|app|dmg|pkg|msi|com|pif)$',

            'malware_hosting': r'(?i)\.(exe|scr|bat|cmd|vbs|jar|apk|ipa|dmg|pkg|deb|rpm|msi|com|pif)(\?|$)',

            'crack_warez': r'(?i)(crack|keygen|patch|serial|activation|loader|activator)[-_\s]*(download|free|full|version)',

            'fake_download': r'(?i)(download|install|get|setup)[-_\s]*(now|free|here|latest|full|version|setup).*\.(exe|dmg|pkg|msi|apk)',

            'torrent_malware': r'(?i)(torrent|magnet|utorrent|bittorrent).*\.(exe|scr|bat)',

            'dropper_pattern': r'(?i)(setup|install|installer|update|updater|runtime|player|codec).*\.(exe|msi|dmg|pkg)',

            # ============================================================
            # CATEGORY 8: PLATFORM-SPECIFIC SCAMS
            # ============================================================
            'discord_scam': r'(?i)(discord)[-_\s]*(nitro|free|gift|giveaway|steam|promotion|boost|server|hack|generator|claim)',

            'steam_scam': r'(?i)(steam)[-_\s]*(community|trade|gift|card|wallet|market|inventory|skins|csgo|dota|tf2|vote|screenshot)',

            'gaming_phish': r'(?i)(free[-_\s]*(robux|vbucks|v-bucks|minecoins|riot[-_\s]*points|apex[-_\s]*coins|cod[-_\s]*points)|generator|hack|cheat|mod[-_\s]*menu)',

            'social_media_hack': r'(?i)(instagram|facebook|twitter|tiktok|snapchat)[-_\s]*(followers|likes|views|verification|verified|badge|hack|generator|free)',

            'streaming_scam': r'(?i)(netflix|hulu|disney\+?|hbo|prime[-_\s]*video|spotify)[-_\s]*(free|account|premium|trial|generator|share|crack)',

            'office_phish': r'(?i)(office[-_\s]*365|onedrive|sharepoint|teams|outlook)[-_\s]*(verify|login|secure|access|document|share|suspended)',

            # ============================================================
            # CATEGORY 9: SPECIFIC SCAM PATTERNS
            # ============================================================
            'fake_update': r'(?i)(update|upgrade)[-_\s]*(required|available|needed|pending|critical|security|important|urgent|now).*\.(exe|dmg|pkg|msi|apk)',

            'fake_antivirus': r'(?i)(virus|malware|trojan|infected|threat|security|antivirus|protect)[-_\s]*(detected|found|alert|warning|scan|remove|clean|fix)',

            'tech_support_scam': r'(?i)(microsoft|windows|apple|mac)[-_\s]*(support|help|tech|technician|error|warning|alert|defender|security)',

            'refund_scam': r'(?i)(refund|reimburse|compensation|overpay|overcharge)[-_\s]*(owed|due|claim|process|form|pending)',

            'job_scam': r'(?i)(work[-_\s]*from[-_\s]*home|remote[-_\s]*job|easy[-_\s]*money|earn|hiring|employment)[-_\s]*(urgent|immediate|guaranteed|weekly|daily)',

            'survey_scam': r'(?i)(survey|questionnaire|feedback|review)[-_\s]*(reward|gift|prize|winner|selected|earn|paid)',

            'lottery_scam': r'(?i)(lottery|lotto|jackpot|sweepstakes)[-_\s]*(winner|won|claim|prize|selected|notification)',

            # ============================================================
            # CATEGORY 10: INTERNATIONAL & HOMOGRAPH ATTACKS
            # ============================================================
            'homograph_cyrillic': r'[а-яА-Я]|[\u0430-\u044f\u0410-\u042f]',  # Cyrillic

            'homograph_greek': r'[\u0370-\u03FF]',  # Greek characters

            'homograph_mixing': r'[a-zA-Z][а-яА-Я]|[а-яА-Я][a-zA-Z]',  # Mixed Latin/Cyrillic

            'rtl_override': r'[\u202E\u202D]',  # Right-to-Left override (hiding extensions)

            'zero_width_chars': r'[\u200B-\u200D\uFEFF]',  # Invisible characters

            # Only match when CYRILLIC confusables (О, о) are mixed with Latin text
            # Don't match normal 'o', '0', '1', 'l' which are in every URL
            'confusables': r'(?:[a-z]+[О0о]+[a-z]+)|(?:[a-z]+[Оо][a-z]*\.com)',  # Cyrillic O in Latin words
        }
    
    def calculate_hash(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data (0.0 to 8.0)"""
        if not data:
            return 0.0

        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)

        return entropy

    def calculate_multiple_hashes(self, data: bytes) -> Dict[str, str]:
        """Calculate MD5, SHA-1, and SHA-256 hashes"""
        return {
            'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest()
        }

    def is_archive_file(self, filename: str) -> bool:
        """Check if file is an archive based on extension"""
        archive_extensions = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.tar.gz', '.tar.bz2', '.tar.xz'}
        return any(filename.lower().endswith(ext) for ext in archive_extensions)

    async def extract_and_scan_archive(self, data: bytes, filename: str) -> Tuple[List[str], List[Dict]]:
        """Extract archive contents and scan each file with early-exit optimization"""
        archive_files = []
        scan_results = []
        max_files_to_scan = 5  # Only scan first 5 files for speed
        malicious_found = False

        try:
            # Try ZIP extraction
            if filename.lower().endswith('.zip'):
                with BytesIO(data) as bio:
                    try:
                        with zipfile.ZipFile(bio, 'r') as zf:
                            # Check for password-protected/encrypted files
                            encrypted_files = [f for f in zf.filelist if f.flag_bits & 0x1]  # Bit 0 = encrypted
                            has_encrypted = len(encrypted_files) > 0

                            if has_encrypted:
                                logger.warning(f"🔒 Password-protected archive detected: {len(encrypted_files)}/{len(zf.filelist)} files encrypted")
                                archive_files.append(f"🔒 {len(encrypted_files)} encrypted file(s) - PASSWORD PROTECTED")

                            # ZIPBOMB DETECTION: Check compression ratio (works even on encrypted files!)
                            total_compressed_size = len(data)
                            total_uncompressed_size = sum(file.file_size for file in zf.filelist if not file.is_dir())

                            if total_compressed_size > 0:
                                compression_ratio = total_uncompressed_size / total_compressed_size
                                logger.info(f"Archive compression ratio: {compression_ratio:.1f}:1 ({EnhancedScanResult._format_size(total_uncompressed_size)} uncompressed / {EnhancedScanResult._format_size(total_compressed_size)} compressed)")

                                # Zipbomb detection thresholds
                                if compression_ratio > 1000:
                                    # Extreme zipbomb (>1000:1)
                                    logger.warning(f"🎈 ZIPBOMB DETECTED! Compression ratio: {compression_ratio:.1f}:1 (Encrypted: {has_encrypted})")
                                    archive_files.append(f"⚠️ ZIPBOMB DETECTED ({compression_ratio:.0f}:1 compression)")
                                    scan_results.append({
                                        'filename': filename,
                                        'malicious': True,
                                        'threat_score': 100.0,
                                        'threat_level': 'CRITICAL',
                                        'zipbomb': True,
                                        'compression_ratio': compression_ratio,
                                        'encrypted': has_encrypted
                                    })
                                    return archive_files, scan_results
                                elif compression_ratio > 100:
                                    # Suspicious compression (100-1000:1)
                                    logger.warning(f"⚠️ Suspicious compression ratio: {compression_ratio:.1f}:1 (possible zipbomb)")
                                    archive_files.append(f"⚠️ High compression ({compression_ratio:.0f}:1 ratio)")

                            # Flag password-protected archives as suspicious even if compression is normal
                            if has_encrypted and compression_ratio > 10:
                                logger.warning(f"⚠️ Suspicious: Password-protected archive with {compression_ratio:.0f}:1 compression")
                                scan_results.append({
                                    'filename': filename,
                                    'malicious': True,
                                    'threat_score': 70.0,
                                    'threat_level': 'HIGH',
                                    'encrypted': True,
                                    'reason': 'Password-protected archive with high compression'
                                })

                            files_scanned = 0

                            for file_info in zf.filelist:
                                archive_files.append(file_info.filename)

                                # Skip directories
                                if file_info.is_dir():
                                    continue

                                # Skip encrypted files (can't extract without password)
                                if file_info.flag_bits & 0x1:
                                    logger.info(f"⏭️ Skipping encrypted file: {file_info.filename}")
                                    continue

                                # EARLY EXIT: Stop scanning after finding malware or hitting limit
                                if malicious_found:
                                    logger.info(f"⚡ Early exit: Malware already found, skipping remaining {len(zf.filelist) - files_scanned} files")
                                    break

                                if files_scanned >= max_files_to_scan:
                                    logger.info(f"⚡ Early exit: Scanned {max_files_to_scan} files, skipping remaining {len(zf.filelist) - files_scanned} files")
                                    break

                                # Extract and scan (with size limit for safety)
                                if file_info.file_size > MAX_FILE_SIZE:
                                    logger.warning(f"Skipping large file in archive: {file_info.filename} ({file_info.file_size} bytes)")
                                    continue

                                try:
                                    extracted_data = zf.read(file_info.filename)
                                    logger.info(f"Scanning extracted file {files_scanned + 1}/{max_files_to_scan}: {file_info.filename}")

                                    # FAST SCAN: Skip VirusTotal for archive contents (too slow)
                                    result = await self.scan_file_fast(extracted_data, file_info.filename)

                                    scan_results.append({
                                        'filename': file_info.filename,
                                        'malicious': result.is_malicious,
                                        'threat_score': result.threat_score.total_score,
                                        'threat_level': result.threat_score.threat_level,
                                        'yara_matches': result.yara_matches,
                                        'detections': result.detections,
                                        'malware_categories': result.malware_categories
                                    })

                                    files_scanned += 1

                                    # EARLY EXIT: Stop if malware found
                                    if result.is_malicious:
                                        malicious_found = True
                                        logger.warning(f"🚨 Malware found in archive: {file_info.filename} (score: {result.threat_score.total_score}/100)")

                                except Exception as e:
                                    logger.error(f"Error scanning {file_info.filename}: {e}")

                    except zipfile.BadZipFile:
                        logger.warning("Invalid or encrypted ZIP file")

            # Try TAR extraction
            elif filename.lower().endswith(('.tar', '.tar.gz', '.tar.bz2', '.tar.xz', '.tgz')):
                with BytesIO(data) as bio:
                    try:
                        with tarfile.open(fileobj=bio, mode='r:*') as tf:
                            files_scanned = 0

                            for member in tf.getmembers():
                                archive_files.append(member.name)

                                # Skip directories
                                if member.isdir():
                                    continue

                                # EARLY EXIT: Stop scanning after finding malware or hitting limit
                                if malicious_found:
                                    logger.info(f"⚡ Early exit: Malware already found, skipping remaining files")
                                    break

                                if files_scanned >= max_files_to_scan:
                                    logger.info(f"⚡ Early exit: Scanned {max_files_to_scan} files, skipping remaining files")
                                    break

                                # Extract and scan (with size limit)
                                if member.size > MAX_FILE_SIZE:
                                    logger.warning(f"Skipping large file in archive: {member.name} ({member.size} bytes)")
                                    continue

                                try:
                                    extracted_file = tf.extractfile(member)
                                    if extracted_file:
                                        extracted_data = extracted_file.read()
                                        logger.info(f"Scanning extracted file {files_scanned + 1}/{max_files_to_scan}: {member.name}")

                                        # FAST SCAN: Skip VirusTotal for archive contents (too slow)
                                        result = await self.scan_file_fast(extracted_data, member.name)

                                        scan_results.append({
                                            'filename': member.name,
                                            'malicious': result.is_malicious,
                                            'threat_score': result.threat_score.total_score,
                                            'threat_level': result.threat_score.threat_level
                                        })

                                        files_scanned += 1

                                        # EARLY EXIT: Stop if malware found
                                        if result.is_malicious:
                                            malicious_found = True
                                            logger.warning(f"🚨 Malware found in archive: {member.name} (score: {result.threat_score.total_score}/100)")

                                except Exception as e:
                                    logger.error(f"Error scanning {member.name}: {e}")

                    except tarfile.TarError:
                        logger.warning("Invalid or encrypted TAR file")

        except Exception as e:
            logger.error(f"Archive extraction error: {e}")

        return archive_files, scan_results

    async def scan_file_fast(self, data: bytes, filename: str) -> EnhancedScanResult:
        """Fast scan without VirusTotal/Hybrid Analysis (for archive contents)"""
        start_time = time.time()

        # Calculate hash
        file_hash = self.calculate_hash(data)

        # Run FAST scans only (no API calls)
        yara_task = self._scan_with_yara(data)
        sig_task = asyncio.to_thread(self._scan_with_signatures, data)

        yara_matches = await yara_task
        sig_detections = await sig_task

        # Calculate threat score (without VT/Hybrid)
        threat_score = self._calculate_threat_score(
            yara_matches, sig_detections, 0, 0,  # No VT results
            data, filename, file_hash, 0.0  # No Hybrid results
        )

        scan_time = time.time() - start_time

        logger.info(f"⚡ Fast scan complete: {filename} - {threat_score.total_score:.1f}/100 ({scan_time:.2f}s)")

        # Categorize malware type
        malware_categories = categorize_malware_type(
            yara_matches=yara_matches,
            detections=sig_detections,
            archive_scan_results=[],
            hybrid_verdict=""
        )

        return EnhancedScanResult(
            file_hash=file_hash,
            file_name=filename,
            file_size=len(data),
            threat_score=threat_score,
            detections=sig_detections,
            yara_matches=yara_matches,
            vt_positives=0,
            vt_total=0,
            hybrid_verdict="",
            scan_time=scan_time,
            entropy=0.0,
            md5_hash="",
            sha1_hash="",
            is_archive=False,
            malware_categories=malware_categories,
            archive_files=[],
            archive_scan_results=[]
        )

    async def scan_file(self, data: bytes, filename: str) -> EnhancedScanResult:
        """Complete file scan with all APIs + enhanced analysis"""
        start_time = time.time()

        # Calculate multiple hashes
        hashes = self.calculate_multiple_hashes(data)
        file_hash = hashes['sha256']
        md5_hash = hashes['md5']
        sha1_hash = hashes['sha1']

        # Calculate entropy
        entropy = self.calculate_entropy(data)
        logger.info(f"File entropy: {entropy:.2f}/8.0")

        # Detect file type using magic bytes
        detected_file_type, file_type_description = detect_file_type_magic_bytes(data)
        logger.info(f"Magic bytes detection: {file_type_description}")

        # Run file command for additional detection
        file_command_output = ""
        try:
            import tempfile
            import subprocess
            with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{filename}") as tmp_file:
                tmp_file.write(data)
                tmp_file_path = tmp_file.name

            # Run file command
            result = subprocess.run(['file', '-b', tmp_file_path],
                                  capture_output=True,
                                  text=True,
                                  timeout=5)
            file_command_output = result.stdout.strip()
            logger.info(f"file command: {file_command_output}")

            # Clean up
            os.unlink(tmp_file_path)
        except Exception as e:
            logger.warning(f"file command failed: {e}")
            file_command_output = "Not available"

        # Check if archive and extract if needed
        is_archive = self.is_archive_file(filename)
        archive_files = []
        archive_scan_results = []

        if is_archive:
            logger.info(f"Detected archive file: {filename}")
            archive_files, archive_scan_results = await self.extract_and_scan_archive(data, filename)
            logger.info(f"Archive contains {len(archive_files)} files, scanned {len(archive_scan_results)} files")

        self.stats['total_scans'] += 1

        # Run all scans in parallel
        yara_task = self._scan_with_yara(data)
        sig_task = asyncio.to_thread(self._scan_with_signatures, data)
        vt_task = self._scan_with_virustotal(file_hash, data, filename)
        hybrid_task = self._scan_with_hybrid_analysis(file_hash, data, filename)

        yara_matches = await yara_task
        sig_detections = await sig_task
        vt_positives, vt_total = await vt_task
        hybrid_score, hybrid_verdict = await hybrid_task

        # Calculate threat score
        threat_score = self._calculate_threat_score(
            yara_matches, sig_detections, vt_positives, vt_total,
            data, filename, file_hash, hybrid_score
        )

        # If archive contains malicious files, increase threat score
        if archive_scan_results:
            malicious_count = sum(1 for r in archive_scan_results if r.get('malicious', False))
            if malicious_count > 0:
                logger.warning(f"Archive contains {malicious_count} malicious file(s)!")
                # Boost threat score based on malicious content
                threat_score.heuristic_score = min(100, threat_score.heuristic_score + (malicious_count * 20))
                # Recalculate total
                threat_score._recalculate_total()

        # Update statistics
        self.stats['avg_threat_score'] = (
            (self.stats['avg_threat_score'] * (self.stats['total_scans'] - 1) +
             threat_score.total_score) / self.stats['total_scans']
        )
        self.stats['threat_distribution'][threat_score.threat_level] += 1

        scan_time = time.time() - start_time

        # Categorize malware type
        malware_categories = categorize_malware_type(
            yara_matches=yara_matches,
            detections=sig_detections,
            archive_scan_results=archive_scan_results,
            hybrid_verdict=hybrid_verdict
        )
        logger.info(f"Malware categories: {malware_categories}")

        return EnhancedScanResult(
            file_hash=file_hash,
            file_name=filename,
            file_size=len(data),
            threat_score=threat_score,
            detections=sig_detections,
            yara_matches=yara_matches,
            vt_positives=vt_positives,
            vt_total=vt_total,
            hybrid_verdict=hybrid_verdict,
            scan_time=scan_time,
            entropy=entropy,
            md5_hash=md5_hash,
            sha1_hash=sha1_hash,
            is_archive=is_archive,
            archive_files=archive_files,
            archive_scan_results=archive_scan_results,
            detected_file_type=detected_file_type,
            file_type_description=file_type_description,
            file_command_output=file_command_output,
            malware_categories=malware_categories
        )
    
    async def _scan_with_yara(self, data: bytes) -> List[str]:
        """Scan with YARA"""
        if not self.yara_rules:
            return []
        try:
            matches = await asyncio.to_thread(self.yara_rules.match, data=data)
            return [match.rule for match in matches]
        except Exception as e:
            logger.error(f"YARA scan error: {e}")
            return []

    def _is_text_file(self, data: bytes, sample_size: int = 8192) -> bool:
        """
        Determine if file is text or binary using multiple methods

        Returns:
            True if file is likely text, False if binary
        """
        if not data:
            return True

        # Sample only first N bytes for performance
        sample = data[:sample_size]

        # Method 1: Check for binary file signatures (magic bytes)
        binary_signatures = [
            b'\x89PNG',              # PNG
            b'GIF8',                 # GIF
            b'\xff\xd8\xff',         # JPEG
            b'%PDF',                 # PDF
            b'PK\x03\x04',           # ZIP
            b'PK\x05\x06',           # ZIP (empty)
            b'PK\x07\x08',           # ZIP (spanned)
            b'Rar!',                 # RAR
            b'7z\xbc\xaf\x27\x1c',   # 7Z
            b'MZ',                   # EXE/DLL
            b'BM',                   # BMP
            b'RIFF',                 # WAV/AVI
            b'\x00\x00\x01\x00',     # ICO
            b'ID3',                  # MP3
            b'\x1f\x8b',             # GZIP
            b'OggS',                 # OGG
            b'ftyp',                 # MP4 (at offset 4)
            b'\x49\x49\x2a\x00',     # TIFF (little-endian)
            b'\x4d\x4d\x00\x2a',     # TIFF (big-endian)
            b'\xd0\xcf\x11\xe0',     # MS Office (old format)
            b'SQLite format 3',      # SQLite DB
        ]

        # Check if file starts with known binary signature
        for signature in binary_signatures:
            if sample.startswith(signature):
                logger.debug(f"Binary file detected: magic bytes {signature[:4].hex()}")
                return False

        # Method 2: Check for null bytes (common in binary files, rare in text)
        # Allow up to 0.5% null bytes for some text formats
        null_count = sample.count(b'\x00')
        if null_count > len(sample) * 0.005:
            logger.debug(f"Binary file detected: {null_count} null bytes in {len(sample)} bytes")
            return False

        # Method 3: Check for high percentage of non-printable characters
        # Try to decode as UTF-8 WITHOUT errors='ignore'
        try:
            decoded = sample.decode('utf-8')
            # Count printable characters
            printable_count = sum(1 for c in decoded if c.isprintable() or c in '\r\n\t ')
            printable_ratio = printable_count / len(decoded) if len(decoded) > 0 else 0

            # If >80% printable, it's likely text
            if printable_ratio > 0.80:
                logger.debug(f"Text file detected: {printable_ratio:.1%} printable characters")
                return True
            else:
                logger.debug(f"Binary file detected: only {printable_ratio:.1%} printable characters")
                return False

        except UnicodeDecodeError:
            # If it can't decode as UTF-8, try ASCII
            try:
                decoded = sample.decode('ascii', errors='strict')
                logger.debug(f"Text file detected: valid ASCII")
                return True
            except (UnicodeDecodeError, AttributeError):
                # Can't decode as text
                logger.debug(f"Binary file detected: cannot decode as UTF-8 or ASCII")
                return False

        # Default: treat as binary for safety
        return False

    def _scan_with_signatures(self, data: bytes) -> List[str]:
        """Scan with built-in and custom signatures"""
        detections = []

        # Check if data is binary or text file
        is_text = self._is_text_file(data)

        # Decode to text if it's a text file
        if is_text:
            try:
                text_data = data.decode('utf-8', errors='ignore')
            except:
                text_data = ""
                is_text = False
        else:
            text_data = ""

        # Scan with built-in signatures (regex-based) - ONLY on text data
        if is_text:
            for sig_name, pattern in self.signatures.items():
                if re.search(pattern, text_data, re.IGNORECASE):
                    detections.append(sig_name)
                    logger.info(f"Built-in signature match: {sig_name}")
        else:
            logger.debug("Skipping built-in regex signatures (binary data)")

        # Scan with custom binary patterns (ALWAYS scan these)
        for sig_name, pattern in self.custom_binary_patterns.items():
            try:
                # Simple byte sequence search (wildcards replaced with 00)
                if pattern in data:
                    detections.append(f"custom_{sig_name}")
                    severity = self.signature_severities.get(sig_name, 'medium')
                    logger.warning(f"Custom binary signature match: {sig_name} (severity: {severity})")
            except Exception as e:
                logger.error(f"Error scanning binary pattern {sig_name}: {e}")

        # Scan with custom regex patterns - ONLY on text data
        if is_text:
            for sig_name, pattern in self.custom_regex_patterns.items():
                try:
                    # Scan against decoded text, not binary data
                    if re.search(pattern, text_data, re.IGNORECASE):
                        detections.append(f"custom_{sig_name}")
                        severity = self.signature_severities.get(sig_name, 'medium')
                        logger.warning(f"Custom regex signature match: {sig_name} (severity: {severity})")
                except Exception as e:
                    logger.error(f"Error scanning regex pattern {sig_name}: {e}")
        else:
            logger.debug("Skipping custom regex signatures (binary data)")

        return detections

    def _scan_url_with_signatures(self, url: str) -> Tuple[List[str], float, Dict[str, int]]:
        """
        Scan URL with local signature patterns
        Returns: (detections, threat_score, detailed_scores)
        """
        detections = []
        threat_score = 0.0
        detailed_scores = {}  # Store each pattern's score

        # Severity weights for different URL patterns (0-100 scale)
        severity_weights = {
            # CRITICAL THREATS (90-100) - Immediate danger
            'javascript_uri': 98,           # Code execution
            'rtl_override': 95,             # Extension hiding
            'data_uri': 93,                 # XSS/phishing embedded
            'double_extension': 92,         # Malware disguise
            'malware_hosting': 90,          # Direct malware download

            # HIGH THREATS (75-89) - Very dangerous
            'fake_antivirus': 88,           # Ransomware/scareware
            'crypto_recovery': 87,          # Wallet theft
            'web3_phishing': 86,            # Wallet draining
            'login_page_suspicious': 85,    # Credential phishing
            'auth_page_suspicious': 85,     # Authentication phishing
            'typosquatting_crypto': 84,     # Crypto exchange phishing
            'brand_dash_abuse': 83,         # Brand impersonation
            'subdomain_brand_abuse': 83,    # Subdomain trick
            'credential_input': 82,         # Direct credential theft
            'fake_dex': 82,                 # DeFi phishing
            'homograph_cyrillic': 81,       # Homograph attack
            'homograph_greek': 81,          # Homograph attack
            'homograph_mixing': 81,         # Homograph attack
            'typosquatting_tech': 80,       # Tech brand impersonation
            'lookalike_domains': 80,        # Confusable characters
            'password_reset_phish': 79,     # Password theft
            'payment_method_phish': 78,     # Payment info theft
            'billing_phish': 77,            # Billing scam
            'crypto_support_scam': 77,      # Fake crypto support
            'typosquatting_gaming': 76,     # Gaming platform phishing
            'discord_scam': 75,             # Discord-specific scams

            # MEDIUM-HIGH THREATS (60-74) - Dangerous
            'crypto_giveaway': 74,          # Crypto scam
            'nft_scam': 73,                 # NFT scam
            'crypto_doubler': 72,           # Ponzi scheme
            'fake_update': 71,              # Malware dropper
            'tech_support_scam': 70,        # Tech support scam
            'steam_scam': 69,               # Steam account theft
            'brand_keyword_combo': 68,      # Brand + action keywords
            'office_phish': 67,             # Office 365 phishing
            'at_symbol_trick': 66,          # URL obfuscation
            'ip_address_url': 65,           # IP instead of domain
            'localhost_abuse': 64,          # Localhost exploitation
            'punycode_idn': 63,             # IDN domain
            'fake_download': 62,            # Malware download
            'dropper_pattern': 61,          # Malware installer
            'crack_warez': 60,              # Cracked software

            # MEDIUM THREATS (45-59) - Suspicious
            'security_alert': 59,           # Fake security alerts
            'account_threat': 58,           # Account suspension scam
            'urgency_keywords': 57,         # Social engineering
            'action_required': 56,          # Urgency tactics
            'obfuscated_url': 55,           # URL encoding abuse
            'gaming_phish': 54,             # Gaming scams
            'social_media_hack': 53,        # Social media scams
            'streaming_scam': 52,           # Streaming service scams
            'prize_scam': 51,               # Prize/reward scams
            'lottery_scam': 50,             # Lottery scams
            'suspicious_params': 49,        # Open redirect
            'double_slash_redirect': 48,    # Protocol smuggling
            'ngrok_tunnel': 47,             # Temporary tunnel
            'fake_support': 46,             # Fake support sites
            'impersonation_keywords': 45,   # Impersonation claims

            # LOW-MEDIUM THREATS (30-44) - Noteworthy
            'torrent_malware': 44,          # Torrent risks
            'refund_scam': 43,              # Refund scams
            'job_scam': 42,                 # Work from home scams
            'survey_scam': 41,              # Survey scams
            'suspicious_tld': 40,           # Free TLDs
            'excessive_subdomains': 39,     # Many subdomains
            'base64_in_url': 38,            # Base64 encoding
            'html_entities': 37,            # HTML encoding
            'zero_width_chars': 36,         # Invisible characters
            'confusables': 35,              # Visual similarity
            'free_hosting': 34,             # Free hosting services
            'dyndns_abuse': 33,             # Dynamic DNS
            'suspicious_ports': 32,         # Non-standard ports
            'temp_email': 31,               # Temporary email
            'url_shortener': 30,            # URL shorteners
        }

        for sig_name, pattern in self.url_signatures.items():
            try:
                if re.search(pattern, url, re.IGNORECASE):
                    score = severity_weights.get(sig_name, 50)
                    detections.append(sig_name)
                    detailed_scores[sig_name] = score
                    threat_score = max(threat_score, score)  # Use highest score
                    logger.info(f"URL pattern match: {sig_name} ({score} pts) in {url[:50]}...")
            except re.error as e:
                logger.error(f"Regex error for {sig_name}: {e}")
                continue

        return detections, threat_score, detailed_scores

    async def _scan_with_virustotal(self, file_hash: str, data: bytes, filename: str) -> Tuple[int, int]:
        """Scan with VirusTotal"""
        await self._wait_for_rate_limit()
        
        headers = {'x-apikey': self.vt_api_key}
        async with aiohttp.ClientSession() as session:
            url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
            try:
                async with session.get(url, headers=headers) as response:
                    self.vt_requests.append(time.time())
                    if response.status == 200:
                        data_json = await response.json()
                        stats = data_json['data']['attributes']['last_analysis_stats']
                        positives = stats['malicious'] + stats['suspicious']
                        total = sum(stats.values())
                        return positives, total
                    elif response.status == 404:
                        return 0, 0
            except Exception as e:
                logger.error(f"VirusTotal error: {e}")
                return 0, 0
    
    async def _scan_with_hybrid_analysis(self, file_hash: str, data: bytes, filename: str) -> Tuple[float, str]:
        """Scan with Hybrid Analysis API"""
        if not HYBRID_ANALYSIS_API_KEY:
            return 0.0, ""

        headers = {
            'api-key': HYBRID_ANALYSIS_API_KEY,
            'User-Agent': 'Falcon Sandbox',
            'accept': 'application/json'
        }

        async with aiohttp.ClientSession() as session:
            # Check if file already analyzed
            url = 'https://www.hybrid-analysis.com/api/v2/search/hash'

            try:
                # Hybrid Analysis API uses GET with query params
                async with session.get(url, headers=headers, params={'hash': file_hash}) as response:
                    response_text = await response.text()

                    if response.status == 200:
                        try:
                            result = await response.json()

                            # API returns: {"sha256s": [...], "reports": [...]}
                            reports = result.get('reports', [])

                            if reports and len(reports) > 0:
                                # Get verdict from first report
                                first_report = reports[0]

                                # Handle None values (analysis pending/in progress)
                                verdict = first_report.get('verdict') or 'no-verdict'
                                threat_score = first_report.get('threat_score') or 0
                                state = first_report.get('state', 'unknown')

                                # Skip if analysis is not complete
                                if state not in ['SUCCESS', 'ERROR']:
                                    logger.info(f"Hybrid Analysis: Analysis in progress (state: {state}) for hash {file_hash[:16]}...")
                                    return 0.0, ""

                                # Convert verdict to score
                                score_map = {
                                    'malicious': 100.0,
                                    'suspicious': 70.0,
                                    'no specific threat': 20.0,
                                    'no-verdict': 10.0,
                                    'whitelisted': 0.0
                                }

                                # Ensure verdict is a string before calling .lower()
                                verdict_str = str(verdict).lower() if verdict else 'no-verdict'
                                score = score_map.get(verdict_str, threat_score if threat_score else 0)

                                logger.info(f"Hybrid Analysis: {verdict} (score: {score}) - {len(reports)} report(s)")
                                return score, str(verdict) if verdict else "no-verdict"
                            else:
                                logger.info(f"Hybrid Analysis: No reports for hash {file_hash[:16]}...")
                                return 0.0, ""
                        except Exception as e:
                            logger.error(f"Hybrid Analysis JSON parse error: {e} - Response: {response_text[:200]}")
                            return 0.0, ""
                    elif response.status == 403:
                        logger.error(f"Hybrid Analysis: API key invalid or quota exceeded (403)")
                        return 0.0, ""
                    elif response.status == 404:
                        logger.info(f"Hybrid Analysis: Hash not found {file_hash[:16]}...")
                        return 0.0, ""
                    elif response.status == 400:
                        logger.error(f"Hybrid Analysis: Bad request (400) - {response_text[:300]}")
                        return 0.0, ""
                    else:
                        logger.error(f"Hybrid Analysis: HTTP {response.status} - {response_text[:200]}")
                        return 0.0, ""
            except Exception as e:
                logger.error(f"Hybrid Analysis error: {e}", exc_info=True)
                return 0.0, ""

        return 0.0, ""
    
    async def _wait_for_rate_limit(self):
        """Wait for rate limit"""
        now = time.time()
        self.vt_requests = [t for t in self.vt_requests if now - t < 60]
        if len(self.vt_requests) >= self.vt_rate_limit:
            wait_time = 60 - (now - self.vt_requests[0])
            if wait_time > 0:
                await asyncio.sleep(wait_time)
                self.vt_requests.pop(0)
    
    def _calculate_threat_score(self, yara_matches, sig_detections, vt_positives, vt_total,
                               data, filename, file_hash, hybrid_score) -> ThreatScore:
        """Calculate comprehensive threat score"""
        threat_score = ThreatScore()

        # Low-severity YARA rules (informational/capabilities - not malicious indicators)
        LOW_SEVERITY_RULES = {
            'Big_Numbers1', 'Big_Numbers2', 'Big_Numbers3', 'Big_Numbers',
            'invalid_trailer_structure', 'multiple_versions', 'CRC32_poly_Constant',
            'BASE64_table', 'network_http', 'network_tcp', 'network_dns',
            'win_files_operation', 'Str_Win32_Wininet_Library',
            'Str_Win32_Internet_API', 'Str_Win32_Http_API',
            'SEH_Save', 'SEH_Init', 'anti_dbg', 'maldoc_getEIP_method_1',
            'IsPE32', 'HasOverlay', 'HasDigitalSignature',
            # File format detections (not necessarily malicious)
            'Contains_VBA_macro_code', 'Contains_UserForm_Object',
            'Contains_VBE_File', 'Contains_DDE_Protocol',
            # Common capabilities (informational only)
            'inject_thread', 'create_process', 'win_registry', 'win_mutex',
            'antivirusdetector', 'check_sandbox', 'VM_detect'
        }

        # YARA score - SEVERITY-BASED
        if yara_matches:
            high_severity_matches = [m for m in yara_matches if m not in LOW_SEVERITY_RULES]
            low_severity_matches = [m for m in yara_matches if m in LOW_SEVERITY_RULES]

            # High severity rules: 70 points each (very suspicious)
            # Low severity rules: 5 points each (just informational)
            high_score = min(len(high_severity_matches) * 70, 100)
            low_score = min(len(low_severity_matches) * 5, 30)  # Cap at 30

            threat_score.yara_score = min(high_score + low_score, 100)

            if high_severity_matches:
                logger.warning(f"YARA HIGH-SEVERITY: {high_severity_matches} - score {high_score:.1f}")
            if low_severity_matches:
                logger.info(f"YARA LOW-SEVERITY: {low_severity_matches} - score {low_score:.1f}")
        
        # Signature score - WEIGHTED BY SEVERITY
        if sig_detections:
            # Built-in signature weights
            sig_weights = {
                'ransomware': 95,
                'keylogger': 90,
                'cryptominer': 85,
                'powershell_encoded': 75,
                'base64_executable': 80,
                'suspicious_vbs': 70,
                'obfuscated': 65,
                'discord_webhook': 55
            }

            # Severity-based scores for custom signatures
            severity_scores = {
                'critical': 95,
                'high': 80,
                'medium': 60,
                'low': 40
            }

            # Use MAXIMUM signature score (worst one)
            max_score = 0
            for sig in sig_detections:
                if sig.startswith('custom_'):
                    # Custom signature - get severity from loaded data
                    sig_name = sig.replace('custom_', '')
                    severity = self.signature_severities.get(sig_name, 'medium')
                    score = severity_scores.get(severity, 60)
                else:
                    # Built-in signature
                    score = sig_weights.get(sig, 50)

                max_score = max(max_score, score)

            threat_score.signature_score = max_score
            logger.warning(f"Signature detections: {sig_detections} - max score {max_score:.1f}")
        
        # VirusTotal score - MORE AGGRESSIVE
        if vt_total > 0:
            percentage = (vt_positives / vt_total) * 100
            
            # ANY detection should significantly raise score
            if vt_positives >= 10:
                # Many engines = definitely malicious
                threat_score.virustotal_score = 90 + min(percentage - 14, 10)
            elif vt_positives >= VT_THRESHOLD:
                # Over threshold = highly suspicious
                threat_score.virustotal_score = 75 + (vt_positives * 2)
            elif vt_positives > 0:
                # ANY detection = suspicious
                threat_score.virustotal_score = 35 + (vt_positives * 10)
            else:
                # Clean scan
                threat_score.virustotal_score = 0
            
            threat_score.virustotal_score = min(threat_score.virustotal_score, 100)
            
            logger.info(f"VirusTotal: {vt_positives}/{vt_total} detections = score {threat_score.virustotal_score:.1f}")
        
        # Heuristic score (file extension) - FIXED
        ext = os.path.splitext(filename)[1].lower()
        
        # Check blocked extensions properly
        if BLOCKED_EXTENSIONS and ext in BLOCKED_EXTENSIONS:
            threat_score.heuristic_score = 90.0
            logger.warning(f"BLOCKED EXTENSION DETECTED: {ext} in file {filename}")
        elif ext in ['.exe', '.dll', '.scr', '.com', '.pif']:
            threat_score.heuristic_score = 70.0
        elif ext in ['.bat', '.cmd', '.vbs', '.ps1', '.js']:
            threat_score.heuristic_score = 65.0
        elif ext in ['.msi', '.app', '.dmg', '.jar']:
            threat_score.heuristic_score = 55.0
        else:
            threat_score.heuristic_score = 15.0
        
        # Hybrid Analysis score
        threat_score.hybrid_analysis_score = hybrid_score
        
        # Reputation - more aggressive
        if vt_positives > 0 or len(yara_matches) > 0 or len(sig_detections) > 0:
            threat_score.reputation_score = 75.0  # Known threats
        else:
            threat_score.reputation_score = 45.0  # Unknown
        
        # Calculate total
        threat_score.calculate_total({
            'yara': 0.25,
            'signature': 0.20,
            'virustotal': 0.30,
            'heuristic': 0.10,
            'reputation': 0.05,
            'hybrid_analysis': 0.10
        })
        
        # CRITICAL OVERRIDES - Fix false negatives
        
        # Override 1: VT detections meet/exceed threshold
        if vt_positives >= VT_THRESHOLD:
            threat_score.total_score = max(threat_score.total_score, 70.0)
            if threat_score.threat_level not in ['high', 'critical']:
                threat_score.threat_level = "high"
                threat_score.confidence = 85.0
            logger.warning(f"VT THRESHOLD EXCEEDED: {vt_positives}/{vt_total} (threshold: {VT_THRESHOLD})")
        
        # Override 2: HIGH-SEVERITY YARA matches meet/exceed threshold
        # Only count high-severity matches, not informational/capability rules
        LOW_SEVERITY_RULES = {
            'Big_Numbers1', 'Big_Numbers2', 'Big_Numbers3', 'Big_Numbers',
            'invalid_trailer_structure', 'multiple_versions', 'CRC32_poly_Constant',
            'BASE64_table', 'network_http', 'network_tcp', 'network_dns',
            'win_files_operation', 'Str_Win32_Wininet_Library',
            'Str_Win32_Internet_API', 'Str_Win32_Http_API',
            'SEH_Save', 'SEH_Init', 'anti_dbg', 'maldoc_getEIP_method_1',
            'IsPE32', 'HasOverlay', 'HasDigitalSignature',
            # File format detections (not necessarily malicious)
            'Contains_VBA_macro_code', 'Contains_UserForm_Object',
            'Contains_VBE_File', 'Contains_DDE_Protocol',
            # Common capabilities (informational only)
            'inject_thread', 'create_process', 'win_registry', 'win_mutex',
            'antivirusdetector', 'check_sandbox', 'VM_detect'
        }
        high_severity_yara = [m for m in yara_matches if m not in LOW_SEVERITY_RULES]

        if len(high_severity_yara) >= YARA_THRESHOLD:
            threat_score.total_score = max(threat_score.total_score, 70.0)
            if threat_score.threat_level not in ['high', 'critical']:
                threat_score.threat_level = "high"
                threat_score.confidence = 85.0
            logger.warning(f"HIGH-SEVERITY YARA THRESHOLD EXCEEDED: {len(high_severity_yara)} matches (threshold: {YARA_THRESHOLD})")
        
        # Override 3: Blocked extension = always high threat
        if BLOCKED_EXTENSIONS and ext in BLOCKED_EXTENSIONS:
            threat_score.total_score = max(threat_score.total_score, 75.0)
            threat_score.threat_level = "high"
            threat_score.confidence = 90.0
            logger.error(f"BLOCKED EXTENSION: {ext} - File: {filename}")
        
        # Override 4: Hybrid Analysis says malicious
        if hybrid_score >= 80:
            threat_score.total_score = max(threat_score.total_score, 75.0)
            if threat_score.threat_level not in ['high', 'critical']:
                threat_score.threat_level = "high"
        
        # Override 5: ANY VT detection should raise minimum score
        if vt_positives > 0:
            threat_score.total_score = max(threat_score.total_score, 35.0)
            if threat_score.threat_level == 'safe':
                threat_score.threat_level = 'low'
        
        return threat_score
    
    async def scan_url(self, url: str) -> Dict:
        """Scan URL with local signatures, VirusTotal and Google Safe Browsing"""
        results = {
            'url': url,
            'is_malicious': False,
            'virustotal_status': 'unknown',
            'virustotal_detections': 0,
            'virustotal_total': 0,
            'gsb_status': 'safe',
            'threat_score': 0,
            'categories': [],
            'local_detections': [],
            'local_score': 0,
            'detailed_scores': {}  # Track individual pattern scores
        }

        # Local signature scanning
        local_detections, local_score, detailed_scores = self._scan_url_with_signatures(url)
        results['local_detections'] = local_detections
        results['local_score'] = local_score
        results['detailed_scores'] = detailed_scores  # Store detailed breakdown
        results['threat_score'] += local_score

        # Only mark as malicious if local score exceeds threshold (60)
        # This prevents false positives from low-severity patterns on legitimate sites
        if local_score >= 60:
            results['is_malicious'] = True
            logger.warning(f"Local URL scan: {url[:50]}... matched {len(local_detections)} patterns with score {local_score}")
        elif local_detections:
            logger.info(f"Local URL scan: {url[:50]}... matched {len(local_detections)} patterns with low score {local_score}")

        # VirusTotal URL scan
        await self._wait_for_rate_limit()

        vt_score = 0  # Track VT contribution separately
        try:
            async with aiohttp.ClientSession() as session:
                headers = {'x-apikey': self.vt_api_key}

                # URL encode the URL for VT API
                import base64
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

                vt_url = f'https://www.virustotal.com/api/v3/urls/{url_id}'

                async with session.get(vt_url, headers=headers) as response:
                    self.vt_requests.append(time.time())

                    if response.status == 200:
                        data = await response.json()
                        stats = data['data']['attributes']['last_analysis_stats']

                        positives = stats.get('malicious', 0) + stats.get('suspicious', 0)
                        total = sum(stats.values())

                        results['virustotal_detections'] = positives
                        results['virustotal_total'] = total

                        if positives >= VT_THRESHOLD:
                            results['virustotal_status'] = 'malicious'
                            results['is_malicious'] = True
                            vt_score = 50
                            results['threat_score'] += 50
                            logger.warning(f"VirusTotal: {url} is malicious ({positives}/{total})")
                        elif positives > 0:
                            results['virustotal_status'] = 'suspicious'
                            # Don't immediately mark as malicious for low detections
                            # Let the total threat score determine the verdict
                            vt_score = 30
                            results['threat_score'] += 30
                            logger.info(f"VirusTotal: {url} is suspicious ({positives}/{total})")
                        else:
                            results['virustotal_status'] = 'clean'
                            vt_score = 0
                        
                        # Get categories
                        categories = data['data']['attributes'].get('categories', {})
                        results['categories'] = list(categories.values())[:3]  # Top 3
                        
                    elif response.status == 404:
                        # URL not in VT database, submit for scanning
                        logger.info(f"URL not in VT database, submitting: {url}")
                        results['virustotal_status'] = 'not_scanned'
        
        except Exception as e:
            logger.error(f"VirusTotal URL scan error: {e}")
            results['virustotal_status'] = 'error'

        # Store VT score separately
        results['vt_score'] = vt_score

        # Google Safe Browsing
        gsb_score = 0  # Track GSB contribution separately
        if GSB_API_KEY:
            try:
                async with aiohttp.ClientSession() as session:
                    gsb_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}'
                    payload = {
                        'client': {'clientId': 'discord-security-bot', 'clientVersion': '1.0'},
                        'threatInfo': {
                            'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                            'platformTypes': ['ANY_PLATFORM'],
                            'threatEntryTypes': ['URL'],
                            'threatEntries': [{'url': url}]
                        }
                    }
                    async with session.post(gsb_url, json=payload) as response:
                        if response.status == 200:
                            result = await response.json()
                            if result.get('matches'):
                                threat_type = result['matches'][0].get('threatType', 'UNKNOWN')
                                results['gsb_status'] = f'malicious ({threat_type})'
                                results['is_malicious'] = True
                                gsb_score = 50
                                results['threat_score'] += 50
                                logger.warning(f"Google Safe Browsing: {url} is malicious ({threat_type})")
                            else:
                                results['gsb_status'] = 'clean'
                                gsb_score = 0
            except Exception as e:
                logger.error(f"Google Safe Browsing error: {e}")
                results['gsb_status'] = 'error'

        # Store GSB score separately
        results['gsb_score'] = gsb_score

        # URLhaus API - Malware URL database (30,000+ entries, free with Auth-Key)
        urlhaus_score = 0
        results['urlhaus_status'] = 'unknown'
        if URLHAUS_AUTH_KEY:
            try:
                async with aiohttp.ClientSession() as session:
                    urlhaus_url = 'https://urlhaus-api.abuse.ch/v1/url/'
                    headers = {'Auth-Key': URLHAUS_AUTH_KEY}
                    data = {'url': url}
                    async with session.post(urlhaus_url, headers=headers, data=data) as response:
                        if response.status == 200:
                            result = await response.json()
                            if result.get('query_status') == 'ok':
                                # URL found in URLhaus database
                                threat = result.get('threat', 'unknown')
                                results['urlhaus_status'] = f'malicious ({threat})'
                                results['is_malicious'] = True
                                urlhaus_score = 60  # High confidence - URLhaus is curated
                                results['threat_score'] += urlhaus_score
                                logger.warning(f"URLhaus: {url} is malicious (threat: {threat})")
                            elif result.get('query_status') == 'no_results':
                                results['urlhaus_status'] = 'clean'
                                urlhaus_score = 0
                            else:
                                results['urlhaus_status'] = 'unknown'
            except Exception as e:
                logger.error(f"URLhaus API error: {e}")
                results['urlhaus_status'] = 'error'

        results['urlhaus_score'] = urlhaus_score

        # Final determination based on total threat score
        # If not already marked malicious by VT/GSB/URLhaus, check total score
        if not results['is_malicious'] and results['threat_score'] >= 60:
            results['is_malicious'] = True
            logger.warning(f"URL marked malicious based on total threat score: {results['threat_score']}")

        return results
    
    def get_stats(self) -> Dict:
        return {**self.stats}


class EnhancedSecurityBot(commands.Bot):
    """Enhanced security bot with all features"""

    def __init__(self, vt_api_key: str, yara_rules_path: Optional[str] = None):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.messages = True

        super().__init__(command_prefix='!', intents=intents)
        self.scanner = EnhancedSecurityScanner(vt_api_key, yara_rules_path)

        # Initialize quarantine system with encryption
        if ENABLE_QUARANTINE:
            self.quarantine_db = QuarantineDB(encryption_key=QUARANTINE_ENCRYPTION_KEY)
            logger.info("Quarantine system initialized")
        else:
            self.quarantine_db = None
            logger.info("Quarantine system disabled")

        # Store pending file data for quarantine decisions
        self.pending_files: Dict[str, Tuple[bytes, discord.Message, 'EnhancedScanResult']] = {}

        # More aggressive URL pattern
        self.url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            re.IGNORECASE
        )
    
    async def setup_hook(self):
        logger.info("Enhanced Security Bot starting...")
        await self.add_cog(SecurityCommands(self))
        await self.tree.sync()
    
    async def on_ready(self):
        logger.info(f'Logged in as {self.user} (ID: {self.user.id})')
        logger.info('Enhanced security monitoring active!')
        print("REGISTERED COMMANDS:", [cmd.name for cmd in self.commands])
        
        # Send startup notification to audit channel
        if AUDIT_CHANNEL_ID:
            channel = self.get_channel(AUDIT_CHANNEL_ID)
            if channel:
                embed = discord.Embed(
                    title="🤖 Security Bot Online",
                    description="Enhanced monitoring active with all features enabled",
                    color=discord.Color.green()
                )
                embed.add_field(name="Auto Delete", value=str(AUTO_DELETE_MALICIOUS))
                embed.add_field(name="VT Threshold", value=str(VT_THRESHOLD))
                embed.add_field(name="Max File Size", value=f"{MAX_FILE_SIZE / 1024 / 1024:.0f} MB")
                await channel.send(embed=embed)
    
    async def on_message(self, message: discord.Message):
        if message.author == self.user:
            return

        logger.debug(f"Message from {message.author}: {message.content[:100]}")

        try:
            # Scan attachments
            if message.attachments and ENABLE_ATTACHMENT_SCANNING:
                logger.info(f"Found {len(message.attachments)} attachments to scan")
                await self.scan_attachments(message)

            # Scan URLs
            if ENABLE_URL_SCANNING:
                urls = self.url_pattern.findall(message.content)
                if urls:
                    logger.info(f"Found {len(urls)} URLs in message: {urls}")
                    await self.scan_urls(message, urls[:MAX_URLS_PER_MESSAGE])
                else:
                    logger.debug("No URLs found in message")

        except Exception as e:
            logger.error(f"on_message error: {e}", exc_info=True)

        # THIS MUST RUN NO MATTER WHAT
        await self.process_commands(message)


    
    async def scan_attachments(self, message: discord.Message):
        """Scan attachments with all features"""
        for attachment in message.attachments:
            # Check file size
            if attachment.size > MAX_FILE_SIZE:
                await message.channel.send(
                    f"⚠️ File too large: {attachment.size / 1024 / 1024:.1f}MB "
                    f"(max: {MAX_FILE_SIZE / 1024 / 1024:.0f}MB)"
                )
                continue
            
            # Download file data for magic bytes detection
            file_data = await attachment.read()

            # Check blocked extensions
            file_ext = os.path.splitext(attachment.filename)[1].lower()
            logger.info(f"Checking extension '{file_ext}' against blocked list: {BLOCKED_EXTENSIONS}")

            # Also check magic bytes to prevent bypassing by renaming
            detected_type, detected_desc = detect_file_type_magic_bytes(file_data)
            logger.info(f"Magic bytes detection: {detected_desc}")

            # Block dangerous file types based on magic bytes OR extension
            dangerous_types = {'exe', 'elf', 'macho', 'script', 'php'}
            is_blocked_by_magic = detected_type in dangerous_types
            is_blocked_by_ext = BLOCKED_EXTENSIONS and file_ext in BLOCKED_EXTENSIONS

            if is_blocked_by_ext or is_blocked_by_magic:
                block_reason = []
                if is_blocked_by_ext:
                    block_reason.append(f"extension: {file_ext}")
                if is_blocked_by_magic:
                    block_reason.append(f"type: {detected_desc}")

                logger.error(f"BLOCKED FILE DETECTED: {' + '.join(block_reason)} in {attachment.filename}")

                # Delete the message immediately (always delete blocked files)
                block_reason_text = ' + '.join(block_reason)
                try:
                    await message.delete()
                    logger.info(f"Deleted message with blocked file type")

                    warning_msg = await message.channel.send(
                        f"🚨 **BLOCKED FILE TYPE**\n"
                        f"File `{attachment.filename}` was deleted for security reasons.\n"
                        f"**Reason:** {block_reason_text}\n"
                        f"**Detected Type:** {detected_desc}\n"
                        f"User: {message.author.mention}"
                    )
                except Exception as e:
                    logger.error(f"Could not delete message: {e}")
                    warning_msg = await message.channel.send(
                        f"🚨 **BLOCKED FILE TYPE**\n"
                        f"This file is not allowed for security reasons.\n"
                        f"**Reason:** {block_reason_text}"
                    )

                # Log to audit channel
                if AUDIT_CHANNEL_ID:
                    audit_channel = self.get_channel(AUDIT_CHANNEL_ID)
                    if audit_channel:
                        audit_embed = discord.Embed(
                            title="🚫 Blocked File Type (Magic Bytes + Extension Check)",
                            color=discord.Color.dark_red()
                        )
                        audit_embed.add_field(name="User", value=str(message.author))
                        audit_embed.add_field(name="File", value=attachment.filename)
                        audit_embed.add_field(name="Extension", value=file_ext)
                        audit_embed.add_field(name="Detected Type", value=detected_desc)
                        audit_embed.add_field(name="Block Reason", value=block_reason_text)
                        await audit_channel.send(embed=audit_embed)
                
                continue
            
            # Scan (file_data already downloaded above for magic bytes check)
            scan_msg = await message.channel.send(
                f"🔍 Scanning `{attachment.filename}` - Enhanced scan in progress..."
            )

            try:
                # file_data already loaded above, no need to download again
                result = await self.scanner.scan_file(file_data, attachment.filename)

                # Show results
                await scan_msg.edit(content=None, embed=result.to_embed())

                # Handle malicious files
                if result.is_malicious:
                    await self._handle_malicious_file(message, result, attachment.filename, file_data)
            
            except Exception as e:
                logger.error(f"Scan error: {e}")
                await scan_msg.edit(content=f"❌ Scan failed: {str(e)[:100]}")
    
    async def _handle_malicious_file(self, message: discord.Message, result: EnhancedScanResult, filename: str, file_data: bytes = None):
        """Handle malicious file detection with quarantine system"""

        # Check if quarantine is enabled
        if ENABLE_QUARANTINE and self.quarantine_db and file_data:
            # Store file data temporarily for user decision
            file_hash = result.file_hash
            self.pending_files[file_hash] = (file_data, message, result)

            # Determine if user is admin
            is_admin = message.author.guild_permissions.administrator if message.guild else False

            # Create interactive view
            view = ThreatActionView(
                user_id=message.author.id,
                threat_level=result.threat_score.threat_level,
                is_admin=is_admin,
                timeout=AUTO_QUARANTINE_TIMEOUT
            )

            # Send action prompt
            action_msg = await message.channel.send(
                f"⚠️ {message.author.mention} **THREAT DETECTED** in `{filename}`\n"
                f"**Threat Level:** {result.threat_score.threat_level.upper()} ({result.threat_score.total_score:.1f}/100)\n"
                f"**Choose an action within {AUTO_QUARANTINE_TIMEOUT}s or it will be auto-quarantined:**",
                view=view
            )

            # Wait for user decision
            await view.wait()

            # Handle user action
            if view.action == "keep":
                # User chose to keep - do nothing, file stays
                logger.info(f"User {message.author} chose to KEEP malicious file: {filename}")
                # Clean up pending data
                self.pending_files.pop(file_hash, None)

            elif view.action == "delete":
                # User chose to delete permanently
                try:
                    await message.delete()
                    logger.info(f"User {message.author} DELETED malicious file: {filename}")
                except Exception as e:
                    logger.error(f"Could not delete message: {e}")
                # Clean up pending data
                self.pending_files.pop(file_hash, None)

            else:  # quarantine or timeout
                # Quarantine the file
                try:
                    detections = result.yara_matches + result.detections
                    item_id = self.quarantine_db.store_file(
                        file_data=file_data,
                        file_hash=file_hash,
                        filename=filename,
                        user_id=message.author.id,
                        user_name=str(message.author),
                        channel_id=message.channel.id,
                        guild_id=message.guild.id if message.guild else 0,
                        threat_score=result.threat_score.total_score,
                        threat_level=result.threat_score.threat_level,
                        detections=detections,
                        message_content=message.content
                    )

                    # Delete original message
                    await message.delete()

                    if view.action == "timeout_quarantine":
                        await action_msg.edit(
                            content=f"⏱️ **AUTO-QUARANTINED** (no response)\n"
                                    f"File `{filename}` has been quarantined (ID: {item_id})\n"
                                    f"Use `!quarantine list` to view and `!quarantine retrieve {item_id}` to restore.",
                            view=None
                        )

                    logger.info(f"Quarantined file {filename} (ID: {item_id})")

                except Exception as e:
                    logger.error(f"Quarantine error: {e}")
                    await message.channel.send(f"❌ Error quarantining file: {str(e)}")

                # Clean up pending data
                self.pending_files.pop(file_hash, None)

        else:
            # Quarantine disabled - use old auto-delete behavior
            if AUTO_DELETE_MALICIOUS:
                try:
                    await message.delete()
                    logger.info(f"Deleted malicious file: {filename} from {message.author}")

                    if MENTION_USER_ON_DELETE:
                        warning = await message.channel.send(
                            f"🚨 {message.author.mention} Your file was blocked - "
                            f"Threat score: **{result.threat_score.total_score:.1f}/100**"
                        )
                        await asyncio.sleep(WARNING_DELETE_DELAY)
                        try:
                            await warning.delete()
                        except:
                            pass
                except Exception as e:
                    logger.error(f"Could not delete message: {e}")

        # Always send to audit channel regardless of quarantine
        if AUDIT_CHANNEL_ID:
            audit_channel = self.get_channel(AUDIT_CHANNEL_ID)
            if audit_channel:
                audit_embed = discord.Embed(
                    title="🚨 Malicious File Detected",
                    color=discord.Color.red(),
                    timestamp=datetime.utcnow()
                )
                audit_embed.add_field(name="User", value=f"{message.author} ({message.author.id})")
                audit_embed.add_field(name="Channel", value=message.channel.mention)
                audit_embed.add_field(name="File", value=filename)
                audit_embed.add_field(name="Threat Score", value=f"{result.threat_score.total_score:.1f}/100")
                audit_embed.add_field(name="VT Detections", value=f"{result.vt_positives}/{result.vt_total}")
                if result.hybrid_verdict:
                    audit_embed.add_field(name="Hybrid Analysis", value=result.hybrid_verdict)
                await audit_channel.send(embed=audit_embed)

        # Send webhook alert
        if ALERT_WEBHOOK_URL:
            try:
                async with aiohttp.ClientSession() as session:
                    webhook_data = {
                        'content': f'🚨 **MALICIOUS FILE DETECTED**',
                        'embeds': [{
                            'title': 'Security Alert',
                            'description': f'File: `{filename}`\nUser: {message.author.name}\nScore: {result.threat_score.total_score:.1f}/100',
                            'color': 15158332,
                            'timestamp': datetime.utcnow().isoformat()
                        }]
                    }
                    await session.post(ALERT_WEBHOOK_URL, json=webhook_data)
            except Exception as e:
                logger.error(f"Webhook error: {e}")
    
    async def scan_urls(self, message: discord.Message, urls: List[str]):
        """Scan URLs with VirusTotal and Google Safe Browsing with containment"""
        logger.info(f"Scanning {len(urls)} URLs from message")

        # Store original message info (don't delete yet - only if malicious)
        original_author = message.author
        original_channel = message.channel
        original_content = message.content
        message_deleted = False

        for url in urls:
            logger.info(f"Checking URL: {url}")

            # Skip trusted domains
            parsed = urlparse(url)
            if TRUSTED_DOMAINS and parsed.netloc in TRUSTED_DOMAINS:
                logger.info(f"Skipping trusted domain: {parsed.netloc}")
                await original_channel.send(f"✅ Trusted domain skipped: `{parsed.netloc}`")
                continue

            # Show scanning message (defang URL for safety)
            url_preview = defang_url(url)[:50]
            scan_msg = await original_channel.send(f"🔍 Scanning URL from {original_author.mention}: `{url_preview}...`")

            try:
                result = await self.scanner.scan_url(url)

                if result['is_malicious']:
                    # Determine detection sources
                    detection_sources = []
                    if result.get('local_score', 0) > 0:
                        detection_sources.append("🔍 Local Engine")
                    if result.get('vt_score', 0) > 0:
                        detection_sources.append("🦠 VirusTotal")
                    if result.get('gsb_score', 0) > 0:
                        detection_sources.append("🛡️ Google Safe Browsing")
                    if result.get('urlhaus_score', 0) > 0:
                        detection_sources.append("🗂️ URLhaus")

                    sources_text = " + ".join(detection_sources) if detection_sources else "Unknown"

                    # Create threat embed with defanged URL
                    defanged = defang_url(url)
                    embed = discord.Embed(
                        title="🚨 Malicious URL Detected",
                        description=f"**URL (Defanged):** `{defanged}`\n**Detected by:** {sources_text}\n\n⚠️ *Click 'Trust URL' below to reveal the actual URL (at your own risk!)*",
                        color=discord.Color.red(),
                        timestamp=datetime.utcnow()
                    )

                    # INDIVIDUAL SCORES - Show each source's contribution
                    scores_breakdown = f"```\n"
                    scores_breakdown += f"Local Engine:    {result['local_score']:>3}/100\n"
                    scores_breakdown += f"VirusTotal:      {result.get('vt_score', 0):>3}/100\n"
                    scores_breakdown += f"Safe Browsing:   {result.get('gsb_score', 0):>3}/100\n"
                    scores_breakdown += f"URLhaus:         {result.get('urlhaus_score', 0):>3}/100\n"
                    scores_breakdown += f"─────────────────────────\n"
                    scores_breakdown += f"TOTAL THREAT:    {result['threat_score']:>3}/100\n"
                    scores_breakdown += f"```"
                    embed.add_field(name="⚠️ Threat Score Breakdown", value=scores_breakdown, inline=False)

                    # Categorize and display local detections with threat type
                    if result.get('local_detections'):
                        detailed_scores = result.get('detailed_scores', {})
                        detections = result['local_detections']

                        # Categorize URL threats
                        categories = {
                            'phishing': [d for d in detections if any(x in d.lower() for x in
                                ['phish', 'credential', 'login', 'password', 'auth'])],
                            'typosquatting': [d for d in detections if any(x in d.lower() for x in
                                ['typosquat', 'brand', 'lookalike', 'homograph', 'confusable'])],
                            'malware': [d for d in detections if any(x in d.lower() for x in
                                ['malware', 'download', 'payload', 'trojan', 'ransomware'])],
                            'scam': [d for d in detections if any(x in d.lower() for x in
                                ['scam', 'giveaway', 'prize', 'crypto_giveaway', 'fake', 'doubler'])],
                            'suspicious': []
                        }

                        # Anything not categorized goes to suspicious
                        categorized = set(sum(categories.values(), []))
                        categories['suspicious'] = [d for d in detections if d not in categorized]

                        # Build display with categories
                        local_dets = ""
                        threat_types = []

                        if categories['phishing']:
                            threat_types.append("Phishing")
                            local_dets += "**🎣 Phishing Indicators:**\n"
                            for pattern in categories['phishing'][:3]:
                                score = detailed_scores.get(pattern, 0)
                                local_dets += f"• {pattern}: {score} pts\n"
                            if len(categories['phishing']) > 3:
                                local_dets += f"• *...+{len(categories['phishing']) - 3} more*\n"
                            local_dets += "\n"

                        if categories['typosquatting']:
                            threat_types.append("Typosquatting")
                            local_dets += "**🔤 Typosquatting/Brand Abuse:**\n"
                            for pattern in categories['typosquatting'][:3]:
                                score = detailed_scores.get(pattern, 0)
                                local_dets += f"• {pattern}: {score} pts\n"
                            if len(categories['typosquatting']) > 3:
                                local_dets += f"• *...+{len(categories['typosquatting']) - 3} more*\n"
                            local_dets += "\n"

                        if categories['malware']:
                            threat_types.append("Malware Distribution")
                            local_dets += "**💀 Malware Distribution:**\n"
                            for pattern in categories['malware'][:3]:
                                score = detailed_scores.get(pattern, 0)
                                local_dets += f"• {pattern}: {score} pts\n"
                            if len(categories['malware']) > 3:
                                local_dets += f"• *...+{len(categories['malware']) - 3} more*\n"
                            local_dets += "\n"

                        if categories['scam']:
                            threat_types.append("Scam")
                            local_dets += "**💸 Scam/Fraud:**\n"
                            for pattern in categories['scam'][:3]:
                                score = detailed_scores.get(pattern, 0)
                                local_dets += f"• {pattern}: {score} pts\n"
                            if len(categories['scam']) > 3:
                                local_dets += f"• *...+{len(categories['scam']) - 3} more*\n"
                            local_dets += "\n"

                        if categories['suspicious']:
                            if not threat_types:  # Only show if no other categories
                                threat_types.append("Suspicious")
                            local_dets += "**⚠️ Suspicious Indicators:**\n"
                            for pattern in categories['suspicious'][:3]:
                                score = detailed_scores.get(pattern, 0)
                                local_dets += f"• {pattern}: {score} pts\n"
                            if len(categories['suspicious']) > 3:
                                local_dets += f"• *...+{len(categories['suspicious']) - 3} more*\n"

                        # Add threat classification at the top of embed
                        if threat_types:
                            classification = " | ".join(threat_types)
                            embed.description = f"**URL:** ||{defanged}|| (Defanged - Click to reveal)\n**Threat Type:** `{classification}`"

                        embed.add_field(name=f"🔍 Detection Details ({len(detections)} patterns)", value=local_dets.strip(), inline=False)

                    # VirusTotal details
                    vt_status = result['virustotal_status']
                    if vt_status != 'unknown':
                        vt_text = f"{result['virustotal_detections']}/{result['virustotal_total']} engines"
                        if result['virustotal_detections'] > 0:
                            vt_text += f" ({result['virustotal_detections']/result['virustotal_total']*100:.1f}%)"
                        embed.add_field(name="🦠 VirusTotal Details", value=vt_text, inline=True)

                    # Google Safe Browsing details with better formatting
                    gsb_status = result['gsb_status']
                    if gsb_status and gsb_status != 'clean' and gsb_status != 'unknown':
                        # Extract threat type from status like "malicious (MALWARE)"
                        gsb_display = gsb_status.replace('malicious', '⚠️ Malicious')
                        embed.add_field(name="🛡️ Google Safe Browsing", value=gsb_display, inline=True)
                    elif gsb_status:
                        embed.add_field(name="🛡️ Google Safe Browsing", value=gsb_status.capitalize(), inline=True)

                    # URLhaus details with better formatting
                    if result.get('urlhaus_status'):
                        urlhaus_status = result['urlhaus_status']
                        if 'malicious' in urlhaus_status:
                            # Extract malware family from status like "malicious (Emotet)"
                            urlhaus_display = urlhaus_status.replace('malicious', '⚠️ Malicious')
                            embed.add_field(name="🗂️ URLhaus Database", value=urlhaus_display, inline=True)
                        else:
                            embed.add_field(name="🗂️ URLhaus Database", value=urlhaus_status.capitalize(), inline=True)

                    # Categories
                    if result.get('categories'):
                        cats = ", ".join(result['categories'])
                        embed.add_field(name="📁 Categories", value=cats, inline=False)

                    embed.set_footer(text="⚠️ Do not visit this URL!")

                    await scan_msg.edit(content=None, embed=embed)

                    # Quarantine URL if enabled
                    if ENABLE_QUARANTINE and self.quarantine_db:
                        # Create interactive view for URL action
                        is_admin = original_author.guild_permissions.administrator if hasattr(original_author, 'guild_permissions') else False
                        view = URLActionView(
                            user_id=original_author.id,
                            url=url,
                            is_admin=is_admin,
                            timeout=AUTO_QUARANTINE_TIMEOUT
                        )

                        action_msg = await original_channel.send(
                            f"⚠️ {original_author.mention} **MALICIOUS URL DETECTED**\n"
                            f"**Threat Score:** {result['threat_score']}/100\n"
                            f"**Choose an action within {AUTO_QUARANTINE_TIMEOUT}s or URL will be quarantined:**",
                            view=view
                        )

                        # Wait for user decision
                        await view.wait()

                        if view.action == "trust":
                            # User chose to trust - restore original message
                            logger.info(f"User {original_author} chose to TRUST malicious URL: {url[:50]}")

                            # Post original message back
                            if not message_deleted:
                                await action_msg.edit(
                                    content=f"⚠️ User chose to TRUST this URL (Threat Score: {result['threat_score']}/100)\n"
                                            f"**Original message restored below** - Use at your own risk!",
                                    view=None
                                )
                                # Repost the original message
                                await original_channel.send(f"**[Message from {original_author.mention}]:**\n{original_content}")
                            else:
                                await action_msg.edit(
                                    content=f"⚠️ User chose to TRUST this URL (Threat Score: {result['threat_score']}/100)\n"
                                            f"**URL:** {url}\n"
                                            f"**Original message:** {original_content}\n"
                                            f"**Use at your own risk!**",
                                    view=None
                                )

                        else:  # remove or timeout
                            # Delete message and quarantine URL
                            try:
                                # Delete the message now (if not already deleted)
                                if not message_deleted:
                                    try:
                                        await message.delete()
                                        message_deleted = True
                                        logger.info(f"Deleted message with malicious URL")
                                    except:
                                        pass

                                # Store in quarantine
                                detections = []
                                if result.get('local_detections'):
                                    detections.extend([f"Local: {det}" for det in result['local_detections']])
                                detections.append(f"VirusTotal: {result['virustotal_detections']}/{result['virustotal_total']}")
                                detections.append(f"GSB: {result['gsb_status']}")
                                item_id = self.quarantine_db.store_url(
                                    url=url,
                                    user_id=original_author.id,
                                    user_name=str(original_author),
                                    channel_id=original_channel.id,
                                    guild_id=original_channel.guild.id if hasattr(original_channel, 'guild') and original_channel.guild else 0,
                                    threat_score=result['threat_score'],
                                    detections=detections,
                                    message_content=url  # Store the URL since original message was deleted
                                )

                                # Message already deleted at start of function

                                # Update action message
                                if view.action == "timeout_remove":
                                    await action_msg.edit(
                                        content=f"⏱️ **AUTO-REMOVED** (no response)\n"
                                                f"Malicious URL removed and quarantined (ID: {item_id})\n"
                                                f"Original message content stored in quarantine.",
                                        view=None
                                    )
                                else:
                                    await action_msg.edit(
                                        content=f"🔒 Malicious URL removed and quarantined (ID: {item_id})",
                                        view=None
                                    )

                                logger.info(f"Quarantined URL {url[:50]} (ID: {item_id})")

                            except Exception as e:
                                logger.error(f"URL quarantine error: {e}")
                                await original_channel.send(f"❌ Error quarantining URL: {str(e)}")

                    else:
                        # Quarantine disabled - just warn
                        logger.warning(f"Malicious URL detected but quarantine disabled: {url[:50]}")

                    # Log to audit channel
                    if AUDIT_CHANNEL_ID:
                        audit_channel = self.get_channel(AUDIT_CHANNEL_ID)
                        if audit_channel:
                            audit_embed = embed.copy()
                            audit_embed.add_field(name="User", value=f"{original_author} ({original_author.id})", inline=False)
                            audit_embed.add_field(name="Channel", value=original_channel.mention, inline=False)
                            await audit_channel.send(embed=audit_embed)

                    # Send webhook alert
                    if ALERT_WEBHOOK_URL:
                        try:
                            async with aiohttp.ClientSession() as session:
                                defanged_webhook = defang_url(url)
                                webhook_data = {
                                    'content': f'🚨 **MALICIOUS URL DETECTED**',
                                    'embeds': [{
                                        'title': 'Security Alert',
                                        'description': f'URL (Defanged): {defanged_webhook}\nUser: {original_author.name}\nChannel: {original_channel.name}',
                                        'color': 15158332,
                                        'timestamp': datetime.utcnow().isoformat()
                                    }]
                                }
                                await session.post(ALERT_WEBHOOK_URL, json=webhook_data)
                        except Exception as e:
                            logger.error(f"Webhook error: {e}")

                else:
                    # URL is safe - still defang for consistency
                    safe_defanged = defang_url(url)
                    embed = discord.Embed(
                        title="✅ URL Scan Complete",
                        description=f"**URL:** {safe_defanged}",
                        color=discord.Color.green()
                    )

                    # INDIVIDUAL SCORES - Show breakdown even for safe URLs
                    scores_breakdown = f"```\n"
                    scores_breakdown += f"Local Engine:    {result['local_score']:>3}/100\n"
                    scores_breakdown += f"VirusTotal:      {result.get('vt_score', 0):>3}/100\n"
                    scores_breakdown += f"Safe Browsing:   {result.get('gsb_score', 0):>3}/100\n"
                    scores_breakdown += f"─────────────────────────\n"
                    scores_breakdown += f"TOTAL THREAT:    {result['threat_score']:>3}/100\n"
                    scores_breakdown += f"```"
                    embed.add_field(name="📊 Score Breakdown", value=scores_breakdown, inline=False)

                    # VirusTotal details
                    vt_status = result['virustotal_status']
                    if vt_status == 'clean':
                        embed.add_field(name="🦠 VirusTotal", value="✅ Clean (0 detections)", inline=True)
                    elif vt_status == 'not_scanned':
                        embed.add_field(name="🦠 VirusTotal", value="ℹ️ Not in database", inline=True)
                    else:
                        embed.add_field(name="🦠 VirusTotal", value=vt_status, inline=True)

                    # Google Safe Browsing
                    gsb_display = "✅ Clean" if result['gsb_status'] == 'clean' else result['gsb_status']
                    embed.add_field(name="🛡️ Google Safe Browsing", value=gsb_display, inline=True)

                    # Overall Status
                    embed.add_field(name="🔐 Overall Status", value="✅ **SAFE**", inline=True)

                    # Local detections (if any low-severity matches)
                    if result.get('local_detections'):
                        local_dets = ", ".join(result['local_detections'][:3])
                        if len(result['local_detections']) > 3:
                            local_dets += f", ...+{len(result['local_detections']) - 3} more"
                        embed.add_field(name="ℹ️ Low-Severity Patterns", value=f"```{local_dets}```", inline=False)

                    # Categories
                    if result.get('categories'):
                        cats = ", ".join(result['categories'])
                        embed.add_field(name="📁 Categories", value=cats, inline=False)

                    await scan_msg.edit(content=None, embed=embed)

            except Exception as e:
                logger.error(f"URL scan error for {url}: {e}", exc_info=True)
                await scan_msg.edit(content=f"❌ URL scan failed: {str(e)[:100]}")
    
    async def on_command_error(self, ctx, error):
        raise error

class SecurityCommands(commands.Cog):
    """Security bot commands"""
    
    def __init__(self, bot: EnhancedSecurityBot):
        self.bot = bot
    
    @commands.command(name='all')
    async def show_help(self, ctx):
        """Show all available commands"""
        embed = discord.Embed(
            title="🛡️ Security Bot Commands",
            description="Discord Security Audit Bot - Enhanced Edition",
            color=discord.Color.blue(),
            timestamp=datetime.utcnow()
        )
        
        # General Commands
        embed.add_field(
            name="📊 !stats",
            value="View scanning statistics and active APIs",
            inline=False
        )
        
        embed.add_field(
            name="📖 !help",
            value="Show this help message",
            inline=False
        )
        
        embed.add_field(
            name="ℹ️ !info",
            value="Show bot configuration and status",
            inline=False
        )
        
        # Admin Commands
        embed.add_field(
            name="🔧 Admin Commands",
            value="*Requires Administrator permission*",
            inline=False
        )
        
        embed.add_field(
            name="🗑️ !autodelete <on/off>",
            value="Enable or disable automatic deletion of malicious files\n"
                  "Example: `!autodelete on`",
            inline=False
        )
        
        embed.add_field(
            name="🚫 !blacklist <extension>",
            value="Add file extension to blacklist (will be blocked)\n"
                  "Example: `!blacklist .apk`",
            inline=False
        )
        
        embed.add_field(
            name="✅ !whitelist <extension>",
            value="Remove file extension from blacklist (will be allowed)\n"
                  "Example: `!whitelist .pdf`",
            inline=False
        )
        
        embed.add_field(
            name="📋 !listblacklist",
            value="Show all blacklisted file extensions",
            inline=False
        )
        
        # Quarantine Commands
        embed.add_field(
            name="🔒 Quarantine Commands",
            value="*Interactive threat management*",
            inline=False
        )

        embed.add_field(
            name="📋 !quarantine",
            value="View quarantine help and subcommands\n"
                  "• `!quarantine list` - View quarantined items\n"
                  "• `!quarantine retrieve <ID>` - Restore item\n"
                  "• `!quarantine stats` - View statistics",
            inline=False
        )

        # Automatic Features
        embed.add_field(
            name="🤖 Automatic Features",
            value="• Scans all file uploads automatically\n"
                  "• Scans URLs with VirusTotal + Google Safe Browsing\n"
                  "• Threat scoring 0-100 (6 detection engines)\n"
                  "• **Interactive quarantine with user choices**\n"
                  "• Blocks blacklisted file extensions\n"
                  "• Posts alerts to audit channel\n"
                  "• Sends webhook notifications",
            inline=False
        )

        embed.set_footer(text=f"Prefix: ! | Requested by {ctx.author.name}")
        await ctx.send(embed=embed)
    
    @commands.command(name='info')
    async def show_info(self, ctx):
        """Show bot configuration and status"""
        embed = discord.Embed(
            title="⚙️ Bot Configuration",
            color=discord.Color.blue(),
            timestamp=datetime.utcnow()
        )
        
        # Current Settings
        embed.add_field(
            name="Auto Delete Malicious",
            value="🟢 Enabled" if AUTO_DELETE_MALICIOUS else "🔴 Disabled",
            inline=True
        )
        
        embed.add_field(
            name="VT Threshold",
            value=f"{VT_THRESHOLD} detections",
            inline=True
        )
        
        embed.add_field(
            name="YARA Threshold",
            value=f"{YARA_THRESHOLD} matches",
            inline=True
        )
        
        embed.add_field(
            name="Max File Size",
            value=f"{MAX_FILE_SIZE / 1024 / 1024:.0f} MB",
            inline=True
        )
        
        embed.add_field(
            name="URL Scanning",
            value="🟢 Enabled" if ENABLE_URL_SCANNING else "🔴 Disabled",
            inline=True
        )
        
        embed.add_field(
            name="Blacklisted Extensions",
            value=f"{len(BLOCKED_EXTENSIONS)} types",
            inline=True
        )
        
        # Active APIs
        file_engines = ["VirusTotal", "YARA Rules", "Signatures"]
        if HYBRID_ANALYSIS_API_KEY:
            file_engines.append("Hybrid Analysis")
        
        url_engines = ["VirusTotal"]
        if GSB_API_KEY:
            url_engines.append("Google Safe Browsing")
        
        embed.add_field(
            name="📂 File Detection Engines",
            value="• " + "\n• ".join(file_engines),
            inline=False
        )
        
        embed.add_field(
            name="🔗 URL Detection Engines",
            value="• " + "\n• ".join(url_engines),
            inline=False
        )
        
        # Audit Channel
        if AUDIT_CHANNEL_ID:
            channel = self.bot.get_channel(AUDIT_CHANNEL_ID)
            if channel:
                embed.add_field(
                    name="Audit Channel",
                    value=channel.mention,
                    inline=False
                )
        
        embed.set_footer(text="Security Audit System v3.0 Enhanced")
        await ctx.send(embed=embed)
    
    @commands.command(name='stats')
    async def show_stats(self, ctx):
        """Show statistics"""
        stats = self.bot.scanner.get_stats()
        
        embed = discord.Embed(
            title="📊 Security Scanner Statistics",
            color=discord.Color.blue()
        )
        
        embed.add_field(name="Total Scans", value=f"{stats['total_scans']:,}")
        embed.add_field(name="Avg Threat Score", value=f"{stats['avg_threat_score']:.1f}/100")
        
        dist_text = "```\n"
        for level in ['safe', 'low', 'medium', 'high', 'critical']:
            count = stats['threat_distribution'][level]
            dist_text += f"{level.upper():<10} {count:>5}\n"
        dist_text += "```"
        embed.add_field(name="Threat Distribution", value=dist_text, inline=False)
        
        # Show API status
        api_status = []
        api_status.append(f"✅ VirusTotal (Files + URLs)")
        if HYBRID_ANALYSIS_API_KEY:
            api_status.append(f"✅ Hybrid Analysis (Files)")
        if GSB_API_KEY:
            api_status.append(f"✅ Google Safe Browsing (URLs)")
        api_status.append(f"✅ YARA Rules (Files)")
        api_status.append(f"✅ Signature Detection (Files)")
        
        embed.add_field(name="Active Detection Engines", value="\n".join(api_status), inline=False)
        
        await ctx.send(embed=embed)
    
    @commands.command(name='autodelete')
    @commands.has_permissions(administrator=True)
    async def set_autodelete(self, ctx, setting: str):
        """Enable or disable automatic deletion of malicious files (Admin only)"""
        global AUTO_DELETE_MALICIOUS
        
        setting = setting.lower()
        if setting in ['on', 'true', 'enable', 'yes', '1']:
            AUTO_DELETE_MALICIOUS = True
            status = "🟢 ENABLED"
            color = discord.Color.green()
            description = "Malicious files will be automatically deleted"
        elif setting in ['off', 'false', 'disable', 'no', '0']:
            AUTO_DELETE_MALICIOUS = False
            status = "🔴 DISABLED"
            color = discord.Color.red()
            description = "Malicious files will be flagged but NOT deleted"
        else:
            await ctx.send("❌ Invalid setting. Use: `on` or `off`\nExample: `!secautodelete on`")
            return
        
        embed = discord.Embed(
            title=f"⚙️ Auto-Delete: {status}",
            description=description,
            color=color,
            timestamp=datetime.utcnow()
        )
        
        embed.add_field(
            name="Changed By",
            value=f"{ctx.author.mention}",
            inline=True
        )
        
        await ctx.send(embed=embed)
        
        # Log to audit channel
        if AUDIT_CHANNEL_ID:
            audit_channel = self.bot.get_channel(AUDIT_CHANNEL_ID)
            if audit_channel:
                audit_embed = discord.Embed(
                    title="⚙️ Configuration Changed",
                    description=f"Auto-Delete set to: **{status}**",
                    color=color,
                    timestamp=datetime.utcnow()
                )
                audit_embed.add_field(name="Admin", value=str(ctx.author))
                await audit_channel.send(embed=audit_embed)
        
        logger.info(f"Auto-delete changed to {AUTO_DELETE_MALICIOUS} by {ctx.author}")
    
    @commands.command(name='blacklist')
    @commands.has_permissions(administrator=True)
    async def add_to_blacklist(self, ctx, extension: str):
        """Add file extension to blacklist (Admin only)"""
        global BLOCKED_EXTENSIONS
        
        # Normalize extension
        if not extension.startswith('.'):
            extension = f'.{extension}'
        extension = extension.lower()
        
        if extension in BLOCKED_EXTENSIONS:
            await ctx.send(f"⚠️ Extension `{extension}` is already blacklisted")
            return
        
        # Add to blacklist
        BLOCKED_EXTENSIONS.add(extension)
        
        embed = discord.Embed(
            title="🚫 Extension Blacklisted",
            description=f"Extension `{extension}` has been added to the blacklist",
            color=discord.Color.red(),
            timestamp=datetime.utcnow()
        )
        
        embed.add_field(
            name="Effect",
            value=f"Files with `{extension}` extension will be blocked",
            inline=False
        )
        
        embed.add_field(
            name="Added By",
            value=f"{ctx.author.mention}",
            inline=True
        )
        
        embed.add_field(
            name="Total Blacklisted",
            value=f"{len(BLOCKED_EXTENSIONS)} extensions",
            inline=True
        )
        
        await ctx.send(embed=embed)
        
        logger.warning(f"Extension {extension} blacklisted by {ctx.author}")
    
    @commands.command(name='whitelist')
    @commands.has_permissions(administrator=True)
    async def remove_from_blacklist(self, ctx, extension: str):
        """Remove file extension from blacklist (Admin only)"""
        global BLOCKED_EXTENSIONS
        
        # Normalize extension
        if not extension.startswith('.'):
            extension = f'.{extension}'
        extension = extension.lower()
        
        if extension not in BLOCKED_EXTENSIONS:
            await ctx.send(f"⚠️ Extension `{extension}` is not in the blacklist")
            return
        
        # Remove from blacklist
        BLOCKED_EXTENSIONS.discard(extension)
        
        embed = discord.Embed(
            title="✅ Extension Whitelisted",
            description=f"Extension `{extension}` has been removed from the blacklist",
            color=discord.Color.green(),
            timestamp=datetime.utcnow()
        )
        
        embed.add_field(
            name="Effect",
            value=f"Files with `{extension}` extension will now be scanned normally",
            inline=False
        )
        
        embed.add_field(
            name="Removed By",
            value=f"{ctx.author.mention}",
            inline=True
        )
        
        embed.add_field(
            name="Total Blacklisted",
            value=f"{len(BLOCKED_EXTENSIONS)} extensions",
            inline=True
        )
        
        await ctx.send(embed=embed)
        
        logger.info(f"Extension {extension} whitelisted by {ctx.author}")
    
    @commands.command(name='listblacklist')
    async def list_blacklist(self, ctx):
        """Show all blacklisted file extensions"""
        embed = discord.Embed(
            title="🚫 Blacklisted File Extensions",
            description="Files with these extensions will be blocked",
            color=discord.Color.red(),
            timestamp=datetime.utcnow()
        )

        if BLOCKED_EXTENSIONS:
            # Sort extensions
            sorted_exts = sorted(list(BLOCKED_EXTENSIONS))

            # Split into columns for better display
            chunks = [sorted_exts[i:i+10] for i in range(0, len(sorted_exts), 10)]

            for i, chunk in enumerate(chunks, 1):
                ext_list = "\n".join([f"• `{ext}`" for ext in chunk])
                embed.add_field(
                    name=f"Group {i}" if len(chunks) > 1 else "Extensions",
                    value=ext_list,
                    inline=True
                )

            embed.set_footer(text=f"Total: {len(BLOCKED_EXTENSIONS)} blacklisted extensions")
        else:
            embed.description = "No extensions are currently blacklisted"
            embed.color = discord.Color.blue()

        await ctx.send(embed=embed)

    @commands.group(name='quarantine', invoke_without_command=True)
    async def quarantine_group(self, ctx):
        """Quarantine management commands"""
        if ctx.invoked_subcommand is None:
            embed = discord.Embed(
                title="🔒 Quarantine System",
                description="Manage quarantined files and URLs",
                color=discord.Color.orange()
            )

            embed.add_field(
                name="📋 !quarantine list",
                value="View all quarantined items",
                inline=False
            )

            embed.add_field(
                name="📥 !quarantine retrieve <ID>",
                value="Retrieve a quarantined file or URL",
                inline=False
            )

            embed.add_field(
                name="🗑️ !quarantine delete <ID>",
                value="Permanently delete a quarantined item (Admin only)",
                inline=False
            )

            embed.add_field(
                name="📊 !quarantine stats",
                value="View quarantine statistics",
                inline=False
            )

            embed.add_field(
                name="🧹 !quarantine cleanup",
                value=f"Delete items older than {QUARANTINE_CLEANUP_DAYS} days (Admin only)",
                inline=False
            )

            await ctx.send(embed=embed)

    @quarantine_group.command(name='list')
    async def quarantine_list(self, ctx):
        """List quarantined items"""
        if not ENABLE_QUARANTINE or not self.bot.quarantine_db:
            await ctx.send("❌ Quarantine system is not enabled.")
            return

        # Get quarantine items for this guild
        guild_id = ctx.guild.id if ctx.guild else None
        items = self.bot.quarantine_db.list_items(guild_id=guild_id, limit=50)

        if not items:
            await ctx.send("✅ Quarantine is empty!")
            return

        # Create paginator
        paginator = QuarantinePaginator(
            items=items,
            items_per_page=5,
            user_id=ctx.author.id
        )

        embed = paginator.create_embed()
        await ctx.send(embed=embed, view=paginator)

    @quarantine_group.command(name='retrieve')
    async def quarantine_retrieve(self, ctx, item_id: int):
        """Retrieve a quarantined item"""
        if not ENABLE_QUARANTINE or not self.bot.quarantine_db:
            await ctx.send("❌ Quarantine system is not enabled.")
            return

        # Get item
        item = self.bot.quarantine_db.get_item(item_id)

        if not item:
            await ctx.send(f"❌ Quarantine item ID `{item_id}` not found.")
            return

        # Check permissions - only original user or admin can retrieve
        is_admin = ctx.author.guild_permissions.administrator if ctx.guild else False
        if item.user_id != ctx.author.id and not is_admin:
            await ctx.send("❌ You can only retrieve your own quarantined items (or be an admin).")
            return

        # Show confirmation
        view = RetrieveConfirmView(
            user_id=ctx.author.id,
            item_id=item_id,
            filename=item.filename
        )

        warning_embed = discord.Embed(
            title="⚠️ Retrieve Quarantined Item?",
            description=f"**File:** `{item.filename}`\n"
                       f"**Threat Level:** {item.threat_level.upper()} ({item.threat_score:.1f}/100)\n"
                       f"**Quarantined:** {item.quarantine_timestamp[:10]}",
            color=discord.Color.orange()
        )

        warning_embed.add_field(
            name="⚠️ Warning",
            value="This item was flagged as potentially malicious. "
                  "Only retrieve if you are absolutely sure it's safe!",
            inline=False
        )

        confirm_msg = await ctx.send(embed=warning_embed, view=view)

        # Wait for confirmation
        await view.wait()

        if not view.confirmed:
            return

        # Retrieve the item
        if item.item_type == 'file':
            # Get file data
            file_data = self.bot.quarantine_db.get_file_data(item.file_hash)

            if not file_data:
                await ctx.send("❌ File data not found in quarantine storage.")
                return

            # Send file via DM
            try:
                file_obj = discord.File(
                    fp=BytesIO(file_data),
                    filename=item.filename
                )

                # Try to send via DM
                try:
                    await ctx.author.send(
                        f"📥 **Retrieved from quarantine:**\n"
                        f"**Original uploader:** <@{item.user_id}>\n"
                        f"**Threat:** {item.threat_level.upper()} ({item.threat_score:.1f}/100)\n"
                        f"⚠️ **USE AT YOUR OWN RISK!**",
                        file=file_obj
                    )
                    # Notify in channel that file was sent
                    await ctx.send(f"✅ File `{item.filename}` has been sent to your DMs, {ctx.author.mention}.")
                except discord.Forbidden:
                    await ctx.send("❌ I couldn't DM you! Please enable DMs from server members and try again.")
                    logger.warning(f"Could not DM {ctx.author} (ID: {ctx.author.id}) - DMs disabled")
                    return

                # Mark as retrieved
                self.bot.quarantine_db.mark_retrieved(item_id)
                logger.info(f"User {ctx.author} retrieved quarantined file ID {item_id} via DM")

            except Exception as e:
                await ctx.send(f"❌ Error sending file: {str(e)}")
                logger.error(f"Error retrieving file: {e}")

        elif item.item_type == 'url':
            # Send URL info via DM (defang for safety)
            detections = json.loads(item.detections)
            defanged_url = defang_url(item.filename)

            embed = discord.Embed(
                title="📥 Retrieved URL from Quarantine",
                description=f"**URL (Defanged):** ||{defanged_url}||\n"
                           f"**Threat Score:** {item.threat_score:.1f}/100",
                color=discord.Color.orange()
            )

            embed.add_field(
                name="Detections",
                value="\n".join([f"• {d}" for d in detections]),
                inline=False
            )

            if item.message_content:
                embed.add_field(
                    name="Original Message",
                    value=item.message_content[:500],
                    inline=False
                )

            embed.add_field(
                name="⚠️ Warning",
                value="This URL was flagged as malicious. Visit at your own risk!",
                inline=False
            )

            embed.set_footer(text=f"Original uploader: {item.user_name}")

            # Try to send via DM
            try:
                await ctx.author.send(embed=embed)
                await ctx.send(f"✅ URL information has been sent to your DMs, {ctx.author.mention}.")
            except discord.Forbidden:
                await ctx.send("❌ I couldn't DM you! Please enable DMs from server members and try again.")
                logger.warning(f"Could not DM {ctx.author} (ID: {ctx.author.id}) - DMs disabled")
                return

            # Mark as retrieved
            self.bot.quarantine_db.mark_retrieved(item_id)
            logger.info(f"User {ctx.author} retrieved quarantined URL ID {item_id} via DM")

    @quarantine_group.command(name='delete')
    @commands.has_permissions(administrator=True)
    async def quarantine_delete(self, ctx, item_id: int):
        """Permanently delete a quarantined item (Admin only)"""
        if not ENABLE_QUARANTINE or not self.bot.quarantine_db:
            await ctx.send("❌ Quarantine system is not enabled.")
            return

        # Get item info first
        item = self.bot.quarantine_db.get_item(item_id)

        if not item:
            await ctx.send(f"❌ Quarantine item ID `{item_id}` not found.")
            return

        # Delete
        success = self.bot.quarantine_db.delete_item(item_id)

        if success:
            embed = discord.Embed(
                title="🗑️ Quarantine Item Deleted",
                description=f"**ID:** {item_id}\n**File:** `{item.filename}`",
                color=discord.Color.green()
            )
            embed.add_field(name="Deleted By", value=str(ctx.author))
            await ctx.send(embed=embed)
            logger.info(f"Admin {ctx.author} deleted quarantine item {item_id}")
        else:
            await ctx.send(f"❌ Failed to delete quarantine item {item_id}")

    @quarantine_group.command(name='stats')
    async def quarantine_stats(self, ctx):
        """View quarantine statistics"""
        if not ENABLE_QUARANTINE or not self.bot.quarantine_db:
            await ctx.send("❌ Quarantine system is not enabled.")
            return

        guild_id = ctx.guild.id if ctx.guild else None
        stats = self.bot.quarantine_db.get_stats(guild_id=guild_id)

        embed = discord.Embed(
            title="📊 Quarantine Statistics",
            color=discord.Color.blue()
        )

        embed.add_field(name="Total Items", value=f"{stats['total']:,}", inline=True)
        embed.add_field(name="Active", value=f"{stats['active']:,}", inline=True)
        embed.add_field(name="Retrieved", value=f"{stats['retrieved']:,}", inline=True)

        # By type
        by_type = stats.get('by_type', {})
        if by_type:
            type_text = "\n".join([f"• {k.upper()}: {v}" for k, v in by_type.items()])
            embed.add_field(name="By Type", value=type_text or "None", inline=True)

        # By threat level
        by_threat = stats.get('by_threat_level', {})
        if by_threat:
            threat_text = "\n".join([f"• {k.upper()}: {v}" for k, v in by_threat.items()])
            embed.add_field(name="By Threat Level", value=threat_text or "None", inline=True)

        await ctx.send(embed=embed)

    @quarantine_group.command(name='cleanup')
    @commands.has_permissions(administrator=True)
    async def quarantine_cleanup(self, ctx):
        """Cleanup old quarantine items (Admin only)"""
        if not ENABLE_QUARANTINE or not self.bot.quarantine_db:
            await ctx.send("❌ Quarantine system is not enabled.")
            return

        count = self.bot.quarantine_db.cleanup_old_items(days=QUARANTINE_CLEANUP_DAYS)

        embed = discord.Embed(
            title="🧹 Quarantine Cleanup Complete",
            description=f"Deleted {count} items older than {QUARANTINE_CLEANUP_DAYS} days",
            color=discord.Color.green()
        )
        embed.add_field(name="Cleaned By", value=str(ctx.author))

        await ctx.send(embed=embed)
        logger.info(f"Admin {ctx.author} cleaned up {count} old quarantine items")


def main():
    """Main entry point"""
    if not DISCORD_TOKEN or not VT_API_KEY:
        logger.error("Missing DISCORD_TOKEN or VT_API_KEY!")
        return
    
    bot = EnhancedSecurityBot(
        vt_api_key=VT_API_KEY,
        yara_rules_path=YARA_RULES_PATH if os.path.exists(YARA_RULES_PATH) else None
    )
    
    bot.run(DISCORD_TOKEN)


if __name__ == '__main__':
    main()
