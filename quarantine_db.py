"""
Quarantine Database Manager
Stores and manages quarantined files and URLs for later retrieval

SECURITY: All quarantined files are encrypted with AES-256 before storage
to prevent accidental execution of malware from the quarantine directory.
"""

import sqlite3
import json
import os
import stat
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import logging
from cryptography.fernet import Fernet

logger = logging.getLogger('QuarantineDB')


@dataclass
class QuarantineItem:
    """Represents a quarantined item"""
    id: int
    item_type: str  # 'file' or 'url'
    file_hash: str
    filename: str
    file_size: int
    user_id: int
    user_name: str
    channel_id: int
    guild_id: int
    threat_score: float
    threat_level: str
    detections: str  # JSON string
    quarantine_timestamp: str
    retrieved: bool = False
    retrieved_timestamp: Optional[str] = None
    message_content: Optional[str] = None  # For URLs
    encrypted: bool = True  # Whether file is encrypted (default: True for security)

    def to_dict(self) -> Dict:
        return asdict(self)


class QuarantineDB:
    """Manages quarantine database with AES-256 encryption"""

    def __init__(self, db_path: str = 'quarantine.db', storage_dir: str = 'quarantine_storage', encryption_key: Optional[str] = None):
        self.db_path = db_path
        self.storage_dir = storage_dir

        # Initialize encryption
        if encryption_key:
            try:
                self.cipher = Fernet(encryption_key.encode())
                self.encryption_enabled = True
                logger.info("🔒 Quarantine encryption: ENABLED (AES-256)")
            except Exception as e:
                logger.error(f"Failed to initialize encryption: {e}")
                logger.warning("⚠️ Quarantine encryption: DISABLED (falling back to plaintext storage)")
                self.cipher = None
                self.encryption_enabled = False
        else:
            logger.warning("⚠️ No encryption key provided - quarantine files will be stored in PLAINTEXT!")
            logger.warning("⚠️ Set QUARANTINE_ENCRYPTION_KEY in .env for secure storage")
            self.cipher = None
            self.encryption_enabled = False

        # Create storage directory with restricted permissions
        os.makedirs(storage_dir, exist_ok=True)
        try:
            # Set directory to owner-only access (700)
            os.chmod(storage_dir, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            logger.info(f"🔒 Quarantine directory secured: {storage_dir} (chmod 700)")
        except Exception as e:
            logger.warning(f"Could not set directory permissions: {e}")

        # Initialize database
        self._init_db()

        logger.info(f"Quarantine DB initialized: {db_path}")

    def _init_db(self):
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Create quarantine items table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS quarantine_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_type TEXT NOT NULL,
                    file_hash TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    user_name TEXT NOT NULL,
                    channel_id INTEGER NOT NULL,
                    guild_id INTEGER NOT NULL,
                    threat_score REAL NOT NULL,
                    threat_level TEXT NOT NULL,
                    detections TEXT NOT NULL,
                    quarantine_timestamp TEXT NOT NULL,
                    retrieved INTEGER DEFAULT 0,
                    retrieved_timestamp TEXT,
                    message_content TEXT,
                    encrypted INTEGER DEFAULT 1
                )
            ''')

            # Add encrypted column to existing tables (migration)
            try:
                cursor.execute('ALTER TABLE quarantine_items ADD COLUMN encrypted INTEGER DEFAULT 0')
                logger.info("Added 'encrypted' column to existing quarantine_items table")
            except sqlite3.OperationalError:
                # Column already exists
                pass

            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_id ON quarantine_items(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_guild_id ON quarantine_items(guild_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_hash ON quarantine_items(file_hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_retrieved ON quarantine_items(retrieved)')

            conn.commit()
            logger.info("Database schema initialized")

    def _encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data using AES-256"""
        if not self.encryption_enabled or not self.cipher:
            logger.warning("Encryption not enabled - storing plaintext!")
            return data

        try:
            encrypted = self.cipher.encrypt(data)
            logger.debug(f"Encrypted {len(data)} bytes → {len(encrypted)} bytes")
            return encrypted
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise

    def _decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using AES-256"""
        if not self.encryption_enabled or not self.cipher:
            logger.warning("Encryption not enabled - returning plaintext!")
            return encrypted_data

        try:
            decrypted = self.cipher.decrypt(encrypted_data)
            logger.debug(f"Decrypted {len(encrypted_data)} bytes → {len(decrypted)} bytes")
            return decrypted
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise

    def store_file(self, file_data: bytes, file_hash: str, filename: str,
                   user_id: int, user_name: str, channel_id: int, guild_id: int,
                   threat_score: float, threat_level: str, detections: List[str],
                   message_content: Optional[str] = None) -> int:
        """Store a quarantined file with AES-256 encryption"""

        # Encrypt file data before storage
        original_size = len(file_data)
        if self.encryption_enabled:
            try:
                encrypted_data = self._encrypt_data(file_data)
                logger.info(f"🔒 Encrypted {filename}: {original_size} bytes → {len(encrypted_data)} bytes")
            except Exception as e:
                logger.error(f"Encryption failed for {filename}: {e}")
                raise
        else:
            encrypted_data = file_data
            logger.warning(f"⚠️ Storing {filename} in PLAINTEXT (encryption disabled)")

        # Save encrypted file to storage
        file_path = os.path.join(self.storage_dir, file_hash)
        try:
            # If file already exists with read-only permissions, remove it first
            # (same hash = same file content, so safe to overwrite)
            if os.path.exists(file_path):
                try:
                    os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)  # Make writable temporarily
                    os.remove(file_path)
                    logger.debug(f"Removed existing quarantined file: {file_hash[:16]}...")
                except Exception as rm_error:
                    logger.warning(f"Could not remove existing file: {rm_error}")

            with open(file_path, 'wb') as f:
                f.write(encrypted_data)

            # Set file permissions to read-only for owner (400)
            # This prevents accidental execution even if decrypted
            os.chmod(file_path, stat.S_IRUSR)
            logger.debug(f"🔒 File permissions set to 400 (read-only): {file_path}")

        except Exception as e:
            logger.error(f"Failed to save quarantined file: {e}")
            raise

        # Store metadata in database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO quarantine_items
                (item_type, file_hash, filename, file_size, user_id, user_name,
                 channel_id, guild_id, threat_score, threat_level, detections,
                 quarantine_timestamp, message_content, encrypted)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                'file',
                file_hash,
                filename,
                original_size,  # Store original size, not encrypted size
                user_id,
                user_name,
                channel_id,
                guild_id,
                threat_score,
                threat_level,
                json.dumps(detections),
                datetime.utcnow().isoformat(),
                message_content,
                1 if self.encryption_enabled else 0
            ))

            item_id = cursor.lastrowid
            conn.commit()

        encryption_status = "🔒 ENCRYPTED" if self.encryption_enabled else "⚠️ PLAINTEXT"
        logger.info(f"Quarantined file {filename} (ID: {item_id}, Hash: {file_hash[:16]}...) [{encryption_status}]")
        return item_id

    def store_url(self, url: str, user_id: int, user_name: str,
                  channel_id: int, guild_id: int, threat_score: float,
                  detections: List[str], message_content: str) -> int:
        """Store a quarantined URL"""

        import hashlib
        url_hash = hashlib.sha256(url.encode()).hexdigest()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO quarantine_items
                (item_type, file_hash, filename, file_size, user_id, user_name,
                 channel_id, guild_id, threat_score, threat_level, detections,
                 quarantine_timestamp, message_content)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                'url',
                url_hash,
                url,  # Store URL in filename field
                0,
                user_id,
                user_name,
                channel_id,
                guild_id,
                threat_score,
                'high',  # URLs are typically high threat
                json.dumps(detections),
                datetime.utcnow().isoformat(),
                message_content
            ))

            item_id = cursor.lastrowid
            conn.commit()

        logger.info(f"Quarantined URL {url[:50]}... (ID: {item_id})")
        return item_id

    def get_item(self, item_id: int) -> Optional[QuarantineItem]:
        """Get quarantine item by ID"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM quarantine_items WHERE id = ?', (item_id,))
            row = cursor.fetchone()

            if row:
                return QuarantineItem(**dict(row))
            return None

    def get_file_data(self, file_hash: str, decrypt: bool = True) -> Optional[bytes]:
        """
        Retrieve file data from storage

        Args:
            file_hash: SHA256 hash of the file
            decrypt: Whether to decrypt the file (default: True)

        Returns:
            Decrypted file data if decrypt=True, encrypted data otherwise
        """
        file_path = os.path.join(self.storage_dir, file_hash)

        if not os.path.exists(file_path):
            logger.warning(f"File not found in quarantine: {file_hash[:16]}...")
            return None

        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()

            # Check if file should be decrypted
            if decrypt and self.encryption_enabled:
                try:
                    decrypted_data = self._decrypt_data(encrypted_data)
                    logger.info(f"🔓 Decrypted file: {file_hash[:16]}... ({len(encrypted_data)} → {len(decrypted_data)} bytes)")
                    return decrypted_data
                except Exception as e:
                    logger.error(f"Failed to decrypt file {file_hash[:16]}...: {e}")
                    logger.warning("⚠️ File may not be encrypted or key is incorrect")
                    # Try returning encrypted data as fallback
                    return encrypted_data
            else:
                if decrypt and not self.encryption_enabled:
                    logger.warning("⚠️ Decryption requested but encryption is disabled - returning plaintext")
                return encrypted_data

        except Exception as e:
            logger.error(f"Failed to read quarantined file: {e}")
            return None

    def list_items(self, user_id: Optional[int] = None, guild_id: Optional[int] = None,
                   retrieved: bool = False, limit: int = 50) -> List[QuarantineItem]:
        """List quarantine items with filters"""
        query = 'SELECT * FROM quarantine_items WHERE retrieved = ?'
        params = [1 if retrieved else 0]

        if user_id:
            query += ' AND user_id = ?'
            params.append(user_id)

        if guild_id:
            query += ' AND guild_id = ?'
            params.append(guild_id)

        query += ' ORDER BY quarantine_timestamp DESC LIMIT ?'
        params.append(limit)

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()

            return [QuarantineItem(**dict(row)) for row in rows]

    def mark_retrieved(self, item_id: int) -> bool:
        """Mark item as retrieved"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE quarantine_items
                SET retrieved = 1, retrieved_timestamp = ?
                WHERE id = ?
            ''', (datetime.utcnow().isoformat(), item_id))

            success = cursor.rowcount > 0
            conn.commit()

        if success:
            logger.info(f"Marked item {item_id} as retrieved")
        return success

    def delete_item(self, item_id: int) -> bool:
        """Delete quarantine item and associated file"""
        # Get item first
        item = self.get_item(item_id)
        if not item:
            return False

        # Delete file if it exists
        if item.item_type == 'file':
            file_path = os.path.join(self.storage_dir, item.file_hash)
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    logger.info(f"Deleted file: {file_path}")
                except Exception as e:
                    logger.error(f"Could not delete file: {e}")

        # Delete from database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM quarantine_items WHERE id = ?', (item_id,))
            success = cursor.rowcount > 0
            conn.commit()

        if success:
            logger.info(f"Deleted quarantine item {item_id}")
        return success

    def get_stats(self, guild_id: Optional[int] = None) -> Dict:
        """Get quarantine statistics"""
        query_base = 'SELECT COUNT(*) FROM quarantine_items WHERE '
        params_total = []
        params_retrieved = []

        if guild_id:
            query_base += 'guild_id = ? AND '
            params_total.append(guild_id)
            params_retrieved.append(guild_id)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Total items
            cursor.execute(query_base + '1=1', params_total)
            total = cursor.fetchone()[0]

            # Retrieved items
            cursor.execute(query_base + 'retrieved = 1', params_retrieved)
            retrieved = cursor.fetchone()[0]

            # By type
            cursor.execute(f'''
                SELECT item_type, COUNT(*)
                FROM quarantine_items
                {f"WHERE guild_id = {guild_id}" if guild_id else ""}
                GROUP BY item_type
            ''')
            by_type = dict(cursor.fetchall())

            # By threat level
            cursor.execute(f'''
                SELECT threat_level, COUNT(*)
                FROM quarantine_items
                {f"WHERE guild_id = {guild_id}" if guild_id else ""}
                GROUP BY threat_level
            ''')
            by_threat = dict(cursor.fetchall())

        return {
            'total': total,
            'active': total - retrieved,
            'retrieved': retrieved,
            'by_type': by_type,
            'by_threat_level': by_threat
        }

    def cleanup_old_items(self, days: int = 30) -> int:
        """Delete items older than specified days"""
        from datetime import timedelta

        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Get items to delete
            cursor.execute(
                'SELECT id, file_hash, item_type FROM quarantine_items WHERE quarantine_timestamp < ?',
                (cutoff,)
            )
            items = cursor.fetchall()

            # Delete files
            for item_id, file_hash, item_type in items:
                if item_type == 'file':
                    file_path = os.path.join(self.storage_dir, file_hash)
                    if os.path.exists(file_path):
                        try:
                            os.remove(file_path)
                        except Exception as e:
                            logger.error(f"Could not delete old file: {e}")

            # Delete from database
            cursor.execute('DELETE FROM quarantine_items WHERE quarantine_timestamp < ?', (cutoff,))
            count = cursor.rowcount
            conn.commit()

        logger.info(f"Cleaned up {count} old quarantine items")
        return count
