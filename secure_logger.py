# secure_logger.py
import json
import os
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

class SecureLogger:
    def __init__(self, private_key_file="private_key.pem", log_file="nids.log"):
        self.log_file = log_file
        self.last_hash = self.get_last_hash()
        
        # Load the private key
        try:
            with open(private_key_file, "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                )
        except FileNotFoundError:
            print(f"[FATAL LOGGER ERROR] Private key not found at {private_key_file}.")
            print("Please run 'generate_keys.py' first.")
            exit(1)

    def get_last_hash(self):
        """Find the hash of the very last entry in the log file."""
        if not os.path.exists(self.log_file) or os.path.getsize(self.log_file) == 0:
            # This is the first log entry
            return "0" * 64  # Start with a SHA-256 hash of all zeros

        last_line = ""
        with open(self.log_file, 'r') as f:
            for line in f:
                last_line = line
        
        try:
            # The last line is a JSON object, parse it
            last_log_entry = json.loads(last_line)
            # Return the hash of this entry, which forms the "previous hash" for the next one
            return last_log_entry['log_hash']
        except (json.JSONDecodeError, KeyError):
            print("[LOGGER WARNING] Log file may be corrupt. Starting new hash chain.")
            return "0" * 64

    def log_alert(self, alert_message):
        """
        Creates a secure, signed, and hash-chained log entry.
        """
        timestamp = datetime.utcnow().isoformat()
        
        # 1. Create the core log data
        log_data = {
            "timestamp": timestamp,
            "alert": alert_message,
            "previous_hash": self.last_hash  # This is the hash chain!
        }
        
        # Serialize to a consistent string
        log_data_string = json.dumps(log_data, sort_keys=True)
        
        # 2. Hash the log data (Integrity)
        current_hash = hashlib.sha256(log_data_string.encode()).hexdigest()
        
        # 3. Sign the hash (Authenticity)
        signature = self.private_key.sign(
            current_hash.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # 4. Create the final, complete log entry
        final_log = {
            "log_entry": log_data,
            "log_hash": current_hash,
            "signature": signature.hex()  # Store signature as hex
        }
        
        # 5. Write to file
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(final_log) + "\n")
            
        # 6. Update the last_hash for the next log
        self.last_hash = current_hash