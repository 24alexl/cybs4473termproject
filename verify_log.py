# verify_log.py
import json
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

def verify_log_integrity(log_file="nids.log", public_key_file="public_key.pem"):
    print(f"--- Verifying Log File: {log_file} ---")
    
    # Load the public key
    try:
        with open(public_key_file, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read()
            )
    except FileNotFoundError:
        print(f"[VERIFY FAILED] Public key not found at {public_key_file}.")
        return

    previous_hash = "0" * 64  # Hash chain starts with all zeros
    line_number = 0

    try:
        with open(log_file, 'r') as f:
            for line in f:
                line_number += 1
                
                try:
                    log_entry = json.loads(line)
                    
                    # Extract components
                    log_data = log_entry['log_entry']
                    log_hash = log_entry['log_hash']
                    signature_hex = log_entry['signature']
                    
                    # 1. Verify the Hash Chain (Integrity)
                    if log_data['previous_hash'] != previous_hash:
                        print(f"\n[TAMPERING DETECTED] at line {line_number}!")
                        print("Reason: Hash chain is broken.")
                        print(f"Expected prev_hash: {previous_hash}")
                        print(f"Found prev_hash:    {log_data['previous_hash']}")
                        return
                    
                    # 2. Re-hash the entry to see if it matches
                    log_data_string = json.dumps(log_data, sort_keys=True)
                    recalculated_hash = hashlib.sha256(log_data_string.encode()).hexdigest()
                    
                    if log_hash != recalculated_hash:
                        print(f"\n[TAMPERING DETECTED] at line {line_number}!")
                        print("Reason: Log content does not match its hash.")
                        return

                    # 3. Verify the Signature (Authenticity)
                    try:
                        public_key.verify(
                            bytes.fromhex(signature_hex),
                            log_hash.encode(),
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
                        )
                    except InvalidSignature:
                        print(f"\n[TAMPERING DETECTED] at line {line_number}!")
                        print("Reason: Invalid digital signature.")
                        return
                    
                    # If all checks pass, update the previous_hash for the next loop
                    previous_hash = log_hash
                    
                except (json.JSONDecodeError, KeyError) as e:
                    print(f"\n[VERIFY FAILED] Corrupt log entry at line {line_number}: {e}")
                    return

    except FileNotFoundError:
        print(f"[VERIFY FAILED] Log file not found at {log_file}.")
        return

    print(f"\n--- [VERIFICATION SUCCESSFUL] ---")
    print(f"Checked {line_number} entries. Log integrity and authenticity are confirmed.")

if __name__ == "__main__":
    verify_log_integrity()