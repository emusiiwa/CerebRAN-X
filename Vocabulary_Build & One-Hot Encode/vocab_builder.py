# libraries
import os
import json
import pickle
import re
import time
from tqdm import tqdm
from collections import defaultdict
import ipaddress

# ============================================================================
# HELPER FUNCTIONS FOR MULTI-FOLDER PROCESSING
# ============================================================================

def get_all_report_paths(base_folders):
    """
    Collects all report.json file paths from multiple base folders.
    Each base folder contains analysis subdirectories (e.g., 1, 2, etc.)
    and each subdirectory contains a reports/report.json file.
    
    Args:
        base_folders: List of base folder paths
    
    Returns:
        List of tuples: (sample_id, full_path_to_report.json)
    """
    all_report_paths = []
    
    for base_folder in base_folders:
        if not os.path.exists(base_folder):
            print("Warning: Folder does not exist: {}".format(base_folder))
            continue
        
        print("\nScanning folder: {}".format(base_folder))
        
        # List all subdirectories in the base folder
        try:
            subdirs = [d for d in os.listdir(base_folder) 
                      if os.path.isdir(os.path.join(base_folder, d))]
            
            for subdir in subdirs:
                # Check if the subdirectory name is numeric (sample ID)
                if subdir.isdigit():
                    report_path = os.path.join(base_folder, subdir, "reports", "report.json")
                    
                    # Check if report.json exists
                    if os.path.exists(report_path):
                        sample_id = int(subdir)
                        all_report_paths.append((sample_id, report_path))
            
            print("  Found {} analysis folders".format(len([d for d in subdirs if d.isdigit()])))
            print("  Found {} valid report.json files".format(len([p for sid, p in all_report_paths if base_folder in p])))
        
        except Exception as e:
            print("Error scanning {}: {}".format(base_folder, e))
    
    return all_report_paths

# ============================================================================
# FEATURE EXTRACTION WITH AGGREGATION/PATTERNS
# ============================================================================

def extract_api_features(report):
    """
    Extract API call features (binary presence).
    """
    features = set()
    apistats = report.get('behavior', {}).get('apistats', {})
    
    for api_dict in apistats.values():
        for api in api_dict.keys():
            features.add(f"API:{api}")
    
    return features

def extract_registry_pattern_features(report):
    """
    Extract registry patterns instead of individual keys.
    """
    features = set()
    behavior_summary = report.get('behavior', {}).get('summary', {})
    
    # Important registry patterns for malware detection
    REGISTRY_PATTERNS = {
        'run_keys': r'\\Run|\\RunOnce',
        'shadow_copy': r'\\VSS|ShadowCopy',
        'safeboot': r'\\SafeBoot',
        'crypto_keys': r'\\Cryptography|\\CryptnetUrlCache',
        'startup': r'\\Startup',
        'policies': r'\\Policies',
        'windows_defender': r'\\Windows Defender',
        'firewall': r'\\Firewall',
        'system': r'\\System\\CurrentControlSet',
        'software': r'\\Software\\Microsoft\\Windows',
    }
    
    operations = ['regkey_opened', 'regkey_deleted', 'regkey_read', 'regkey_written']
    
    for operation in operations:
        regkeys = behavior_summary.get(operation, [])
        
        # Count total operations
        if regkeys:
            features.add(f"REG:{operation.upper()}:count")
        
        # Check for patterns
        for pattern_name, pattern_regex in REGISTRY_PATTERNS.items():
            count = sum(1 for key in regkeys if re.search(pattern_regex, key, re.I))
            if count > 0:
                features.add(f"REG:{operation.upper()}:{pattern_name}")
    
    return features

def extract_directory_pattern_features(report):
    """
    Extract directory patterns instead of individual paths.
    """
    features = set()
    behavior_summary = report.get('behavior', {}).get('summary', {})
    
    DIRECTORY_PATTERNS = {
        'system_dirs': r'c:\\windows|c:\\program files',
        'user_docs': r'\\documents|\\desktop|\\downloads|\\pictures',
        'temp_dirs': r'\\temp|\\tmp',
        'appdata': r'\\appdata',
        'startup': r'\\startup',
        'program_data': r'\\programdata',
    }
    
    operations = ['directory_created', 'directory_enumerated']
    
    for operation in operations:
        directories = behavior_summary.get(operation, [])
        
        # Count total operations
        if directories:
            features.add(f"DIR:{operation.upper()}:count")
        
        # Check for patterns
        for pattern_name, pattern_regex in DIRECTORY_PATTERNS.items():
            count = sum(1 for d in directories if re.search(pattern_regex, d, re.I))
            if count > 0:
                features.add(f"DIR:{operation.upper()}:{pattern_name}")
    
    return features

def extract_string_pattern_features(report):
    """
    Extract string patterns instead of individual strings.
    """
    features = set()
    strings = report.get('strings', [])
    
    if not strings:
        return features
    
    # Pattern-based detection
    PATTERNS = {
        'bitcoin_address': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
        'onion_address': r'\b[a-z2-7]{16,56}\.onion\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'url_http': r'https?://[^\s]+',
        'url_ftp': r'ftp://[^\s]+',
        'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'ransom_keywords': r'\b(decrypt|ransom|bitcoin|payment|restore|locked|encrypted|recover)\b',
        'crypto_terms': r'\b(aes|rsa|key|cipher|encrypt)\b',
        'file_extension': r'\.\w{2,4}$',
    }
    
    for pattern_name, pattern_regex in PATTERNS.items():
        count = sum(1 for s in strings if re.search(pattern_regex, s, re.I))
        if count > 0:
            features.add(f"STRING:{pattern_name}")
            features.add(f"STRING:{pattern_name}_count")
    
    # String characteristics
    features.add(f"STRING:total_count")
    features.add(f"STRING:avg_length")
    
    return features

def extract_network_aggregated_features(report):
    """
    Extract aggregated network metrics instead of individual IPs/hosts.
    """
    features = set()
    behavior_summary = report.get('behavior', {}).get('summary', {})
    
    ips = behavior_summary.get('connects_ip', [])
    hosts = behavior_summary.get('connects_host', [])
    resolved = behavior_summary.get('resolves_host', [])
    
    # Connection counts
    if ips:
        features.add('NET:connects_ip_count')
        features.add('NET:unique_ips')
    
    if hosts:
        features.add('NET:connects_host_count')
        features.add('NET:unique_hosts')
    
    if resolved:
        features.add('NET:resolves_host_count')
    
    # IP analysis
    private_ips = 0
    public_ips = 0
    for ip in ips:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                private_ips += 1
            else:
                public_ips += 1
        except ValueError:
            pass
    
    if private_ips > 0:
        features.add('NET:has_private_ip')
    if public_ips > 0:
        features.add('NET:has_public_ip')
    
    # Suspicious TLD patterns
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.onion', '.bit']
    for host in hosts:
        if any(host.endswith(tld) for tld in suspicious_tlds):
            features.add('NET:suspicious_tld')
            break
    
    # Network activity indicator
    if ips or hosts:
        features.add('NET:has_network_activity')
    
    return features

def extract_system_pattern_features(report):
    """
    Extract system operation patterns.
    """
    features = set()
    behavior_summary = report.get('behavior', {}).get('summary', {})
    
    # DLL Analysis
    dlls = behavior_summary.get('dll_loaded', [])
    if dlls:
        features.add('SYS:dll_count')
        
        suspicious_dlls = {
            'crypto': ['advapi32.dll', 'bcrypt.dll', 'cryptsp.dll', 'rsaenh.dll'],
            'network': ['ws2_32.dll', 'wininet.dll', 'urlmon.dll', 'winhttp.dll'],
            'process': ['kernel32.dll', 'ntdll.dll', 'psapi.dll'],
        }
        
        dlls_lower = [dll.lower() for dll in dlls]
        for category, dll_list in suspicious_dlls.items():
            for dll in dll_list:
                if dll in dlls_lower:
                    features.add(f'SYS:dll_{category}')
                    break
    
    # Command Line Analysis
    cmd_lines = behavior_summary.get('command_line', [])
    if cmd_lines:
        features.add('SYS:cmd_count')
        
        suspicious_patterns = {
            'vssadmin_delete': r'vssadmin.*delete.*shadows',
            'bcdedit': r'bcdedit.*recoveryenabled.*no',
            'wbadmin_delete': r'wbadmin.*delete.*catalog',
            'cipher': r'cipher\s+/w',
            'powershell': r'powershell',
            'reg_modify': r'reg\s+(add|delete)',
            'schtasks': r'schtasks.*\/create',
            'icacls': r'icacls.*\/grant',
        }
        
        for pattern_name, pattern_regex in suspicious_patterns.items():
            for cmd in cmd_lines:
                if re.search(pattern_regex, cmd, re.I):
                    features.add(f'SYS:cmd_{pattern_name}')
                    break
    
    # Mutex Analysis
    mutexes = behavior_summary.get('mutex', [])
    if mutexes:
        features.add('SYS:mutex_count')
        
        # Check for GUID-like mutexes
        for m in mutexes:
            if re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', m, re.I):
                features.add('SYS:mutex_has_guid')
                break
    
    # GUID Analysis
    guids = behavior_summary.get('guid', [])
    if guids:
        features.add('SYS:guid_count')
    
    return features

def extract_dropped_file_features(report):
    """
    Extract dropped file extensions and types.
    """
    features = set()
    dropped_files = report.get('dropped', [])
    
    if not dropped_files:
        return features
    
    features.add('DROP:has_dropped_files')
    features.add('DROP:total_count')
    
    # Ransom note indicators
    ransom_note_extensions = {'.txt', '.html', '.htm', '.readme', '.instructions'}
    executable_extensions = {'.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js'}
    
    for file_info in dropped_files:
        file_name = file_info.get('name', '').lower()
        
        if '.' in file_name:
            ext = '.' + file_name.split('.')[-1]
            
            # Keep specific extensions as features
            features.add(f"DROP:EXTENSION:{ext}")
            
            if ext in ransom_note_extensions:
                features.add('DROP:has_ransom_note')
            
            if ext in executable_extensions:
                features.add('DROP:has_executable')
        
        # File type
        file_type = file_info.get('type', '')
        if file_type:
            features.add(f"DROP:TYPE:{file_type.replace(' ', '_').lower()}")
    
    return features

def extract_signature_features(report):
    """
    Extract signature features (already aggregated by Cuckoo).
    """
    features = set()
    signatures = report.get('signatures', [])
    
    if not signatures:
        return features
    
    features.add('SIG:total_count')
    
    for sig in signatures:
        sig_name = sig.get('name', '').lower()
        features.add(f"SIGNATURE:{sig_name}")
        
        # Also track severity if available
        severity = sig.get('severity', 0)
        if severity >= 3:
            features.add('SIG:has_high_severity')
    
    return features

# ============================================================================
# MAIN VOCABULARY BUILDER
# ============================================================================

def extract_all_features_from_report(report_path):
    """
    Extract all aggregated/pattern-based features from a single report.
    """
    try:
        with open(report_path, 'r') as f:
            report = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error reading {report_path}: {e}")
        return set()
    
    all_features = set()
    
    # Extract from each category
    all_features.update(extract_api_features(report))
    all_features.update(extract_registry_pattern_features(report))
    all_features.update(extract_directory_pattern_features(report))
    all_features.update(extract_string_pattern_features(report))
    all_features.update(extract_network_aggregated_features(report))
    all_features.update(extract_system_pattern_features(report))
    all_features.update(extract_dropped_file_features(report))
    all_features.update(extract_signature_features(report))
    
    return all_features

def build_vocabulary(report_path_map):
    """
    Build vocabulary of all unique features across all samples.
    
    Args:
        report_path_map: Dictionary mapping sample_id -> report_path
    
    Returns:
        vocabulary: Set of all unique feature names
        feature_stats: Dictionary with statistics about feature categories
    """
    print("\n" + "="*80)
    print("BUILDING FEATURE VOCABULARY")
    print("="*80)
    
    vocabulary = set()
    feature_stats = defaultdict(int)
    
    for sample_id, report_path in tqdm(sorted(report_path_map.items()), 
                                       desc="Building vocabulary", 
                                       unit="report"):
        features = extract_all_features_from_report(report_path)
        vocabulary.update(features)
        
        # Track statistics by category
        for feature in features:
            category = feature.split(':')[0]
            feature_stats[category] += 1
    
    print("\n" + "="*80)
    print("VOCABULARY STATISTICS")
    print("="*80)
    print(f"Total unique features: {len(vocabulary)}")
    print(f"Total samples processed: {len(report_path_map)}")
    print("\nFeatures by category:")
    for category in sorted(feature_stats.keys()):
        category_features = [f for f in vocabulary if f.startswith(category + ':')]
        print(f"  {category:15s}: {len(category_features):5d} unique features")
    print("="*80)
    
    return vocabulary, feature_stats

def save_vocabulary(vocabulary, output_file='feature_vocab.json'):
    """
    Save vocabulary to a JSON file.
    
    Args:
        vocabulary: Set of feature names
        output_file: Path to output JSON file
    """
    # Convert set to sorted list for consistent ordering
    vocab_list = sorted(list(vocabulary))
    
    with open(output_file, 'w') as f:
        json.dump(vocab_list, f, indent=2)
    
    print(f"\n✓ Vocabulary saved to: {output_file}")
    print(f"  Total features: {len(vocab_list)}")
    print(f"  File size: {os.path.getsize(output_file) / 1024:.2f} KB")

def load_vocabulary(input_file='feature_vocab.json'):
    """
    Load vocabulary from a JSON file.
    
    Args:
        input_file: Path to vocabulary JSON file
    
    Returns:
        vocabulary: List of feature names
    """
    with open(input_file, 'r') as f:
        vocabulary = json.load(f)
    
    print(f"✓ Vocabulary loaded from: {input_file}")
    print(f"  Total features: {len(vocabulary)}")
    
    return vocabulary

# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    # Start timing
    start_time = time.time()
    
    # Define the two base folders containing Cuckoo analysis results
    base_folders = [
        "analysis_folder_X",
        "analysis_folder_Y"
    ]
    
    print("="*80)
    print("CUCKOO FEATURE VOCABULARY BUILDER")
    print("="*80)
    print(f"System: Ubuntu 18.04")
    print(f"Working directory: {os.getcwd()}")
    print(f"Start time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Collect all report paths from both folders
    print("\nStep 1: Collecting report paths from all folders...")
    all_report_paths = get_all_report_paths(base_folders)
    
    if not all_report_paths:
        print("ERROR: No report.json files found in the specified folders!")
        exit(1)
    
    # Count analysis folders per base folder
    folder1_count = sum(1 for sid, path in all_report_paths if base_folders[0] in path)
    folder2_count = sum(1 for sid, path in all_report_paths if base_folders[1] in path)
    
    print(f"\n✓ Analysis folders scanned:")
    print(f"  Folder 1 ({base_folders[0]}): {folder1_count} folders")
    print(f"  Folder 2 ({base_folders[1]}): {folder2_count} folders")
    print(f"  TOTAL: {len(all_report_paths)} analysis folders")
    
    # Sort by sample_id
    all_report_paths.sort(key=lambda x: x[0])
    
    # Create dictionary mapping sample_id to report path
    report_path_map = {sample_id: path for sample_id, path in all_report_paths}
    
    # Build vocabulary
    print("\nStep 2: Building vocabulary from all reports...")
    vocab_start = time.time()
    vocabulary, feature_stats = build_vocabulary(report_path_map)
    vocab_time = time.time() - vocab_start
    
    # Save vocabulary
    print("\nStep 3: Saving vocabulary...")
    output_file = os.path.join(os.getcwd(), 'feature_vocab.json')
    save_vocabulary(vocabulary, output_file=output_file)
    
    # Calculate total time
    total_time = time.time() - start_time
    
    print("\n" + "="*80)
    print("VOCABULARY BUILDING COMPLETE!")
    print("="*80)
    print(f"\nTotal analysis folders traversed: {len(all_report_paths)}")
    print(f"  - From folder 1: {folder1_count}")
    print(f"  - From folder 2: {folder2_count}")
    print(f"\nTime taken:")
    print(f"  - Vocabulary building: {vocab_time:.2f} seconds ({vocab_time/60:.2f} minutes)")
    print(f"  - Total execution time: {total_time:.2f} seconds ({total_time/60:.2f} minutes)")
    print(f"\nGenerated file:")
    print(f"  {output_file}")
    print(f"\nEnd time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)