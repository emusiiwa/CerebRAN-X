# libraries
import os
import json
import time
import pandas as pd
import numpy as np
from tqdm import tqdm
from scipy.sparse import csr_matrix, save_npz

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_all_report_paths(base_folders):
    """
    Collects all report.json file paths from multiple base folders.
    """
    all_report_paths = []
    
    for base_folder in base_folders:
        if not os.path.exists(base_folder):
            print("Warning: Folder does not exist: {}".format(base_folder))
            continue
        
        print("\nScanning folder: {}".format(base_folder))
        
        try:
            subdirs = [d for d in os.listdir(base_folder) 
                      if os.path.isdir(os.path.join(base_folder, d))]
            
            for subdir in subdirs:
                if subdir.isdigit():
                    report_path = os.path.join(base_folder, subdir, "reports", "report.json")
                    
                    if os.path.exists(report_path):
                        sample_id = int(subdir)
                        all_report_paths.append((sample_id, report_path))
            
            print("  Found {} analysis folders".format(len([d for d in subdirs if d.isdigit()])))
            print("  Found {} valid report.json files".format(len([p for sid, p in all_report_paths if base_folder in p])))
        
        except Exception as e:
            print("Error scanning {}: {}".format(base_folder, e))
    
    return all_report_paths

def load_vocabulary(vocab_file='feature_vocab.json'):
    """
    Load vocabulary from JSON file.
    """
    print("\nLoading vocabulary from: {}".format(vocab_file))
    
    if not os.path.exists(vocab_file):
        raise FileNotFoundError("Vocabulary file not found: {}".format(vocab_file))
    
    with open(vocab_file, 'r') as f:
        vocabulary = json.load(f)
    
    print("  Loaded {} features".format(len(vocabulary)))
    
    return vocabulary

# ============================================================================
# FEATURE EXTRACTION (must match vocabulary builder)
# ============================================================================

def extract_api_features(report):
    features = set()
    apistats = report.get('behavior', {}).get('apistats', {})
    for api_dict in apistats.values():
        for api in api_dict.keys():
            features.add("API:{}".format(api))
    return features

def extract_registry_pattern_features(report):
    import re
    features = set()
    behavior_summary = report.get('behavior', {}).get('summary', {})
    
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
        if regkeys:
            features.add("REG:{}:count".format(operation.upper()))
        for pattern_name, pattern_regex in REGISTRY_PATTERNS.items():
            count = sum(1 for key in regkeys if re.search(pattern_regex, key, re.I))
            if count > 0:
                features.add("REG:{}:{}".format(operation.upper(), pattern_name))
    
    return features

def extract_directory_pattern_features(report):
    import re
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
        if directories:
            features.add("DIR:{}:count".format(operation.upper()))
        for pattern_name, pattern_regex in DIRECTORY_PATTERNS.items():
            count = sum(1 for d in directories if re.search(pattern_regex, d, re.I))
            if count > 0:
                features.add("DIR:{}:{}".format(operation.upper(), pattern_name))
    
    return features

def extract_string_pattern_features(report):
    import re
    features = set()
    strings = report.get('strings', [])
    
    if not strings:
        return features
    
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
            features.add("STRING:{}".format(pattern_name))
            features.add("STRING:{}_count".format(pattern_name))
    
    features.add("STRING:total_count")
    features.add("STRING:avg_length")
    
    return features

def extract_network_aggregated_features(report):
    try:
        import ipaddress
    except ImportError:
        pass
    
    features = set()
    behavior_summary = report.get('behavior', {}).get('summary', {})
    
    ips = behavior_summary.get('connects_ip', [])
    hosts = behavior_summary.get('connects_host', [])
    resolved = behavior_summary.get('resolves_host', [])
    
    if ips:
        features.add('NET:connects_ip_count')
        features.add('NET:unique_ips')
    if hosts:
        features.add('NET:connects_host_count')
        features.add('NET:unique_hosts')
    if resolved:
        features.add('NET:resolves_host_count')
    
    try:
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
    except:
        pass
    
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.onion', '.bit']
    for host in hosts:
        if any(host.endswith(tld) for tld in suspicious_tlds):
            features.add('NET:suspicious_tld')
            break
    
    if ips or hosts:
        features.add('NET:has_network_activity')
    
    return features

def extract_system_pattern_features(report):
    import re
    features = set()
    behavior_summary = report.get('behavior', {}).get('summary', {})
    
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
                    features.add('SYS:dll_{}'.format(category))
                    break
    
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
                    features.add('SYS:cmd_{}'.format(pattern_name))
                    break
    
    mutexes = behavior_summary.get('mutex', [])
    if mutexes:
        features.add('SYS:mutex_count')
        for m in mutexes:
            if re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', m, re.I):
                features.add('SYS:mutex_has_guid')
                break
    
    guids = behavior_summary.get('guid', [])
    if guids:
        features.add('SYS:guid_count')
    
    return features

def extract_dropped_file_features(report):
    features = set()
    dropped_files = report.get('dropped', [])
    
    if not dropped_files:
        return features
    
    features.add('DROP:has_dropped_files')
    features.add('DROP:total_count')
    
    ransom_note_extensions = {'.txt', '.html', '.htm', '.readme', '.instructions'}
    executable_extensions = {'.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js'}
    
    for file_info in dropped_files:
        file_name = file_info.get('name', '').lower()
        
        if '.' in file_name:
            ext = '.' + file_name.split('.')[-1]
            features.add("DROP:EXTENSION:{}".format(ext))
            
            if ext in ransom_note_extensions:
                features.add('DROP:has_ransom_note')
            if ext in executable_extensions:
                features.add('DROP:has_executable')
        
        file_type = file_info.get('type', '')
        if file_type:
            features.add("DROP:TYPE:{}".format(file_type.replace(' ', '_').lower()))
    
    return features

def extract_signature_features(report):
    features = set()
    signatures = report.get('signatures', [])
    
    if not signatures:
        return features
    
    features.add('SIG:total_count')
    
    for sig in signatures:
        sig_name = sig.get('name', '').lower()
        features.add("SIGNATURE:{}".format(sig_name))
        
        severity = sig.get('severity', 0)
        if severity >= 3:
            features.add('SIG:has_high_severity')
    
    return features

def extract_all_features_from_report(report_path):
    """
    Extract all aggregated features from a single report.
    """
    try:
        with open(report_path, 'r') as f:
            report = json.load(f)
    except (IOError, ValueError) as e:
        print("Error reading {}: {}".format(report_path, e))
        return set()
    
    all_features = set()
    all_features.update(extract_api_features(report))
    all_features.update(extract_registry_pattern_features(report))
    all_features.update(extract_directory_pattern_features(report))
    all_features.update(extract_string_pattern_features(report))
    all_features.update(extract_network_aggregated_features(report))
    all_features.update(extract_system_pattern_features(report))
    all_features.update(extract_dropped_file_features(report))
    all_features.update(extract_signature_features(report))
    
    return all_features

# ============================================================================
# ONE-HOT ENCODING
# ============================================================================

def create_onehot_matrix(report_path_map, vocabulary):
    """
    Create one-hot encoded matrix using vocabulary.
    
    Returns:
        DataFrame with sample_id as first column, features as remaining columns
    """
    print("\n" + "="*80)
    print("CREATING ONE-HOT ENCODED MATRIX")
    print("="*80)
    print("Samples: {}".format(len(report_path_map)))
    print("Features: {}".format(len(vocabulary)))
    print("Matrix size: {} x {}".format(len(report_path_map), len(vocabulary)))
    
    # Create vocabulary index for fast lookup
    vocab_index = {feature: idx for idx, feature in enumerate(vocabulary)}
    
    # Initialize matrix with zeros
    sample_ids = sorted(report_path_map.keys())
    matrix = np.zeros((len(sample_ids), len(vocabulary)), dtype=np.int8)
    
    # Fill matrix
    print("\nEncoding samples...")
    for row_idx, sample_id in enumerate(tqdm(sample_ids, desc="One-hot encoding", unit="sample")):
        report_path = report_path_map[sample_id]
        
        # Extract features for this sample
        sample_features = extract_all_features_from_report(report_path)
        
        # Set 1 for features that exist
        for feature in sample_features:
            if feature in vocab_index:
                col_idx = vocab_index[feature]
                matrix[row_idx, col_idx] = 1
    
    # Create DataFrame with sample_id as FIRST COLUMN (not index)
    df = pd.DataFrame(matrix, columns=vocabulary)
    df.insert(0, 'sample_id', sample_ids)
    
    print("\n✓ Matrix created successfully")
    print("  Shape: {}".format(df.shape))
    print("  Memory usage: {:.2f} MB".format(df.memory_usage(deep=True).sum() / 1024 / 1024))
    
    return df

# ============================================================================
# SAVE IN MULTIPLE FORMATS
# ============================================================================

def save_all_formats(df, output_dir='output'):
    """
    Save DataFrame in multiple formats: CSV, Excel, Parquet, Sparse
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    print("\n" + "="*80)
    print("SAVING IN MULTIPLE FORMATS")
    print("="*80)
    
    # Extract sample_ids and features for metadata
    sample_ids = df['sample_id'].tolist()
    feature_names = df.columns[1:].tolist()  # Skip sample_id column
    feature_matrix = df.iloc[:, 1:].values  # Skip sample_id column
    
    # 1. Save as CSV
    print("\n[1/4] Saving CSV format...")
    csv_start = time.time()
    csv_path = os.path.join(output_dir, 'features_aggregated.csv')
    df.to_csv(csv_path, index=False)
    csv_time = time.time() - csv_start
    csv_size = os.path.getsize(csv_path) / (1024 * 1024)
    print("  ✓ Saved: {}".format(csv_path))
    print("    Size: {:.2f} MB".format(csv_size))
    print("    Time: {:.2f} seconds".format(csv_time))
    
    # 2. Save as Excel
    print("\n[2/4] Saving Excel format...")
    excel_start = time.time()
    excel_path = os.path.join(output_dir, 'features_aggregated.xlsx')
    
    # Check column limit
    if len(df.columns) > 16384:
        print("  ⚠ WARNING: Too many columns ({}) for Excel (limit: 16,384)".format(len(df.columns)))
        print("  ✗ Skipping Excel format")
        excel_time = 0
        excel_size = 0
    else:
        try:
            df.to_excel(excel_path, index=False, engine='openpyxl')
            excel_time = time.time() - excel_start
            excel_size = os.path.getsize(excel_path) / (1024 * 1024)
            print("  ✓ Saved: {}".format(excel_path))
            print("    Size: {:.2f} MB".format(excel_size))
            print("    Time: {:.2f} seconds".format(excel_time))
        except Exception as e:
            print("  ✗ Error saving Excel: {}".format(e))
            excel_time = 0
            excel_size = 0
    
    # 3. Save as Parquet
    print("\n[3/4] Saving Parquet format...")
    parquet_start = time.time()
    parquet_path = os.path.join(output_dir, 'features_aggregated.parquet')
    df.to_parquet(parquet_path, compression='gzip', index=False)
    parquet_time = time.time() - parquet_start
    parquet_size = os.path.getsize(parquet_path) / (1024 * 1024)
    print("  ✓ Saved: {}".format(parquet_path))
    print("    Size: {:.2f} MB".format(parquet_size))
    print("    Time: {:.2f} seconds".format(parquet_time))
    
    # 4. Save as Sparse Matrix
    print("\n[4/4] Saving Sparse Matrix format...")
    sparse_start = time.time()
    
    # Convert to sparse
    sparse_matrix = csr_matrix(feature_matrix)
    sparse_path = os.path.join(output_dir, 'features_sparse.npz')
    save_npz(sparse_path, sparse_matrix)
    
    # Save metadata
    feature_names_path = os.path.join(output_dir, 'feature_names.json')
    with open(feature_names_path, 'w') as f:
        json.dump(feature_names, f, indent=2)
    
    sample_ids_path = os.path.join(output_dir, 'sample_ids.json')
    with open(sample_ids_path, 'w') as f:
        json.dump(sample_ids, f, indent=2)
    
    sparse_time = time.time() - sparse_start
    sparse_size = (os.path.getsize(sparse_path) + 
                   os.path.getsize(feature_names_path) + 
                   os.path.getsize(sample_ids_path)) / (1024 * 1024)
    
    print("  ✓ Saved: {}".format(sparse_path))
    print("  ✓ Saved: {}".format(feature_names_path))
    print("  ✓ Saved: {}".format(sample_ids_path))
    print("    Total size: {:.2f} MB".format(sparse_size))
    print("    Time: {:.2f} seconds".format(sparse_time))
    
    # Summary report
    report_path = os.path.join(output_dir, 'encoding_report.txt')
    with open(report_path, 'w') as f:
        f.write("="*80 + "\n")
        f.write("ONE-HOT ENCODING REPORT\n")
        f.write("="*80 + "\n\n")
        f.write("Dataset Information:\n")
        f.write("  Samples: {}\n".format(len(sample_ids)))
        f.write("  Features: {}\n".format(len(feature_names)))
        f.write("  Matrix size: {} x {}\n\n".format(len(sample_ids), len(feature_names)))
        f.write("Output Files:\n")
        f.write("  1. CSV:           {:.2f} MB ({:.2f}s)\n".format(csv_size, csv_time))
        if excel_size > 0:
            f.write("  2. Excel:         {:.2f} MB ({:.2f}s)\n".format(excel_size, excel_time))
        else:
            f.write("  2. Excel:         SKIPPED (too many columns)\n")
        f.write("  3. Parquet:       {:.2f} MB ({:.2f}s)\n".format(parquet_size, parquet_time))
        f.write("  4. Sparse Matrix: {:.2f} MB ({:.2f}s)\n\n".format(sparse_size, sparse_time))
        f.write("Compression Ratios:\n")
        f.write("  Parquet vs CSV: {:.1f}x smaller\n".format(csv_size / parquet_size if parquet_size > 0 else 0))
        f.write("  Sparse vs CSV:  {:.1f}x smaller\n".format(csv_size / sparse_size if sparse_size > 0 else 0))
    
    print("\n✓ Summary report saved: {}".format(report_path))
    
    return {
        'csv': {'path': csv_path, 'size_mb': csv_size, 'time_sec': csv_time},
        'excel': {'path': excel_path if excel_size > 0 else None, 'size_mb': excel_size, 'time_sec': excel_time},
        'parquet': {'path': parquet_path, 'size_mb': parquet_size, 'time_sec': parquet_time},
        'sparse': {'path': sparse_path, 'size_mb': sparse_size, 'time_sec': sparse_time}
    }

# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    # Start timing
    start_time = time.time()
    
    # Configuration
    base_folders = [
        "analysis_folder_X",
        "analysis_folder_Y"
    ]
    vocab_file = 'feature_vocab.json'  # Must be in same directory
    output_dir = 'dataset_output'
    
    print("="*80)
    print("CUCKOO ONE-HOT ENCODER - MULTI-FORMAT OUTPUT")
    print("="*80)
    print("System: Ubuntu 18.04")
    print("Working directory: {}".format(os.getcwd()))
    print("Start time: {}".format(time.strftime('%Y-%m-%d %H:%M:%S')))
    
    # Step 1: Load vocabulary
    print("\n" + "="*80)
    print("STEP 1: LOADING VOCABULARY")
    print("="*80)
    vocabulary = load_vocabulary(vocab_file)
    
    # Step 2: Collect report paths
    print("\n" + "="*80)
    print("STEP 2: COLLECTING REPORT PATHS")
    print("="*80)
    all_report_paths = get_all_report_paths(base_folders)
    
    if not all_report_paths:
        print("ERROR: No report.json files found!")
        exit(1)
    
    folder1_count = sum(1 for sid, path in all_report_paths if base_folders[0] in path)
    folder2_count = sum(1 for sid, path in all_report_paths if base_folders[1] in path)
    
    print("\n✓ Analysis folders found:")
    print("  Folder 1: {} folders".format(folder1_count))
    print("  Folder 2: {} folders".format(folder2_count))
    print("  TOTAL: {} folders".format(len(all_report_paths)))
    
    all_report_paths.sort(key=lambda x: x[0])
    report_path_map = {sample_id: path for sample_id, path in all_report_paths}
    
    # Step 3: Create one-hot encoded matrix
    print("\n" + "="*80)
    print("STEP 3: ONE-HOT ENCODING")
    print("="*80)
    encoding_start = time.time()
    df = create_onehot_matrix(report_path_map, vocabulary)
    encoding_time = time.time() - encoding_start
    
    # Step 4: Save in all formats
    print("\n" + "="*80)
    print("STEP 4: SAVING OUTPUTS")
    print("="*80)
    save_results = save_all_formats(df, output_dir)
    
    # Final summary
    total_time = time.time() - start_time
    
    print("\n" + "="*80)
    print("ENCODING COMPLETE!")
    print("="*80)
    print("\nTotal analysis folders processed: {}".format(len(all_report_paths)))
    print("  - From folder 1: {}".format(folder1_count))
    print("  - From folder 2: {}".format(folder2_count))
    print("\nMatrix dimensions:")
    print("  - Samples: {}".format(len(df)))
    print("  - Features: {}".format(len(vocabulary)))
    print("  - Total cells: {:,}".format(len(df) * len(vocabulary)))
    print("\nTime taken:")
    print("  - One-hot encoding: {:.2f} seconds ({:.2f} minutes)".format(encoding_time, encoding_time/60))
    print("  - Saving outputs: {:.2f} seconds".format(sum(r['time_sec'] for r in save_results.values())))
    print("  - Total execution: {:.2f} seconds ({:.2f} minutes)".format(total_time, total_time/60))
    print("\nOutput directory: {}".format(os.path.abspath(output_dir)))
    print("End time: {}".format(time.strftime('%Y-%m-%d %H:%M:%S')))
    print("="*80)