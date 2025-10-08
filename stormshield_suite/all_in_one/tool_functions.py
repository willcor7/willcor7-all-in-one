import os
import getpass
import pandas as pd
import paramiko
import configparser
import re
import time
import sys

# A helper function to get user input with a default value from config
def get_input(prompt, default=""):
    """Prompts the user for input, showing a default value."""
    return input(f"{prompt} [default: {default}]: ") or default

def _process_logs_logic(input_path, output_csv_path, output_summary_path):
    """
    Processes firewall log files to deduplicate entries and generate summaries.
    This is the refactored core logic from the original script.
    """
    # Step 1: Load data
    if os.path.isdir(input_path):
        print(f"Input path is a directory: {input_path}")
        input_files = [os.path.join(input_path, f) for f in os.listdir(input_path) if f.endswith('.csv')]
        if not input_files:
            print("Error: No CSV files found in the directory.")
            return None
        df_list = [pd.read_csv(f, on_bad_lines='skip', encoding_errors='ignore', low_memory=False) for f in input_files]
        df = pd.concat(df_list, ignore_index=True)
    elif os.path.isfile(input_path):
        print(f"Input path is a single file: {input_path}")
        df = pd.read_csv(input_path, on_bad_lines='skip', encoding_errors='ignore', low_memory=False)
    else:
        print(f"Error: Input path {input_path} is not a valid file or directory.")
        return None

    print(f"Successfully loaded {len(df)} total rows.")

    # Step 2: Clean and convert columns
    required_cols = ['srcname', 'dstname', 'dstportname', 'time', 'rcvd', 'sent']
    if not all(col in df.columns for col in required_cols):
        print(f"Error: Input data must contain the following columns: {required_cols}")
        return None

    df['time'] = pd.to_datetime(df['time'], errors='coerce')
    df['rcvd'] = pd.to_numeric(df['rcvd'], errors='coerce').fillna(0)
    df['sent'] = pd.to_numeric(df['sent'], errors='coerce').fillna(0)
    df.dropna(subset=['srcname', 'dstname', 'dstportname', 'time'], inplace=True)

    # Step 3: Sort and aggregate
    df.sort_values('time', ascending=True, inplace=True)
    group_keys = ['srcname', 'dstname', 'dstportname']
    agg_dict = {'time': ['min', 'max'], 'rcvd': 'sum', 'sent': 'sum'}
    first_cols = {col: 'first' for col in df.columns if col not in group_keys and col not in agg_dict}
    agg_dict.update(first_cols)
    aggregated_df = df.groupby(group_keys).agg(agg_dict)
    aggregated_df.columns = ['_'.join(col).strip() for col in aggregated_df.columns.values]
    aggregated_df.rename(columns={'time_min': 'min_time', 'time_max': 'max_time', 'rcvd_sum': 'total_rcvd', 'sent_sum': 'total_sent'}, inplace=True)
    aggregated_df['count'] = df.groupby(group_keys).size().values

    # Reorder columns
    output_cols = group_keys + ['count', 'min_time', 'max_time', 'total_rcvd', 'total_sent']
    other_cols = [col for col in aggregated_df.columns if col not in output_cols]
    aggregated_df = aggregated_df.reset_index()[output_cols + sorted(other_cols)]

    # Step 4: Write outputs
    aggregated_df.to_csv(output_csv_path, index=False)
    print(f"Cleaned data with {len(aggregated_df)} unique flows written to {output_csv_path}")

    # Step 5: Generate summary
    aggregated_df['total_traffic'] = aggregated_df['total_rcvd'] + aggregated_df['total_sent']
    top_10_by_count = aggregated_df.sort_values('count', ascending=False).head(10)
    with open(output_summary_path, 'w') as f:
        f.write("Firewall Log Analysis Summary\n" + "="*30 + "\n")
        f.write(f"Total rows processed: {len(df)}\n")
        f.write(f"Total unique flows identified: {len(aggregated_df)}\n\n")
        f.write("Top 10 Flows by Count:\n" + "-"*25 + "\n")
        f.write(top_10_by_count[['srcname', 'dstname', 'dstportname', 'count']].to_string(index=False))
        f.write("\n")
    print(f"Summary report written to {output_summary_path}")
    return top_10_by_count

def analyze_logs(config):
    """
    Orchestrates the log analysis process.
    """
    # Get paths from config or user input
    default_log_path = config.get('Paths', 'log_file_path', fallback="")
    log_path = get_input(f"Enter the path to the log file or directory", default_log_path)

    if not os.path.exists(log_path):
        print(f"Error: The path '{log_path}' does not exist.")
        return

    # Define output paths using os.path.join for compatibility
    output_dir = config.get('Paths', 'output_dir')
    output_csv_path = os.path.join(output_dir, 'analyzed_logs.csv')
    output_summary_path = os.path.join(output_dir, 'analysis_summary.txt')

    # Run the analysis
    top_flows = _process_logs_logic(log_path, output_csv_path, output_summary_path)

    # Smart feature: Suggest creating a rule
    if top_flows is not None and not top_flows.empty:
        print("\n--- Rule Creation Suggestion ---")
        print("Based on the analysis, here are the top traffic flows:")
        print(top_flows[['srcname', 'dstname', 'dstportname', 'count']].to_string(index=False))

        create_rule = input("\nWould you like to create a new firewall rule based on these flows? (yes/no): ").lower()
        if create_rule == 'yes':
            print("\n--- Create a New Rule ---")
            print("This feature will append the new rule to a CSV file.")

            # This part will be more fleshed out when convert_rules is integrated
            # For now, it's a simplified version.
            try:
                # Get rule details from user
                src = get_input("Enter the source object name (e.g., from 'srcname' column)")
                dst = get_input("Enter the destination object name (e.g., from 'dstname' column)")
                port = get_input("Enter the service/port name (e.g., from 'dstportname' column)")
                action = get_input("Enter the action (pass/block)", "pass")

                # Get the rules file path
                default_rules_path = config.get('Paths', 'rules_csv_path', fallback=os.path.join(output_dir, 'rules.csv'))
                rules_file = get_input("Enter the path to your rules CSV file", default_rules_path)

                # Create a DataFrame for the new rule
                new_rule = pd.DataFrame({
                    'Source': [src], 'Destination': [dst], 'Service': [port], 'Action': [action]
                })

                # Append to the CSV file
                if os.path.exists(rules_file):
                    new_rule.to_csv(rules_file, mode='a', header=False, index=False)
                    print(f"Successfully appended the new rule to {rules_file}")
                else:
                    new_rule.to_csv(rules_file, mode='w', header=True, index=False)
                    print(f"Successfully created {rules_file} with the new rule.")

            except Exception as e:
                print(f"An error occurred while creating the rule: {e}")

def _execute_command_interactive(channel, command):
    """Executes a command in an interactive shell and returns the output."""
    channel.send(command + '\n')
    time.sleep(3)  # Wait for the command to execute
    output = ""
    while channel.recv_ready():
        output += channel.recv(65535).decode('utf-8', errors='ignore')
    # Clean up the output to remove the command echo and prompt
    lines = output.splitlines()
    return "\n".join(lines[1:-1]) if len(lines) > 2 else ""

def _export_logic(host, user, password, output_dir):
    """Connects to the firewall and exports configuration."""
    client = None
    try:
        print(f"Connecting to {host} as {user}...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, username=user, password=password, port=22, timeout=15)
        print("SSH connection successful.")

        # Use a timestamp for unique filenames
        timestamp = time.strftime('%Y%m%d_%H%M%S')

        def save_output(basename, content):
            filename = f"export_{basename}_{timestamp}.txt"
            filepath = os.path.join(output_dir, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"   -> Output saved to '{filepath}'")

        print("\n--- Exporting 'CONFIG' data ---")
        channel = client.invoke_shell()
        time.sleep(1)
        channel.recv(65535)  # Clear initial banner
        channel.send('cli\n')
        time.sleep(1)
        channel.send(password + '\n')
        time.sleep(2)
        channel.recv(65535) # Clear the response after entering password
        print("Entered 'cli' mode.")

        print("-> Exporting objects and interfaces...")
        save_output("objects", _execute_command_interactive(channel, "CONFIG OBJECT LIST type=all usage=any"))
        save_output("interfaces", _execute_command_interactive(channel, "CONFIG NETWORK INTERFACE SHOW"))

        channel.close()
        return True

    except paramiko.AuthenticationException:
        print("Authentication failed. Please check your username and password.", file=sys.stderr)
        return False
    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
        return False
    finally:
        if client:
            client.close()
            print("\nSSH connection closed.")

def export_config(config):
    """Orchestrates the firewall configuration export."""
    host = get_input("Enter the firewall IP address", config.get('Exporter', 'firewall_ip', fallback=""))
    user = get_input("Enter the firewall username", config.get('Exporter', 'firewall_user', fallback="admin"))

    if not host or not user:
        print("Error: Firewall IP and username are required.")
        return

    # Securely get password
    password = config.get('Exporter', 'firewall_password', fallback="")
    if not password:
        password = getpass.getpass(f"Enter password for {user}@{host}: ")

    # Get the output directory from config
    output_dir = config.get('Paths', 'reference_dir')
    os.makedirs(output_dir, exist_ok=True) # Ensure it exists
    print(f"Files will be saved in: '{output_dir}'")

    if _export_logic(host, user, password, output_dir):
        print("\nExport completed successfully.")
    else:
        print("\nExport failed.")

import unicodedata
import csv
import time
from pathlib import Path

# --- Constants from converter.py ---
MAX_NSRPC_LINE = 1024
ALLOWED_ACTIONS = {"pass", "block", "drop", "bypass", "deleg", "reset", "log", "decrypt", "nat"}
CSV_TO_NSRPC_MAP = {
    "rule_name": "rulename", "comment": "comment", "state": "state", "action": "action",
    "service": "service", "log_level": "loglevel", "schedule": "schedule",
    "from_src": "srctarget", "from_if": "srcif", "to_dest": "dsttarget", "to_if": "dstif",
    "nat_from_target": "natsrctarget", "nat_to_target": "natdsttarget", "nat_to_port": "natdstport"
}
CSV_ALIASES = {
    "service": ["service", "to_port", "dstport"], "from_src": ["from_src", "source"],
    "to_dest": ["to_dest", "destination"], "nat_from_target": ["nat_from_target", "natsrctarget"],
    "nat_to_target": ["nat_to_target", "natdsttarget"], "nat_to_port": ["nat_to_port", "natdstport"],
}
VALID_FILTER_TOKENS = {
    "rulename", "comment", "state", "action", "inspection", "service", "loglevel",
    "schedule", "srctarget", "srcif", "dsttarget", "dstif"
}

# --- Helper functions from converter.py, adapted for integration ---

def _parse_dependency_file(file_path: str) -> set:
    """Parses object or interface files to get a set of names."""
    if not file_path or not os.path.exists(file_path):
        return set()
    names = set()
    name_re = re.compile(r'name="([^"]+)"')
    ifname_re = re.compile(r'ifname=("[^"]+"|\S+)')
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            match = name_re.search(line) or ifname_re.search(line)
            if match:
                names.add(match.group(1).strip('"'))
    print(f"Loaded {len(names)} names from {os.path.basename(file_path)}.")
    return names

def _read_csv_rules(path: str) -> list:
    """Reads rules from a CSV file, normalizing header keys to lowercase."""
    if not path or not os.path.exists(path):
        print(f"Error: CSV file not found at {path}")
        return []
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f, delimiter=';')
        # Normalize keys to lowercase for consistent, case-insensitive access
        normalized_rows = []
        for row in reader:
            # Ensure key is not None before calling lower() and strip()
            if row: # Handle empty rows
                normalized_row = {k.lower().strip(): v for k, v in row.items() if k}
                normalized_rows.append(normalized_row)
        return normalized_rows

def _format_nsrpc_param(value: str) -> str:
    """Formats a value for an NSRPC command."""
    clean_val = value.strip()
    is_simple = re.match(r'^[a-zA-Z0-9_.-]+$', clean_val) is not None
    if clean_val.lower() == 'any' or is_simple:
        return clean_val
    return f'"{clean_val.replace("\"", r"\"")}"'

def _pick(row: dict, keys: list) -> str:
    """Picks the first non-empty value from a row using a list of possible keys."""
    for k in keys:
        if k in row and row[k]:
            return row[k].strip()
    return ""

def _find_missing_dependencies(row: dict, known_objects: set, known_interfaces: set) -> list:
    """Checks a rule for missing objects or interfaces."""
    missing = []
    all_known = known_objects.union(known_interfaces)
    object_fields = ["from_src", "to_dest", "service", "nat_from_target", "nat_to_target", "nat_to_port"]
    for field in object_fields:
        val = _pick(row, CSV_ALIASES.get(field, [field]))
        if val and val.lower() != 'any':
            for name in [n.strip() for n in val.split(',')]:
                if name and name not in all_known:
                    missing.append(("OBJECT", name))

    if_fields = ["from_if", "to_if"]
    for field in if_fields:
        val = _pick(row, [field])
        if val and val.lower() != 'any':
            if val not in known_interfaces:
                missing.append(("INTERFACE", val))
    return list(set(missing))

def _build_rule_cmd(row: dict, position: int) -> tuple:
    """Builds a single FILTER or NAT NSRPC command."""
    is_nat = _pick(row, ["action"]) == "nat"
    rule_type = "nat" if is_nat else "filter"
    parts = ["CONFIG FILTER RULE INSERT", f"type={rule_type}", f"position={position}"]
    if is_nat:
        parts.append("action=nat")

    # Map CSV fields to NSRPC tokens
    for csv_key, nsrpc_token in CSV_TO_NSRPC_MAP.items():
        if is_nat and nsrpc_token not in VALID_FILTER_TOKENS and 'nat' not in nsrpc_token:
             continue
        aliases = CSV_ALIASES.get(csv_key, [csv_key])
        value = _pick(row, aliases)
        if value:
            parts.append(f"{nsrpc_token}={_format_nsrpc_param(value)}")

    cmd = " ".join(parts)
    return (cmd, None) if len(cmd) <= MAX_NSRPC_LINE else (None, "Generated command is too long")

def _find_latest_ref_file(directory: str, keyword: str) -> str:
    """Finds the most recent file in a directory containing a specific keyword."""
    try:
        files = [os.path.join(directory, f) for f in os.listdir(directory) if keyword in f and os.path.isfile(os.path.join(directory, f))]
        if not files:
            return ""
        # Return the file with the latest modification time
        return max(files, key=os.path.getmtime)
    except FileNotFoundError:
        return ""

def convert_rules(config):
    """Orchestrates the CSV to NSRPC conversion process."""
    print("This tool converts a CSV file of firewall rules into NSRPC commands.")

    # --- Get Inputs ---
    default_csv = config.get('Paths', 'rules_csv_path', fallback="")
    csv_path = get_input("Enter the path to your rules CSV file", default_csv)
    if not os.path.exists(csv_path):
        print(f"Error: File not found: {csv_path}")
        return

    ref_dir = config.get('Paths', 'reference_dir')
    # Dynamically find the latest object and interface files
    latest_obj_file = _find_latest_ref_file(ref_dir, "objects")
    latest_if_file = _find_latest_ref_file(ref_dir, "interfaces")

    obj_file = get_input("Enter path to the objects file (or press Enter to skip validation)", latest_obj_file)
    if_file = get_input("Enter path to the interfaces file (or press Enter to skip validation)", latest_if_file)

    # --- Load Dependencies ---
    known_objects = _parse_dependency_file(obj_file)
    known_interfaces = _parse_dependency_file(if_file)

    # --- Process Rules ---
    rules = _read_csv_rules(csv_path)
    if not rules:
        print("No rules found in the CSV file.")
        return

    safe_commands, pending_rules, missing_deps = [], [], set()
    position = 1
    for i, row in enumerate(rules):
        missing = _find_missing_dependencies(row, known_objects, known_interfaces)
        cmd, err = _build_rule_cmd(row, position)

        if not missing and cmd:
            safe_commands.append(cmd)
            position += 1
        else:
            reason = ", ".join([f"{t}:{n}" for t, n in missing]) if missing else err
            pending_rules.append(f"# Rule from row {i+2} is PENDING. Reason: {reason}\n# Data: {row}\n")
            if missing:
                missing_deps.update(missing)

    # --- Write Output Files ---
    output_dir = config.get('Paths', 'output_dir')

    # Safe rules
    safe_path = os.path.join(output_dir, "rules_safe.txt")
    with open(safe_path, 'w', encoding='utf-8') as f:
        f.write(f"# Generated on {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Source CSV: {csv_path}\n\n")
        f.write("\n".join(safe_commands))
        f.write("\n\nCONFIG FILTER ACTIVATE\n")

    print(f"\nProcessing complete.")
    print(f"  - {len(safe_commands)} safe rules written to: {safe_path}")

    # Pending rules and dependencies
    if pending_rules:
        pending_path = os.path.join(output_dir, "rules_pending.txt")
        with open(pending_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(pending_rules))
        print(f"  - {len(pending_rules)} pending rules written to: {pending_path}")

        deps_path = os.path.join(output_dir, "dependencies_missing.txt")
        with open(deps_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(sorted([f"{t}: {n}" for t, n in missing_deps])))
        print(f"  - {len(missing_deps)} missing dependencies listed in: {deps_path}")

def _find_missing_rules_logic(source_rules, final_rules):
    """Identifies rules present in source but missing in final."""
    # Create a set of unique identifiers for the final rules for quick lookup
    final_rule_ids = set()
    for rule in final_rules:
        # A unique ID is a tuple of the core components of a rule
        rule_id = (
            _pick(rule, CSV_ALIASES.get('from_src', ['from_src'])),
            _pick(rule, CSV_ALIASES.get('to_dest', ['to_dest'])),
            _pick(rule, CSV_ALIASES.get('service', ['service'])),
            _pick(rule, ['action']),
        )
        final_rule_ids.add(rule_id)

    missing_rules = []
    seen_source_ids = set()
    for rule in source_rules:
        rule_id = (
            _pick(rule, CSV_ALIASES.get('from_src', ['from_src'])),
            _pick(rule, CSV_ALIASES.get('to_dest', ['to_dest'])),
            _pick(rule, CSV_ALIASES.get('service', ['service'])),
            _pick(rule, ['action']),
        )
        # Check if the rule is missing and we haven't already added it
        if rule_id not in final_rule_ids and rule_id not in seen_source_ids:
            missing_rules.append(rule)
            seen_source_ids.add(rule_id)

    return missing_rules

def compare_rules(config):
    """Orchestrates the rule comparison process."""
    print("This tool compares a 'source' set of rules against a 'final' set and generates commands for any missing rules.")

    # --- Get Inputs ---
    source_csv_path_str = get_input("Enter the path(s) to your SOURCE CSV file(s) (comma-separated)", "")
    final_csv_path = get_input("Enter the path to your FINAL CSV file", config.get('Paths', 'rules_csv_path', fallback=""))

    source_paths = [p.strip() for p in source_csv_path_str.split(',') if p.strip()]
    if not source_paths or not final_csv_path:
        print("Error: You must provide at least one source CSV and one final CSV.")
        return

    # --- Load Rules ---
    source_rules, final_rules = [], []
    for path in source_paths:
        if os.path.exists(path):
            source_rules.extend(_read_csv_rules(path))
        else:
            print(f"Warning: Source file not found: {path}")

    if os.path.exists(final_csv_path):
        final_rules = _read_csv_rules(final_csv_path)
    else:
        print(f"Error: Final file not found: {final_csv_path}")
        return

    # --- Find Missing Rules and Generate Commands ---
    missing_rules = _find_missing_rules_logic(source_rules, final_rules)
    if not missing_rules:
        print("\nNo missing rules found. The final configuration already contains all source rules.")
        return

    print(f"\nFound {len(missing_rules)} missing rules. Generating commands...")

    cli_commands = []
    for i, rule in enumerate(missing_rules, start=1):
        cmd, err = _build_rule_cmd(rule, i)
        if cmd:
            cli_commands.append(cmd)
        else:
            print(f"Warning: Could not generate command for rule: {rule}. Reason: {err}")

    # --- Write Output ---
    if cli_commands:
        output_dir = config.get('Paths', 'output_dir')
        output_path = os.path.join(output_dir, "missing_rules_commands.txt")
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(f"# Generated on {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("# Commands to add rules that are missing from the final configuration.\n\n")
            f.write("\n".join(cli_commands))
        print(f"Successfully wrote {len(cli_commands)} commands to: {output_path}")

def _find_and_report_duplicates_logic(rows: list):
    """Analyzes rows, identifies duplicates, and prints a report."""
    seen_rules = {}

    for row in rows:
        # Create a normalized signature for the rule
        source = _pick(row, CSV_ALIASES.get("from_src", ["from_src"])) or "any"
        destination = _pick(row, CSV_ALIASES.get("to_dest", ["to_dest"])) or "any"
        service = _pick(row, CSV_ALIASES.get("service", ["service"])) or "any"
        action = _pick(row, ['action']) or "pass" # Default to pass if action is missing

        signature = (source, destination, service, action)

        # Store the occurrence details
        occurrence = {
            "file": row.get("source_file", "N/A"),
            "name": _pick(row, ["rule name", "rulename", "comment"]) or "Unnamed Rule"
        }
        seen_rules.setdefault(signature, []).append(occurrence)

    # Filter for duplicates and report them
    duplicates = {sig: occs for sig, occs in seen_rules.items() if len(occs) > 1}

    print("\n--- Duplicate Rules Report ---")
    if not duplicates:
        print("No duplicate rules were found.")
        return

    for sig, occs in duplicates.items():
        print(f"\n[DUPLICATE FOUND] - Signature: (Source: {sig[0]}, Destination: {sig[1]}, Service: {sig[2]}, Action: {sig[3]})")
        print(f"  This rule was found {len(occs)} times:")
        for occ in occs:
            print(f"  - In File: {occ['file']}, Rule Name: \"{occ['name']}\"")

def detect_duplicates(config):
    """Orchestrates the duplicate rule detection process."""
    print("This tool analyzes one or more CSV files to find duplicate rules based on Source, Destination, Service, and Action.")

    # Get user input for CSV files
    csv_path_str = get_input("Enter the path(s) to your CSV file(s) (comma-separated)", config.get('Paths', 'rules_csv_path', fallback=""))

    paths = [p.strip() for p in csv_path_str.split(',') if p.strip()]
    if not paths:
        print("Error: No CSV files provided.")
        return

    all_rows = []
    for path in paths:
        if os.path.exists(path):
            rows = _read_csv_rules(path)
            # Add source file information to each row for better reporting
            for row in rows:
                row['source_file'] = os.path.basename(path)
            all_rows.extend(rows)
        else:
            print(f"Warning: File not found and will be skipped: {path}")

    if not all_rows:
        print("Could not load any rules to analyze.")
        return

    _find_and_report_duplicates_logic(all_rows)