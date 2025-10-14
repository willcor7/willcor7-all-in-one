import os
import getpass
import pandas as pd
import paramiko
import configparser
import re
import time
import sys
import unicodedata
import csv
from pathlib import Path
from itertools import zip_longest
import datetime
from collections import Counter

# A helper function to get user input with a default value from config
def get_input(prompt, default=""):
    """Prompts the user for input, showing a default value."""
    return input(f"{prompt} [default: {default}]: ") or default

# --- Start of Converter Script Logic ---

# --- Constants ---
_CONVERTER_MAX_NSRPC_LINE = 1024
_CONVERTER_ALLOWED_ACTIONS = {"pass", "block", "drop", "bypass", "deleg", "reset", "log", "decrypt", "nat"}
_CONVERTER_CSV_TO_NSRPC_MAP = {
    "rule_name": "rulename", "comment": "comment", "state": "state", "action": "action",
    "count": "count", "rate": "rate", "set_tos": "settos", "inspection": "inspection",
    "service": "service", "log_level": "loglevel", "schedule": "schedule",
    "route": "route", "no_conn_log": "noconnlog", "tos": "tos", "ip_proto": "ipproto",
    "proto": "proto", "from_user_type": "srcusertype", "from_user_domain": "srcuserdomain",
    "from_user_method": "srcusermethod", "from_src": "srctarget", "from_geo": "srcgeo",
    "from_ip_rep": "srciprep", "from_host_rep": "srchostrep", "from_port": "srcport",
    "from_if": "srcif", "via": "via", "to_dest": "dsttarget", "to_geo": "dstgeo",
    "to_ip_rep": "dstiprep", "to_host_rep": "dsthostrep", "to_port": "dstport",
    "to_if": "dstif", "nat_before_vpn": "beforevpn", "nat_from_target": "natsrctarget",
    "nat_from_arp": "natsrcarp", "nat_from_port": "natsrcport",
    "nat_from_load_balancing": "natsrclb", "nat_to_target": "natdsttarget",
    "nat_to_arp": "natdstarp", "nat_to_port": "natdstport",
    "nat_to_load_balancing": "natdstlb",
}
_CONVERTER_CSV_ALIASES = {
    "rule_name": ["rule_name", "rulename", "rule name"],
    "service": ["service", "to_port", "dstport"], "from_src": ["from_src", "source"],
    "to_dest": ["to_dest", "destination"], "nat_from_target": ["nat_from_target", "natsrctarget"],
    "nat_to_target": ["nat_to_target", "natdsttarget"], "nat_to_port": ["nat_to_port", "natdstport"],
    "log_level": ["log_level", "loglevel"], "proto": ["proto", "ip_proto"],
}
VALID_FILTER_TOKENS = {
    "rulename", "comment", "state", "action", "inspection", "service", "loglevel",
    "schedule", "srctarget", "srcif", "dsttarget", "dstif"
}
_CONVERTER_VALID_FILTER_TOKENS = {
    "rulename", "comment", "state", "action", "count", "rate", "settos",
    "inspection", "service", "loglevel", "schedule", "route", "noconnlog",
    "tos", "ipproto", "proto", "srcusertype", "srcuserdomain", "srcusermethod",
    "srctarget", "srcgeo", "srciprep", "srchostrep", "srcport", "srcif", "via",
    "dsttarget", "dstgeo", "dstiprep", "dsthostrep", "dstport", "dstif"
}

# --- Helper Functions ---

def _converter_parse_objects_file(file_path: Path) -> set:
    if not file_path or not file_path.exists(): return set()
    names = set()
    name_re = re.compile(r'name="([^"]+)"')
    with file_path.open("r", encoding="utf-8") as f:
        for line in f:
            match = name_re.search(line)
            if match: names.add(match.group(1))
            else:
                clean_line = line.strip()
                if clean_line and not clean_line.startswith('#'): names.add(clean_line)
    print(f"[INFO] Loaded {len(names)} existing objects from {file_path.name}.")
    return names

def _converter_parse_interfaces_file(file_path: Path) -> set:
    if not file_path or not file_path.exists(): return set()
    names = set()
    ifname_re = re.compile(r'ifname=("[^"]+"|\S+)')
    name_re = re.compile(r'Name="([^"]+)"')
    with file_path.open("r", encoding="utf-8") as f:
        for line in f:
            clean_line = line.strip()
            ifname_match = ifname_re.search(clean_line)
            if ifname_match: names.add(ifname_match.group(1).strip('"')); continue
            name_match = name_re.search(clean_line)
            if name_match: names.add(name_match.group(1)); continue
            if clean_line and not clean_line.startswith(('#', '[')) and '=' not in clean_line: names.add(clean_line)
    print(f"[INFO] Loaded {len(names)} existing interfaces from {file_path.name}.")
    return names

def _converter_read_csv(path: Path) -> list:
    with path.open("r", encoding="utf-8-sig", newline="") as f: all_lines = f.readlines()
    header_line_content = None; header_line_index = -1
    for i, line in enumerate(all_lines):
        stripped = line.strip()
        if stripped: header_line_content = stripped.lstrip('#'); header_line_index = i; break
    if header_line_content is None: return []
    data_lines = [line for line in all_lines[header_line_index + 1:] if line.strip()]
    delim = ';' if ';' in header_line_content else ','
    original_headers = next(csv.reader([header_line_content], delimiter=delim))
    cleaned_headers = []
    counts = {}
    for h in original_headers:
        stripped_h = h.strip().lstrip('#').strip('"').lower()
        if stripped_h in counts: counts[stripped_h] += 1; cleaned_headers.append(f"{stripped_h}_{counts[stripped_h]}")
        else: counts[stripped_h] = 0; cleaned_headers.append(stripped_h)
    final_rows = []
    reader = csv.reader(data_lines, delimiter=delim)
    for fields in reader:
        if not any(field.strip() for field in fields): continue
        padded_fields = fields + [""] * (len(cleaned_headers) - len(fields))
        row_dict = dict(zip(cleaned_headers, padded_fields[:len(cleaned_headers)]))
        for key, value in row_dict.items(): row_dict[key] = value.strip().strip('"') if value is not None else ""
        final_rows.append(row_dict)
    return final_rows

def _converter_is_valid_host_ip(s: str) -> bool:
    return bool(re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$").match(s))

def _converter_generate_host_objects(rows: list) -> tuple:
    unique_ips = set()
    source_aliases = ["from_src", "source_ip", "src", "source", "src_ip"]
    dest_aliases = ["to_dest", "destination_ip", "dest_ip", "dst_ip", "destination"]
    natsrc_aliases = ["nat_from_target", "natsrctarget", "src_translation", "to_src"]
    natdest_aliases = ["nat_to_target", "natdsttarget", "dst_translation", "to_dst", "translated_ip", "to"]
    for row in rows:
        for aliases in [source_aliases, dest_aliases, natsrc_aliases, natdest_aliases]:
            ip_value = _converter_pick(row, aliases)
            if _converter_is_valid_host_ip(ip_value): unique_ips.add(ip_value)
    commands = []
    if unique_ips:
        commands.append("# --- Objets Hôtes ---")
        for ip in sorted(list(unique_ips)):
            object_name = f"H_{ip.replace('.', '_')}"
            commands.append(f'CONFIG OBJECT HOST NEW name={object_name} ip={ip} comment=""')
        commands.append("")
    return commands, unique_ips

def _converter_is_valid_ip_or_network(s: str) -> bool:
    ip_re = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
    cidr_re = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)/(?:[0-2]?\d|3[0-2])$")
    range_re = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)-(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
    return bool(ip_re.match(s) or cidr_re.match(s) or range_re.match(s))

def _converter_format_nsrpc_param(value: str) -> str:
    clean_val = "".join(c for c in unicodedata.normalize("NFKD", value) if not unicodedata.combining(c)).strip()
    if not clean_val: return '""'
    is_simple = re.match(r'^[a-zA-Z0-9_.-]+$', clean_val) is not None
    if clean_val.lower() == 'any' or _converter_is_valid_ip_or_network(clean_val) or is_simple: return clean_val
    else: return f'"{clean_val.replace("\"", r"\"")}"'

def _converter_pick(row: dict, keys: list) -> str:
    for k in keys:
        v = row.get(k, "").strip()
        if v: return v
    return ""

def _converter_coerce_action(val: str) -> str:
    v = (val or "").strip().lower()
    if v in _CONVERTER_ALLOWED_ACTIONS: return v
    return {"allow": "pass", "accept": "pass", "deny": "drop"}.get(v)

def _converter_find_missing_dependencies(row: dict, known_objects: set, known_interfaces: set, created_host_ips: set) -> list:
    missing = []
    all_known_names = known_objects.union(known_interfaces, {f"H_{ip.replace('.', '_')}" for ip in created_host_ips})
    object_fields = ["from_src", "to_dest", "service", "nat_from_target", "nat_to_target", "nat_to_port", "schedule", "route", "from_geo", "to_geo", "from_ip_rep", "to_ip_rep"]
    for field in object_fields:
        aliases = _CONVERTER_CSV_ALIASES.get(field, [field])
        val = _converter_pick(row, aliases)
        if val and val.lower() != 'any' and not _converter_is_valid_ip_or_network(val):
            for name in [name.strip() for name in val.split(',')]:
                if name and name not in all_known_names: missing.append(("OBJECT", name))
    if_fields = ["from_if", "to_if"]
    for field in if_fields:
        val = _converter_pick(row, [field])
        if val and val.lower() != 'any':
            for name in [name.strip() for name in val.split(',')]:
                if name and name not in known_interfaces: missing.append(("INTERFACE", name))
    return list(set(missing))

def _converter_classify_row(row: dict) -> str:
    if "nat" in _converter_pick(row, ["type_slot"]).lower(): return "NAT"
    if _converter_pick(row, ["action"]).lower() == "nat": return "NAT"
    if _converter_pick(row, ["nat_from_target"]) or _converter_pick(row, ["nat_to_target"]): return "NAT"
    return "FILTER"

def _converter_build_filter_cmd(row: dict, prefix: str, default_slot: int, position: int, created_host_ips: set = None) -> tuple:
    if created_host_ips is None: created_host_ips = set()
    parts = ["CONFIG FILTER RULE INSERT", f"index={int(_converter_pick(row, ['policy', 'slot', 'index']) or default_slot)}", "type=filter", f"position={position}"]
    rule_name = _converter_pick(row, _CONVERTER_CSV_ALIASES.get("rule_name", ["rule_name"]))
    comment = _converter_pick(row, _CONVERTER_CSV_ALIASES.get("comment", ["comment"]))
    if not rule_name: rule_name = comment if comment else f"FilterRule-{position:04d}"; comment = "" if rule_name == comment else comment
    if prefix: rule_name = f"{prefix}{rule_name}"
    rule_name = "".join(c for c in unicodedata.normalize("NFKD", rule_name.replace("\n", " ").strip()) if not unicodedata.combining(c))
    if len(rule_name) > 64: rule_name = rule_name[:61] + "..."
    if rule_name: parts.append(f"rulename={_converter_format_nsrpc_param(rule_name)}")
    if comment: parts.append(f"comment={_converter_format_nsrpc_param(comment)}")
    for csv_key, nsrpc_token in _CONVERTER_CSV_TO_NSRPC_MAP.items():
        if csv_key in ["rule_name", "comment"] or nsrpc_token not in _CONVERTER_VALID_FILTER_TOKENS: continue
        value = _converter_pick(row, _CONVERTER_CSV_ALIASES.get(csv_key, [csv_key]))
        if value:
            if nsrpc_token in ["srctarget", "dsttarget"] and value in created_host_ips: value = f"H_{value.replace('.', '_')}"
            if nsrpc_token == "action":
                value = _converter_coerce_action(value)
                if not value: return None, f"action de filtre inconnue: {_converter_pick(row, _CONVERTER_CSV_ALIASES.get(csv_key, [csv_key]))!r}"
            if nsrpc_token == "ipproto" and "," in value: value = value.split(',')[0]
            parts.append(f"{nsrpc_token}={_converter_format_nsrpc_param(value)}")
    cmd = " ".join(parts)
    return (cmd, None) if len(cmd) <= _CONVERTER_MAX_NSRPC_LINE else (None, "ligne NSRPC générée trop longue")

def _converter_build_nat_cmd(row: dict, prefix: str, default_slot: int, position: int, created_host_ips: set = None) -> tuple:
    if created_host_ips is None: created_host_ips = set()
    parts = ["CONFIG FILTER RULE INSERT", f"index={int(_converter_pick(row, ['policy', 'slot', 'index']) or default_slot)}", "type=nat", "action=nat", f"position={position}"]
    rule_name = _converter_pick(row, _CONVERTER_CSV_ALIASES.get("rule_name", ["rule_name"]))
    comment = _converter_pick(row, _CONVERTER_CSV_ALIASES.get("comment", ["comment"]))
    if not rule_name: rule_name = comment if comment else f"NatRule-{position:04d}"; comment = "" if rule_name == comment else comment
    if prefix: rule_name = f"{prefix}{rule_name}"
    rule_name = "".join(c for c in unicodedata.normalize("NFKD", rule_name.replace("\n", " ").strip()) if not unicodedata.combining(c))
    if len(rule_name) > 64: rule_name = rule_name[:61] + "..."
    if rule_name: parts.append(f"rulename={_converter_format_nsrpc_param(rule_name)}")
    if comment: parts.append(f"comment={_converter_format_nsrpc_param(comment)}")
    if 'dstport' not in row or not row['dstport']:
        service_val = _converter_pick(row, _CONVERTER_CSV_ALIASES.get('service', ['service']))
        if service_val: row['dstport'] = service_val
    for csv_key, nsrpc_token in _CONVERTER_CSV_TO_NSRPC_MAP.items():
        if csv_key in ["rule_name", "comment", "action", "service"]: continue
        value = _converter_pick(row, _CONVERTER_CSV_ALIASES.get(csv_key, [csv_key]))
        if value:
            if nsrpc_token in ["srctarget", "dsttarget", "natsrctarget", "natdsttarget"] and value in created_host_ips: value = f"H_{value.replace('.', '_')}"
            if nsrpc_token == "ipproto" and "," in value: value = value.split(',')[0]
            parts.append(f"{nsrpc_token}={_converter_format_nsrpc_param(value)}")
    cmd = " ".join(parts)
    return (cmd, None) if len(cmd) <= _CONVERTER_MAX_NSRPC_LINE else (None, "ligne NSRPC générée trop longue")

def _converter_write_safe_rules_file(out_path: Path, cmd_list: list, source_csv_paths: list, activate: bool, slot: int, group_by_10: bool = False):
    header = [f"# NSRPC generated on {datetime.datetime.now().isoformat(timespec='seconds')}", f"# Source CSVs: {', '.join(map(str, source_csv_paths))}", f"# Number of commands: {len(cmd_list)}", "SYSTEM SESSION language=fr", "MODIFY ON FORCE", f"CONFIG SLOT ACTIVATE type=filter slot={slot}"]
    with out_path.open("w", encoding="utf-8", newline="") as f:
        f.write("\n".join(header) + "\n\n")
        rule_count = 0
        for cmd in cmd_list:
            f.write(cmd + "\n")
            if cmd.strip() and not cmd.strip().startswith("#"):
                rule_count += 1
                if group_by_10 and rule_count > 0 and rule_count % 10 == 0: f.write("\n")
        if activate: f.write("\nCONFIG FILTER ACTIVATE\n")

def _converter_write_pending_rules_file(out_path: Path, pending_rules: list):
    warning_header = ["######################################################################", "# WARNING: PENDING RULES                                           #", "# ------------------------------------------------------------------ #", "# The commands in this file have MISSING DEPENDENCIES.               #", "# They are provided for debugging purposes and are LIKELY TO FAIL if #", "# executed directly on a firewall without first creating the       #", "# missing objects or interfaces.                                     #", "######################################################################", f"\n# Generated on: {datetime.datetime.now().isoformat(timespec='seconds')}\n"]
    with out_path.open("w", encoding="utf-8") as f: f.write("\n".join(warning_header)); f.write("\n".join(pending_rules))

def _converter_write_missing_dependencies_file(out_path: Path, missing_deps: set):
    header = f"# Missing dependencies found on {datetime.datetime.now().isoformat(timespec='seconds')}"
    with out_path.open("w", encoding="utf-8") as f:
        f.write(header + "\n\n")
        if not missing_deps: f.write("# No missing dependencies were found.\n")
        else:
            for dep_type, name in sorted(list(missing_deps)): f.write(f"{dep_type}: {name}\n")

def _find_latest_ref_file(directory: str, keyword: str) -> str:
    """Finds the most recent file in a directory containing a specific keyword."""
    try:
        files = [os.path.join(directory, f) for f in os.listdir(directory) if keyword in f and os.path.isfile(os.path.join(directory, f))]
        if not files:
            return ""
        return max(files, key=os.path.getmtime)
    except (FileNotFoundError, ValueError):
        return ""

# --- End of Converter Script Logic ---

def analyze_logs(config):
    """
    Orchestrates the log analysis process using the full implementation.
    """
    print("\n--- Analyze Firewall Logs ---")
    # Get paths from config or user input
    default_log_path = config.get('Paths', 'log_file_path', fallback="")
    log_path = get_input(f"Enter the path to the log file or directory", default_log_path)

    if not os.path.exists(log_path):
        print(f"Error: The path '{log_path}' does not exist.", file=sys.stderr)
        return

    # Define output paths using os.path.join for compatibility
    output_dir = config.get('Paths', 'output_dir')
    output_csv_path = os.path.join(output_dir, 'analyzed_logs.csv')
    output_summary_path = os.path.join(output_dir, 'analysis_summary.txt')

    # Run the analysis
    aggregated_df = _analyzer_process_logs(log_path, output_csv_path, output_summary_path)

    # Smart feature: Suggest creating a rule
    if aggregated_df is not None and not aggregated_df.empty:
        print("\n--- Rule Creation Suggestion ---")
        top_flows = aggregated_df.sort_values('count', ascending=False).head(10)
        print("Based on the analysis, here are the top 10 flows by count:")

        # Display numbered flows
        top_flows_display = top_flows[['srcname', 'dstname', 'dstportname', 'count']].copy()
        top_flows_display.index = range(1, len(top_flows_display) + 1)
        print(top_flows_display.to_string())

        while True:
            create_rule = input("\nWould you like to create a new firewall rule from this list? (yes/no): ").lower()
            if create_rule != 'yes':
                break

            selected_flow = None
            while True:
                try:
                    flow_choice = int(get_input("Enter the number of the flow to use for the rule", "1"))
                    if 1 <= flow_choice <= len(top_flows):
                        selected_flow = top_flows.iloc[flow_choice - 1]
                        break
                    else:
                        print("Invalid number. Please choose a number from the list.", file=sys.stderr)
                except ValueError:
                    print("Invalid input. Please enter a number.", file=sys.stderr)

            print("\n--- Create a New NSRPC Rule Command ---")
            print("This feature generates a CLI command and appends it to a file.")

            try:
                # --- Get validation files ---
                ref_dir = Path(config.get('Paths', 'reference_dir'))
                obj_file_path = get_input("Enter path to the objects file for validation (optional)", _find_latest_ref_file(str(ref_dir), "objects"))
                if_file_path = get_input("Enter path to the interfaces file for validation (optional)", _find_latest_ref_file(str(ref_dir), "interfaces"))

                known_objects = _converter_parse_objects_file(Path(obj_file_path)) if obj_file_path else set()
                known_interfaces = _converter_parse_interfaces_file(Path(if_file_path)) if if_file_path else set()

                # --- Get rule details from user ---
                rule_details = {
                    "from_src": get_input("Enter the source object name", selected_flow['srcname']),
                    "to_dest": get_input("Enter the destination object name", selected_flow['dstname']),
                    "service": get_input("Enter the service/port name", selected_flow['dstportname']),
                    "action": get_input("Enter the action (pass/block)", "pass"),
                    "comment": get_input("Enter a comment for the rule (optional)", f"Rule for {selected_flow['srcname']} to {selected_flow['dstname']}")
                }

                # --- Validate dependencies ---
                missing_deps = _converter_find_missing_dependencies(rule_details, known_objects, known_interfaces, set())
                if missing_deps:
                    print("\n[WARNING] Missing dependencies found:", file=sys.stderr)
                    for dep_type, name in missing_deps:
                        print(f"  - {dep_type}: {name}", file=sys.stderr)
                    if get_input("Continue anyway? (yes/no)", "no").lower() != 'yes':
                        print("Rule creation cancelled.")
                        continue # Go to the next iteration of the main loop

                # --- Get generation options ---
                slot = int(get_input("Enter the filter policy slot (index)", "9"))
                position = int(get_input("Enter the position for the new rule", "1"))

                # --- Build the command ---
                cmd, err = _converter_build_filter_cmd(rule_details, "", slot, position)

                if err:
                    print(f"\n[ERROR] Could not generate command: {err}", file=sys.stderr)
                    continue # Go to the next iteration of the main loop

                # --- Append command to file ---
                default_cli_path = os.path.join(output_dir, 'generated_rules_from_logs.txt')
                cli_file = get_input("Enter the path to your CLI output file", default_cli_path)

                with open(cli_file, 'a', encoding='utf-8') as f:
                    f.write(f"# Rule generated from log analysis on {datetime.datetime.now().isoformat(timespec='seconds')}\n")
                    f.write(cmd + "\n\n")

                print(f"\nSuccessfully appended NSRPC command to {cli_file}")
                print(f"Generated command:\n{cmd}")

            except Exception as e:
                print(f"An error occurred while creating the rule: {e}", file=sys.stderr)

def _analyzer_process_logs(input_path, output_csv_path, output_summary_path):
    """
    Processes firewall log files to deduplicate entries and generate summaries.
    This is the full, correct implementation.
    """
    # Step 1: Load data
    df = None
    if os.path.isdir(input_path):
        print(f"Input path is a directory: {input_path}")
        input_files = [os.path.join(input_path, f) for f in os.listdir(input_path) if f.endswith('.csv')]
        if not input_files:
            print("Error: No CSV files found in the directory.", file=sys.stderr)
            return None
        df_list = []
        for f in input_files:
            try:
                df_temp = pd.read_csv(f, on_bad_lines='skip', encoding_errors='ignore', low_memory=False)
                df_list.append(df_temp)
            except Exception as e:
                print(f"Error reading {f}: {e}", file=sys.stderr)
        if not df_list:
            print("Error: No valid CSV files could be processed.", file=sys.stderr)
            return None
        df = pd.concat(df_list, ignore_index=True)
    elif os.path.isfile(input_path):
        print(f"Input path is a single file: {input_path}")
        try:
            df = pd.read_csv(input_path, on_bad_lines='skip', encoding_errors='ignore', low_memory=False)
        except Exception as e:
            print(f"Error reading {input_path}: {e}", file=sys.stderr)
            return None
    else:
        print(f"Error: Input path {input_path} is not a valid file or directory.", file=sys.stderr)
        return None

    print(f"Successfully loaded {len(df)} total rows.")

    # Step 2: Clean and convert columns
    required_cols = ['srcname', 'dstname', 'dstportname', 'time', 'rcvd', 'sent']
    for col in required_cols:
        if col not in df.columns:
            print(f"Error: Required column '{col}' not found in the input data.", file=sys.stderr)
            return None

    df['time'] = pd.to_datetime(df['time'], errors='coerce')
    df['rcvd'] = pd.to_numeric(df['rcvd'], errors='coerce').fillna(0)
    df['sent'] = pd.to_numeric(df['sent'], errors='coerce').fillna(0)
    df.dropna(subset=['srcname', 'dstname', 'dstportname', 'time'], inplace=True)

    # Step 3: Sort by time and aggregate
    df.sort_values('time', ascending=True, inplace=True)
    group_keys = ['srcname', 'dstname', 'dstportname']
    agg_dict = {'time': ['min', 'max'], 'rcvd': 'sum', 'sent': 'sum'}
    first_cols = {col: 'first' for col in df.columns if col not in group_keys and col not in agg_dict}
    agg_dict.update(first_cols)
    aggregated_df = df.groupby(group_keys).agg(agg_dict)

    # Step 4: Clean up aggregated dataframe
    aggregated_df.columns = ['_'.join(col).strip() for col in aggregated_df.columns.values]
    aggregated_df.rename(columns={'time_min': 'min_time', 'time_max': 'max_time', 'rcvd_sum': 'total_rcvd', 'sent_sum': 'total_sent'}, inplace=True)
    aggregated_df['count'] = df.groupby(group_keys).size().values

    output_cols = group_keys + ['count', 'min_time', 'max_time', 'total_rcvd', 'total_sent']
    other_cols = [col for col in aggregated_df.columns if col not in output_cols]
    final_cols = output_cols + sorted(other_cols)
    aggregated_df = aggregated_df.reset_index()[final_cols]

    # Step 5: Write cleaned data to CSV
    aggregated_df.to_csv(output_csv_path, index=False)
    print(f"Cleaned data with {len(aggregated_df)} unique flows written to {output_csv_path}")

    # Step 6: Generate and write summary report
    total_processed = len(df)
    unique_flows = len(aggregated_df)
    aggregated_df['total_traffic'] = aggregated_df['total_rcvd'] + aggregated_df['total_sent']
    top_10_by_count = aggregated_df.sort_values('count', ascending=False).head(10)
    top_10_by_traffic = aggregated_df.sort_values('total_traffic', ascending=False).head(10)

    with open(output_summary_path, 'w') as f:
        f.write("Firewall Log Analysis Summary\n" + "="*30 + "\n")
        f.write(f"Total rows processed: {total_processed}\n")
        f.write(f"Total unique flows identified: {unique_flows}\n\n")
        f.write("Top 10 Flows by Count:\n" + "-"*25 + "\n")
        f.write(top_10_by_count[['srcname', 'dstname', 'dstportname', 'count']].to_string(index=False))
        f.write("\n\n")
        f.write("Top 10 Flows by Total Traffic (Received + Sent):\n" + "-"*50 + "\n")
        f.write(top_10_by_traffic[['srcname', 'dstname', 'dstportname', 'total_traffic', 'total_rcvd', 'total_sent']].to_string(index=False))
        f.write("\n")

    print(f"Summary report written to {output_summary_path}")
    return aggregated_df

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

def convert_rules(config):
    """Orchestrates the CSV to NSRPC conversion process with a user-friendly interface."""
    print("\n--- Convert Rules from CSV to CLI ---")
    print("This tool converts Stormshield CSV rule exports into NSRPC command scripts with dependency validation.")

    # --- Get User Inputs ---
    csv_paths_str = get_input("Enter path(s) to your input CSV file(s) (comma-separated)", config.get('Paths', 'rules_csv_path', fallback=""))
    if not csv_paths_str:
        print("Error: No input CSV files provided.")
        return
    csv_paths = [Path(p.strip()) for p in csv_paths_str.split(',') if p.strip()]

    ref_dir = Path(config.get('Paths', 'reference_dir'))
    obj_file_path = get_input("Enter path to the objects file for validation (optional)", _find_latest_ref_file(str(ref_dir), "objects"))
    if_file_path = get_input("Enter path to the interfaces file for validation (optional)", _find_latest_ref_file(str(ref_dir), "interfaces"))

    print("\n--- Rule Generation Options ---")
    prefix = get_input("Enter a prefix to prepend to rule names (optional)", "")
    slot = int(get_input("Enter the default filter policy slot (index)", "9"))
    start_pos = int(get_input("Enter the starting position for new rules", "1"))
    create_hosts = get_input("Automatically create host objects for IPs? (yes/no)", "no").lower() == 'yes'
    activate = get_input("Append 'CONFIG FILTER ACTIVATE' to the script? (yes/no)", "yes").lower() == 'yes'
    group_by_10 = get_input("Add a blank line every 10 rules for readability? (yes/no)", "yes").lower() == 'yes'

    # --- Setup ---
    output_dir = Path(config.get('Paths', 'output_dir'))
    output_dir.mkdir(parents=True, exist_ok=True)

    known_objects = _converter_parse_objects_file(Path(obj_file_path)) if obj_file_path else set()
    known_interfaces = _converter_parse_interfaces_file(Path(if_file_path)) if if_file_path else set()

    # --- Read and Interleave Rows ---
    all_rows = []
    for path in csv_paths:
        if not path.exists():
            print(f"[ERROR] CSV file not found: {path}", file=sys.stderr)
            continue
        try:
            rows = _converter_read_csv(path)
            all_rows.extend(rows)
            print(f"[INFO] Read {len(rows)} rows from {path.name}")
        except Exception as e:
            print(f"[ERROR] Failed to read CSV {path.name}: {e}", file=sys.stderr)

    # --- Process Rules ---
    safe_commands, pending_rules, all_missing_dependencies = [], [], set()
    created_host_ips = set()
    if create_hosts:
        host_commands, created_host_ips = _converter_generate_host_objects(all_rows)
        safe_commands.extend(host_commands)
        if host_commands: print(f"[INFO] {len(created_host_ips)} unique Host objects will be created.")

    current_position = start_pos
    for i, row in enumerate(all_rows):
        if _converter_pick(row, ["separator_color"]): continue

        rtype = _converter_classify_row(row)
        cmd, err = None, None
        if rtype == "NAT":
            cmd, err = _converter_build_nat_cmd(row, prefix, slot, current_position, created_host_ips)
        else:
            cmd, err = _converter_build_filter_cmd(row, prefix, slot, current_position, created_host_ips)

        missing = _converter_find_missing_dependencies(row, known_objects, known_interfaces, created_host_ips)

        if not missing and cmd:
            safe_commands.append(cmd)
            current_position += 1
        else:
            reasons = ", ".join([f"{t}:{n}" for t, n in sorted(list(set(missing)))])
            if cmd:
                pending_rules.append(f"# PENDING: Missing dependencies: {reasons}\n{cmd}\n")
            else:
                build_error = f"Build error: {err or 'unknown'}"
                missing_error = f"Missing: {reasons}" if reasons else ""
                pending_rules.append(f"# PENDING: Rule from row {i+1} could not be processed.\n# {missing_error} {build_error}\n# Original data: {row}\n")
            all_missing_dependencies.update(missing)

    # --- Write Output Files ---
    out_safe_path = output_dir / "rules_safe.txt"
    _converter_write_safe_rules_file(out_safe_path, safe_commands, [p.name for p in csv_paths], activate, slot, group_by_10)

    num_safe_rules = len([c for c in safe_commands if c.strip() and not c.strip().startswith("#")])
    summary = (
        f"\n[INFO] Processing complete.\n"
        f"  - Total lines read from CSV: {len(all_rows)}\n"
        f"  - Safe commands generated: {num_safe_rules}\n"
        f"  - Pending or ignored rules: {len(pending_rules)}\n"
        f"  - Unique missing dependencies found: {len(all_missing_dependencies)}"
    )
    print(summary)
    print(f"\n[INFO] Safe rules file created: {out_safe_path}")

    if pending_rules:
        out_pending_path = output_dir / "rules_pending.txt"
        _converter_write_pending_rules_file(out_pending_path, pending_rules)
        print(f"[INFO] Pending rules file created: {out_pending_path}")

    if all_missing_dependencies:
        out_missing_path = output_dir / "dependencies_missing.txt"
        _converter_write_missing_dependencies_file(out_missing_path, all_missing_dependencies)
        print(f"[INFO] Missing dependencies file created: {out_missing_path}")

def _find_missing_rules_logic(source_rules, final_rules):
    """Identifies rules present in source but missing in final."""
    # Create a set of unique identifiers for the final rules for quick lookup
    final_rule_ids = set()
    for rule in final_rules:
        # A unique ID is a tuple of the core components of a rule
        rule_id = (
            _converter_pick(rule, _CONVERTER_CSV_ALIASES.get('from_src', ['from_src'])),
            _converter_pick(rule, _CONVERTER_CSV_ALIASES.get('to_dest', ['to_dest'])),
            _converter_pick(rule, _CONVERTER_CSV_ALIASES.get('service', ['service'])),
            _converter_pick(rule, ['action']),
        )
        final_rule_ids.add(rule_id)

    missing_rules = []
    seen_source_ids = set()
    for rule in source_rules:
        rule_id = (
            _converter_pick(rule, _CONVERTER_CSV_ALIASES.get('from_src', ['from_src'])),
            _converter_pick(rule, _CONVERTER_CSV_ALIASES.get('to_dest', ['to_dest'])),
            _converter_pick(rule, _CONVERTER_CSV_ALIASES.get('service', ['service'])),
            _converter_pick(rule, ['action']),
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
    for path_str in source_paths:
        path = Path(path_str)
        if path.exists():
            source_rules.extend(_converter_read_csv(path))
        else:
            print(f"Warning: Source file not found: {path}")

    final_path = Path(final_csv_path)
    if final_path.exists():
        final_rules = _converter_read_csv(final_path)
    else:
        print(f"Error: Final file not found: {final_path}")
        return

    # --- Find Missing Rules and Generate Commands ---
    missing_rules = _find_missing_rules_logic(source_rules, final_rules)
    if not missing_rules:
        print("\nNo missing rules found. The final configuration already contains all source rules.")
        return

    print(f"\nFound {len(missing_rules)} missing rules. Generating commands...")

    # --- Get generation options for missing rules ---
    slot = int(get_input("Enter the filter policy slot for missing rules", "9"))
    start_pos = int(get_input("Enter the starting position for missing rules", "1"))

    cli_commands = []
    for i, rule in enumerate(missing_rules, start=start_pos):
        cmd, err = _converter_build_filter_cmd(rule, "MissingRule-", slot, i)
        if cmd:
            cli_commands.append(cmd)
        else:
            print(f"Warning: Could not generate command for rule: {rule}. Reason: {err}")

    # --- Write Output ---
    if cli_commands:
        output_dir = config.get('Paths', 'output_dir')

        # --- Write CLI commands file ---
        output_path = os.path.join(output_dir, "missing_rules_commands.txt")
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(f"# Generated on {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# {len(cli_commands)} commands to add rules that are missing from the final configuration.\n\n")
            for i, cmd in enumerate(cli_commands):
                f.write(cmd + "\n")
                if (i + 1) % 10 == 0:
                    f.write("\n")
        print(f"Successfully wrote {len(cli_commands)} commands to: {output_path}")

        # --- Write summary file ---
        summary_path = os.path.join(output_dir, "missing_rules_summary.csv")
        try:
            missing_rules_df = pd.DataFrame(missing_rules)
            summary_cols = ['rule_name', 'from_src', 'to_dest', 'service', 'action', 'comment']
            existing_cols = [col for col in summary_cols if col in missing_rules_df.columns]
            if existing_cols:
                missing_rules_df[existing_cols].to_csv(summary_path, index=False, sep=';')
                print(f"Successfully wrote summary of {len(missing_rules_df)} missing rules to: {summary_path}")
            else:
                print("No relevant columns found to create a summary file.")
        except Exception as e:
            print(f"Could not write summary file: {e}", file=sys.stderr)

def _duplicator_normalize_field(value: str) -> str:
    """
    Normalizes a field that may contain multiple objects separated by commas or semicolons.
    Sorts the objects to make the signature order-independent.
    """
    if not isinstance(value, str) or not value.strip():
        return ""
    components = [comp.strip() for comp in re.split(r'[,;]', value) if comp.strip()]
    if len(components) > 1:
        components.sort()
        return ",".join(components)
    return value.strip()

def _duplicator_find_duplicates(rows: list, debug: bool = False) -> dict:
    """Analyzes rows and returns a dictionary of found duplicates."""
    if debug:
        print("\n--- DEBUG: GENERATED SIGNATURES ---")
    seen_rules = {}
    for row in rows:
        if not _converter_pick(row, ["action", "from_src", "to_dest"]):
            continue
        source = _duplicator_normalize_field(_converter_pick(row, _CONVERTER_CSV_ALIASES.get("from_src", ["from_src"]))) or "any"
        destination = _duplicator_normalize_field(_converter_pick(row, _CONVERTER_CSV_ALIASES.get("to_dest", ["to_dest"]))) or "any"
        dest_port = _duplicator_normalize_field(_converter_pick(row, _CONVERTER_CSV_ALIASES.get("service", ["service"]))) or "any"
        protocol = _converter_pick(row, _CONVERTER_CSV_ALIASES.get("proto", ["proto"])) or "any"
        action = _converter_pick(row, ["action"]) or "any"
        signature = (source, destination, dest_port, protocol, action)
        if debug:
            line_num = row.get('original_line', 'N/A')
            print(f"Ligne {line_num}: Signature = {signature}")
        occurrence = {
            "file": row.get("source_file", "N/A"),
            "line": row.get("original_line", "N/A"),
            "name": _converter_pick(row, ["rule_name"]) or "Sans nom",
            "nat_line": row.get("nat_line")
        }
        seen_rules.setdefault(signature, []).append(occurrence)
    return {sig: occs for sig, occs in seen_rules.items() if len(occs) > 1}

def _duplicator_format_as_markdown(duplicates: dict, report_type: str = 'rules') -> str:
    """Formats a dictionary of duplicates into a multi-section Markdown report."""
    if not duplicates:
        return "No duplicates detected."
    report_lines = []
    is_nat_report = report_type == 'nat'
    sorted_signatures = sorted(duplicates.keys(), key=lambda sig: (duplicates[sig][0]['file'], duplicates[sig][0]['line']))
    for sig in sorted_signatures:
        occs = duplicates[sig]
        source, dest, port, proto, action = sig
        header_title = f"### Duplicate - Signature: (Source: `{source}`, Destination: `{dest}`, Port: `{port}`, Protocol: `{proto}`, Action: `{action}`)"
        report_lines.append(header_title)
        report_lines.append("")
        if is_nat_report:
            table_header = "| File | Line (File) | Line (NAT) | Rule Name |"
            table_separator = "|---|---|---|---|"
        else:
            table_header = "| File | Line | Rule Name |"
            table_separator = "|---|---|---|"
        report_lines.append(table_header)
        report_lines.append(table_separator)
        sort_key = 'nat_line' if is_nat_report else 'line'
        sorted_occs = sorted(occs, key=lambda x: (x['file'], x.get(sort_key, 0)))
        for occ in sorted_occs:
            file = f"`{occ['file']}`"
            line = f"`{occ['line']}`"
            name = f"`{occ['name']}`"
            if is_nat_report:
                nat_line_val = f"`{occ.get('nat_line', 'N/A')}`"
                report_lines.append(f"| {file} | {line} | {nat_line_val} | {name} |")
            else:
                report_lines.append(f"| {file} | {line} | {name} |")
        if sig != sorted_signatures[-1]:
            report_lines.append("\n---\n")
    return "\n".join(report_lines)

def _duplicator_generate_delete_script(duplicates: dict, report_type: str, index: int, is_global: bool) -> list:
    """Generates a list of Stormshield CLI commands to delete duplicate rules."""
    commands = []
    rule_type = 'nat' if report_type == 'nat' else 'filter'
    global_param = " global=1" if is_global else ""
    sorted_signatures = sorted(duplicates.keys(), key=lambda sig: (duplicates[sig][0]['file'], duplicates[sig][0]['line']))
    for sig in sorted_signatures:
        occs = duplicates[sig]
        sort_key = 'nat_line' if report_type == 'nat' else 'line'
        sorted_occs = sorted(occs, key=lambda x: (x['file'], x.get(sort_key, 0)))
        name_counts = Counter(occ['name'] for occ in sorted_occs)
        for occ_to_delete in sorted_occs[1:]:
            rule_name = occ_to_delete.get('name')
            command = None
            if report_type == 'nat':
                if rule_name and rule_name != "Sans nom":
                    command = f'CONFIG FILTER RULE REMOVE index={index} type={rule_type} name="{rule_name}"{global_param}'
            else:
                use_position = not rule_name or rule_name == "Sans nom" or name_counts[rule_name] > 1
                if use_position:
                    position = occ_to_delete.get('line')
                    command = f'CONFIG FILTER RULE REMOVE index={index} type={rule_type} position={position}{global_param}'
                else:
                    command = f'CONFIG FILTER RULE REMOVE index={index} type={rule_type} name="{rule_name}"{global_param}'
            if command:
                commands.append(command)
    return commands

def detect_duplicates(config):
    """Orchestrates the duplicate rule detection process."""
    print("This tool analyzes CSV files to find duplicate filter and NAT rules.")
    csv_paths_str = get_input("Enter path(s) to your input CSV file(s) (comma-separated)", config.get('Paths', 'rules_csv_path', fallback=""))
    if not csv_paths_str:
        print("Error: No input CSV files provided.")
        return
    csv_paths = [Path(p.strip()) for p in csv_paths_str.split(',') if p.strip()]

    # Get user options
    slot_index = int(get_input("Enter the policy slot number for the deletion script", "9"))
    is_global = get_input("Use global context for deletion (global=1)? (yes/no)", "no").lower() == 'yes'
    debug_mode = get_input("Enable debug mode to show generated signatures? (yes/no)", "no").lower() == 'yes'

    all_rows = []
    for file_path in csv_paths:
        if not file_path.exists():
            print(f"ERROR: File not found: '{file_path}'")
            continue
        print(f"Reading file: {file_path}")
        rows = _converter_read_csv(file_path)
        for row in rows:
            row['source_file'] = file_path.name
        all_rows.extend(rows)

    if not all_rows:
        print("No data to analyze.")
        return

    # Separate rows into filter rules and NAT rules
    rules_rows = [row for row in all_rows if "local_filter_slot" in row.get("#type_slot", "")]
    nat_rows = [row for row in all_rows if "local_nat_slot" in row.get("#type_slot", "")]

    # Process filter rules
    print("\nAnalyzing filter rule duplicates...")
    rule_duplicates = _duplicator_find_duplicates(rules_rows, debug=debug_mode)
    rule_report = _duplicator_format_as_markdown(rule_duplicates, report_type='rules')

    output_dir = Path(config.get('Paths', 'output_dir'))
    output_dir.mkdir(exist_ok=True)

    rule_report_path = output_dir / "duplicate_rules_report.md"
    with open(rule_report_path, "w", encoding="utf-8") as f:
        f.write(rule_report)
    print(f"Filter rules report written to {rule_report_path} ({len(rule_duplicates)} duplicates found).")

    # Process NAT rules
    nat_rows.sort(key=lambda r: r.get('original_line', 0))
    for i, row in enumerate(nat_rows):
        row['nat_line'] = i + 1

    print("\nAnalyzing NAT rule duplicates...")
    nat_duplicates = _duplicator_find_duplicates(nat_rows, debug=debug_mode)
    nat_report = _duplicator_format_as_markdown(nat_duplicates, report_type='nat')
    nat_report_path = output_dir / "duplicate_nat_report.md"
    with open(nat_report_path, "w", encoding="utf-8") as f:
        f.write(nat_report)
    print(f"NAT rules report written to {nat_report_path} ({len(nat_duplicates)} duplicates found).")

    # Generate deletion script
    print("\nGenerating deletion script...")
    delete_commands = []
    rule_delete_commands = _duplicator_generate_delete_script(rule_duplicates, 'rules', slot_index, is_global)
    if rule_delete_commands:
        delete_commands.append("# Commands to delete duplicate filter rules")
        delete_commands.extend(rule_delete_commands)

    nat_delete_commands = _duplicator_generate_delete_script(nat_duplicates, 'nat', slot_index, is_global)
    if nat_delete_commands:
        if delete_commands:
            delete_commands.append("")
        delete_commands.append("# Commands to delete duplicate NAT rules")
        delete_commands.extend(nat_delete_commands)

    if delete_commands:
        delete_commands.append("\n# Activate the new filter policy")
        delete_commands.append("CONFIG FILTER ACTIVATE")
        script_content = "\n".join(delete_commands)
        delete_script_path = output_dir / "delete_duplicates_script.sh"
        with open(delete_script_path, "w", encoding="utf-8") as f:
            f.write(script_content)
        print(f"Deletion script generated at {delete_script_path} ({len(rule_delete_commands)} filter commands, {len(nat_delete_commands)} NAT commands).")
    else:
        print("No deletion commands to generate.")

    print("\nAnalysis complete.")