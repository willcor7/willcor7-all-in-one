# Stormshield All-in-One Suite

## 1. Overview

This suite is a command-line tool that combines several powerful scripts for managing a Stormshield firewall into a single, user-friendly interactive menu. It is designed to streamline common workflows, from analyzing logs and exporting configurations to converting, comparing, and validating firewall rules.

The tool is built to be cross-platform (Windows, macOS, and Linux) and uses a central configuration file (`config.ini`) to store your settings, making it easy to manage different environments and automate repetitive tasks.

## 2. Installation

Before running the script, you need to install the required Python libraries.

1.  Make sure you have **Python 3.8+** installed.
2.  Install the dependencies using pip:
    ```sh
    pip install pandas paramiko
    ```

<details>
<summary><b>Offline Installation for Windows VM (No Internet Access)</b></summary>

Here is a guide to download the required packages on a connected machine and then install them on an offline Windows VM running Python 3.9.13.

### Context and Prerequisites
- **Target System**: Windows 64-bit with Python 3.9.13.
- **Python Command**: Use `py -m pip` on Windows to ensure you are using the correct Python interpreter.
- **Compatibility Tags**: The wheel files must match the target system's compatibility tags: `cp39` (for the Python interpreter) and `win_amd64` (for the platform).
- **Pandas Version**: Pandas 2.3+ requires Python 3.10 or newer. For Python 3.9, you must use the 2.2.x series.

### Step A — Download Wheels on a Connected Machine
These commands will download the binary wheels for Python 3.9 (64-bit) and their dependencies into a local directory named `.\wheels`.

```powershell
# Create a directory to store the wheels
mkdir .\wheels

# Download Pandas 2.2.x for Python 3.9, Windows 64-bit
py -m pip download --only-binary=:all: --implementation cp --python-version 39 --abi cp39 --platform win_amd64 "pandas==2.2.*" -d .\wheels

# Download Paramiko 3.x and its dependencies for Python 3.9, Windows 64-bit
py -m pip download --only-binary=:all: --implementation cp --python-version 39 --abi cp39 --platform win_amd64 "paramiko==3.*" -d .\wheels
```

### Step B — Transfer Files to the VM
Copy the entire `.\wheels` directory to the offline VM using a USB drive, shared network folder, or any other method. Do not rename the downloaded wheel files, as their names contain the compatibility tags that `pip` needs to recognize them.

### Step C — Install Offline from Wheels
On the VM, open a terminal, navigate into the `wheels` directory, and run the following commands to install the packages. The `--no-index` flag prevents `pip` from attempting to connect to the internet.

```powershell
cd .\wheels
py -m pip install --no-index --find-links=. "pandas==2.2.*"
py -m pip install --no-index --find-links=. "paramiko==3.*"
```

### Quick Verification
You can verify that the packages were installed correctly by running:
```powershell
py -c "import pandas, paramiko; print(pandas.__version__, paramiko.__version__)"
```

### Included Dependencies
- **Pandas**: Depends on `numpy` and `python-dateutil`.
- **Paramiko**: Depends on `cryptography`, `bcrypt`, and `PyNaCl`.

The `pip download` command automatically collects all of these required dependencies for the specified platform.

### Troubleshooting
- If you see a "No matching distribution found" error during the offline installation, it means that `pip` could not find a compatible wheel in the directory specified by `--find-links`. Ensure the wheel files for your platform (`cp39` and `win_amd64`) are present.
- If you have multiple Python versions installed, always use `py -m pip` to ensure you are targeting the correct one.

</details>

## 3. Configuration

The behavior of the script is controlled by the `config.ini` file located in the same directory. Before running the tool, you should edit this file to match your environment.

```ini
[Paths]
# Optional: Set a default path to your log file or directory.
# Windows Example: C:\\Users\\YourUser\\Documents\\stormshield_logs.csv
# Linux/macOS Example: /home/user/stormshield_logs.csv
log_file_path =

# Optional: Set a default path to your main firewall rules CSV file.
rules_csv_path =

# Directory where output files (reports, CLI scripts) will be saved.
output_dir = output

# Directory where reference files (exported objects/interfaces) are stored.
reference_dir = reference_files

[Exporter]
# IP address or hostname of your Stormshield firewall.
firewall_ip = 192.168.1.254

# Username for the firewall.
firewall_user = admin

# For security, it is recommended to leave the password empty.
# The script will prompt you to enter it securely when needed.
firewall_password =
```

## 4. How to Run

1.  Navigate to the `stormshield_suite/all_in_one/` directory in your terminal.
2.  Run the main script:
    ```sh
    python main.py
    ```
3.  The interactive menu will appear. Choose an option by typing the corresponding number and pressing Enter.
4.  Follow the on-screen prompts to provide any required information, such as file paths or firewall credentials.
5.  All output files will be saved in the `output` and `reference_files` directories, as configured in `config.ini`.

---

## 5. Detailed Tool Descriptions

### 1. Analyze Firewall Logs
This tool processes and analyzes Stormshield log files to help you identify recurring traffic patterns.

*   **Functionality**:
    *   Accepts a single CSV file or a directory of CSV files.
    *   Deduplicates log entries based on unique flows (source, destination, port).
    *   Aggregates data for each flow, calculating total occurrences, data volume (sent/received), and the first/last time the flow was seen.
*   **Output**:
    *   `analyzed_logs.csv`: A detailed CSV file containing one row for each unique traffic flow.
    *   `analysis_summary.txt`: A human-readable summary with top 10 flows by count and traffic volume.
*   **Smart Feature**: After analysis, the tool will ask if you want to create a firewall rule based on the identified top flows, helping to close the loop between analysis and action.

### 2. Export Firewall Configuration
Connects to your Stormshield firewall via SSH to download the latest lists of network objects and interfaces.

*   **Functionality**:
    *   Prompts for firewall IP, user, and password (using the values from `config.ini` as defaults).
    *   Executes `CONFIG OBJECT LIST` and `CONFIG NETWORK INTERFACE SHOW` commands.
*   **Output**:
    *   Saves the output to timestamped text files (e.g., `export_objects_YYYYMMDD_HHMMSS.txt`) inside the `reference_files` directory. These files are crucial for validating rules in the converter tool.

### 3. Convert Rules from CSV to CLI
Converts a CSV file of firewall rules into a script of NSRPC (Stormshield CLI) commands. This is the core tool for automating rule creation.

*   **Functionality**:
    *   Takes a CSV file of rules as input.
    *   **Validates Dependencies**: It checks each rule against the object and interface files in the `reference_files` directory (dynamically finding the latest ones). This ensures that all required components exist before you try to apply the rules.
    *   Handles both `filter` and `nat` rules correctly.
*   **Output**:
    *   `rules_safe.txt`: Contains the NSRPC commands for rules that passed validation. This file is ready to be run on the firewall.
    *   `rules_pending.txt`: Contains the original data for rules that failed validation due to missing dependencies.
    *   `dependencies_missing.txt`: A clean list of all the objects and interfaces that need to be created.

### 4. Compare Rule Sets
Compares two sets of rules (a "source" and a "final" set) and generates the CLI commands needed to add any missing rules.

*   **Functionality**:
    *   Ideal for situations where you need to ensure a standard set of rules exists in a new or updated configuration.
    *   Identifies rules present in the source file(s) but absent from the final file.
*   **Output**:
    *   `missing_rules_commands.txt`: An NSRPC script containing the commands to create the missing rules.

### 5. Detect Duplicate Rules
Analyzes one or more CSV files to find duplicate rules.

*   **Functionality**:
    *   Identifies duplicates based on a unique signature: (Source, Destination, Service, Action).
    *   Comments, rule names, and other metadata are ignored, allowing it to find functional duplicates.
*   **Output**:
    *   A report is printed directly to the console, listing each duplicate signature and the file/rule names where the duplicates were found.