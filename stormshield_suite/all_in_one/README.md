# Stormshield All-in-One Suite

## 1. Overview

This suite is a command-line tool that combines several useful scripts for managing a Stormshield firewall into a single, user-friendly interactive menu. It is designed to streamline common workflows, from analyzing logs to generating and validating firewall rules.

The tool is built to be cross-platform (Windows, macOS, and Linux) and uses a configuration file to store your settings, making it easy to manage different environments.

## 2. Features

The interactive menu provides access to the following tools:

1.  **Analyze Firewall Logs**:
    *   Processes and deduplicates Stormshield log files (in CSV format).
    *   Generates a summary report of the top traffic flows.
    *   **Smart Feature**: Suggests creating a new firewall rule based on the analysis and can add it to a rules file for you.

2.  **Export Firewall Configuration**:
    *   Connects to your Stormshield firewall via SSH.
    *   Exports the latest lists of network objects and interfaces.
    *   Saves the output to text files, which are used by the Rule Converter for validation.

3.  **Convert Rules from CSV to CLI**:
    *   Converts a CSV file of firewall rules into NSRPC (Stormshield CLI) commands.
    *   Validates rules against the object and interface files downloaded by the Exporter.
    *   Separates commands into `rules_safe.txt` (for validated rules) and `rules_pending.txt` (for rules with missing dependencies).

4.  **Compare Rule Sets**:
    *   Compares a "source" CSV file against a "final" CSV file.
    *   Identifies rules that exist in the source but are missing from the final version.
    *   Generates a CLI script (`missing_rules_commands.txt`) to add the missing rules.

5.  **Detect Duplicate Rules**:
    *   Analyzes one or more CSV files to find duplicate rules.
    *   Duplicates are identified by a signature of (Source, Destination, Service, Action).
    *   Prints a report of all found duplicates, including their names and file locations.

## 3. Installation

Before running the script, you need to install the required Python libraries.

1.  Make sure you have Python 3.8+ installed.
2.  Install the dependencies using pip:
    ```sh
    pip install pandas paramiko
    ```

## 4. Configuration

The behavior of the script is controlled by the `config.ini` file located in the same directory. You should edit this file to match your environment.

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

## 5. How to Run

1.  Navigate to the `stormshield_suite/all_in_one/` directory in your terminal.
2.  Run the main script:
    ```sh
    python main.py
    ```
3.  The interactive menu will appear. Choose an option by typing the corresponding number and pressing Enter.
4.  Follow the on-screen prompts to provide any required information, such as file paths or firewall credentials.
5.  All output files will be saved in the `output` and `reference_files` directories, as configured in `config.ini`.