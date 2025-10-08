# Firewall Log Processor

## Overview

This project provides a Python script to process, clean, and analyze firewall logs, specifically tailored for StormShield firewall CSV exports. The script reads log files, deduplicates entries based on unique traffic flows (source, destination, port), and generates an aggregated CSV report and a human-readable summary file.

The primary goal is to simplify the identification of recurring traffic patterns to aid in the creation of appropriate firewall rules.

## Features

- **Processes Multiple Files**: Accepts either a single CSV file or a directory containing multiple CSV files as input.
- **Deduplication and Aggregation**: Groups log entries by unique combinations of `srcname`, `dstname`, and `dstportname`.
- **Rich Aggregation**: For each unique flow, it calculates:
    - Total number of occurrences (`count`).
    - Sum of received (`total_rcvd`) and sent (`total_sent`) bytes.
    - The timestamp of the first (`min_time`) and last (`max_time`) occurrence.
    - Contextual data from the first log entry of the flow (e.g., `action`, `ruleid`).
- **Robust Error Handling**: Skips malformed lines in the input CSVs and handles non-numeric data gracefully.
- **Dual Output**: Generates two files:
    1.  A detailed **CSV file** with one row per unique flow and its aggregated data.
    2.  A **summary text file** with high-level statistics, including the top 10 flows by frequency and by total data volume.

## Requirements

- Python 3.x
- pandas library

To install the required library, run:
```bash
pip install pandas
```

## Usage

The script is run from the command line and requires three arguments: the input path, the output CSV path, and the output summary path.

```bash
python process_firewall_logs.py <input_path> <output_csv_path> <output_summary_path>
```

- `<input_path>`: Path to the input CSV file or a directory containing `.csv` files.
- `<output_csv_path>`: The file path where the cleaned, aggregated CSV data will be saved.
- `<output_summary_path>`: The file path where the text summary report will be saved.

### Example

```bash
# Process a single log file
python process_firewall_logs.py /path/to/logs/firewall.csv cleaned_logs.csv summary.txt

# Process all CSV files in a directory
python process_firewall_logs.py /path/to/logs/ cleaned_logs.csv summary.txt
```

## Input File Format

The script expects a CSV file with a header. The key columns used for processing are:
- `time`: Timestamp of the log entry (e.g., `2025-10-06 08:00:00`).
- `srcname`: Source IP address or hostname.
- `dstname`: Destination IP address or hostname.
- `dstportname`: Destination port number or service name.
- `rcvd`: Bytes received (numeric).
- `sent`: Bytes sent (numeric).

The full expected header is:
`time,action,user,srccountry,srcname,dstcountry,dstname,dstportname,ruleid,arg,msg,rcvd,sent,clientappid,serverappid,`

## Output Files

### 1. Cleaned CSV File (`<output_csv_path>`)

This file contains the aggregated data, with one row for each unique flow. Columns include:
- `srcname`, `dstname`, `dstportname`: The unique flow identifiers.
- `count`: The number of times this flow appeared in the logs.
- `min_time`, `max_time`: The earliest and latest timestamps for the flow.
- `total_rcvd`, `total_sent`: The sum of bytes received and sent for the flow.
- Other columns from the original log, populated with data from the first chronological occurrence of the flow.

### 2. Summary Text File (`<output_summary_path>`)

This file provides a high-level overview of the analysis, including:
- Total number of rows processed.
- Total number of unique flows identified.
- A table of the Top 10 flows by count.
- A table of the Top 10 flows by total traffic (received + sent).