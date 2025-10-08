import pandas as pd
import sys
import os

def process_logs(input_path, output_csv_path, output_summary_path):
    """
    Processes firewall log files to deduplicate entries and generate summaries.
    """
    # Step 1: Load data
    if os.path.isdir(input_path):
        print(f"Input path is a directory: {input_path}")
        input_files = [os.path.join(input_path, f) for f in os.listdir(input_path) if f.endswith('.csv')]
        if not input_files:
            print("No CSV files found in the directory.", file=sys.stderr)
            sys.exit(1)

        df_list = []
        for f in input_files:
            try:
                # Added encoding_errors and a more specific on_bad_lines handler
                df_temp = pd.read_csv(f, on_bad_lines='skip', encoding_errors='ignore', low_memory=False)
                df_list.append(df_temp)
            except Exception as e:
                print(f"Error reading {f}: {e}", file=sys.stderr)

        if not df_list:
            print("No valid CSV files could be processed.", file=sys.stderr)
            sys.exit(1)
        df = pd.concat(df_list, ignore_index=True)

    elif os.path.isfile(input_path):
        print(f"Input path is a single file: {input_path}")
        try:
            df = pd.read_csv(input_path, on_bad_lines='skip', encoding_errors='ignore', low_memory=False)
        except Exception as e:
            print(f"Error reading {input_path}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"Error: Input path {input_path} is not a valid file or directory.", file=sys.stderr)
        sys.exit(1)

    print(f"Successfully loaded {len(df)} total rows.")

    # Step 2: Clean and convert columns
    # Ensure required columns for grouping exist
    required_cols = ['srcname', 'dstname', 'dstportname', 'time', 'rcvd', 'sent']
    for col in required_cols:
        if col not in df.columns:
            print(f"Error: Required column '{col}' not found in the input data.", file=sys.stderr)
            sys.exit(1)

    df['time'] = pd.to_datetime(df['time'], errors='coerce')
    df['rcvd'] = pd.to_numeric(df['rcvd'], errors='coerce').fillna(0)
    df['sent'] = pd.to_numeric(df['sent'], errors='coerce').fillna(0)

    # Drop rows where key identifiers are missing
    df.dropna(subset=['srcname', 'dstname', 'dstportname', 'time'], inplace=True)

    # Step 3: Sort by time to get the first chronological entry
    df.sort_values('time', ascending=True, inplace=True)

    # Step 4: Group and aggregate
    group_keys = ['srcname', 'dstname', 'dstportname']

    # Define aggregations
    agg_dict = {
        'time': ['min', 'max'],
        'rcvd': 'sum',
        'sent': 'sum',
    }

    # Include all other columns to take the 'first' value
    first_cols = {col: 'first' for col in df.columns if col not in group_keys and col not in agg_dict}
    agg_dict.update(first_cols)

    aggregated_df = df.groupby(group_keys).agg(agg_dict)

    # Flatten multi-index columns
    aggregated_df.columns = ['_'.join(col).strip() for col in aggregated_df.columns.values]
    aggregated_df.rename(columns={
        'time_min': 'min_time',
        'time_max': 'max_time',
        'rcvd_sum': 'total_rcvd',
        'sent_sum': 'total_sent'
    }, inplace=True)

    # Add count for each group
    aggregated_df['count'] = df.groupby(group_keys).size().values

    # Reorder columns for clarity
    output_cols = group_keys + ['count', 'min_time', 'max_time', 'total_rcvd', 'total_sent']
    other_cols = [col for col in aggregated_df.columns if col not in output_cols]
    final_cols = output_cols + sorted(other_cols) # Keep other columns, sorted for consistency
    aggregated_df = aggregated_df.reset_index()[final_cols]

    # Step 5: Write cleaned data to CSV
    aggregated_df.to_csv(output_csv_path, index=False)
    print(f"Cleaned data with {len(aggregated_df)} unique flows written to {output_csv_path}")

    # Step 6: Generate summary report
    total_processed = len(df)
    unique_flows = len(aggregated_df)

    aggregated_df['total_traffic'] = aggregated_df['total_rcvd'] + aggregated_df['total_sent']
    top_10_by_count = aggregated_df.sort_values('count', ascending=False).head(10)
    top_10_by_traffic = aggregated_df.sort_values('total_traffic', ascending=False).head(10)

    with open(output_summary_path, 'w') as f:
        f.write("Firewall Log Analysis Summary\n")
        f.write("="*30 + "\n")
        f.write(f"Total rows processed: {total_processed}\n")
        f.write(f"Total unique flows identified: {unique_flows}\n\n")

        f.write("Top 10 Flows by Count:\n")
        f.write("-" * 25 + "\n")
        f.write(top_10_by_count[['srcname', 'dstname', 'dstportname', 'count']].to_string(index=False))
        f.write("\n\n")

        f.write("Top 10 Flows by Total Traffic (Received + Sent):\n")
        f.write("-" * 50 + "\n")
        f.write(top_10_by_traffic[['srcname', 'dstname', 'dstportname', 'total_traffic', 'total_rcvd', 'total_sent']].to_string(index=False))
        f.write("\n")

    print(f"Summary report written to {output_summary_path}")


def main():
    if len(sys.argv) != 4:
        print("Usage: python process_firewall_logs.py <input_path> <output_csv_path> <output_summary_path>", file=sys.stderr)
        print("  <input_path>: Path to a single CSV file or a directory of CSV files.", file=sys.stderr)
        sys.exit(1)

    input_path = sys.argv[1]
    output_csv_path = sys.argv[2]
    output_summary_path = sys.argv[3]

    process_logs(input_path, output_csv_path, output_summary_path)

if __name__ == "__main__":
    main()