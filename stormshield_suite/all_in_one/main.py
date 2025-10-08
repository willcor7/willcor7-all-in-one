import os
import configparser
import getpass
import tool_functions

def get_config():
    """Reads the configuration from config.ini."""
    config = configparser.ConfigParser()
    # Ensure the path is correct, assuming main.py is in the same directory as config.ini
    config_path = os.path.join(os.path.dirname(__file__), 'config.ini')
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found at: {config_path}")
    config.read(config_path)
    return config

def main_menu():
    """Displays the main menu and handles user input."""
    print("\n--- Stormshield All-in-One Suite ---")
    print("1. Analyze Firewall Logs")
    print("2. Export Firewall Configuration")
    print("3. Convert Rules from CSV to CLI")
    print("4. Compare Rule Sets")
    print("5. Detect Duplicate Rules")
    print("6. Exit")
    return input("Please choose an option: ")

def main():
    """Main function to run the application."""
    try:
        config = get_config()
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Please make sure a 'config.ini' file exists in the same directory as the script.")
        return

    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Create output directories if they don't exist, making paths absolute
    output_dir = os.path.join(script_dir, config['Paths']['output_dir'])
    reference_dir = os.path.join(script_dir, config['Paths']['reference_dir'])
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(reference_dir, exist_ok=True)

    # Overwrite the config paths with absolute paths for robustness
    config['Paths']['output_dir'] = output_dir
    config['Paths']['reference_dir'] = reference_dir

    while True:
        choice = main_menu()
        if choice == '1':
            print("\n--- Analyze Firewall Logs ---")
            tool_functions.analyze_logs(config)
        elif choice == '2':
            print("\n--- Export Firewall Configuration ---")
            tool_functions.export_config(config)
        elif choice == '3':
            print("\n--- Convert Rules from CSV to CLI ---")
            tool_functions.convert_rules(config)
        elif choice == '4':
            print("\n--- Compare Rule Sets ---")
            tool_functions.compare_rules(config)
        elif choice == '5':
            print("\n--- Detect Duplicate Rules ---")
            tool_functions.detect_duplicates(config)
        elif choice == '6':
            print("Exiting. Goodbye!")
            break
        else:
            print("Invalid option, please try again.")

if __name__ == "__main__":
    main()