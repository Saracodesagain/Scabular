import argparse
import pandas as pd
from utils import load_process_list
from analyzer import analyze_process_list


def main():
    firewatch = argparse.ArgumentParser(description="Scabular - Windows Process Anomaly Analyzer")

    # Define the command arguments
    firewatch.add_argument('command', choices=['analyze', 'analyse'], help='Operation to execute')

    # Define the --file argument
    firewatch.add_argument('--file', help='Path to CSV or JSON file containing process list')

    args = firewatch.parse_args()

    if args.command == 'analyze':
        print("[!] Command used: analyze (American spelling)")
    elif args.command == 'analyse':
        print("[!] Command used: analyse (British spelling)")

    if not args.file:
        print("[-] Error: --file path required for analysis")
        return

    print(f"[!] Initiating analysis on file: {args.file}")

    try:
        df = load_process_list(args.file)
        print(f"[+] Loaded {len(df)} processes from file")

        alerts, _ = analyze_process_list(df)

        if alerts:
            print("\n[!] Suspicious relationships detected:\n")
            for alert in alerts:
                print(f"🚨 Parent: {alert['Parent']} (PID: {alert['PPID']})")
                print(f"   → Child: {alert['Child']} (PID: {alert['PID']})\n")
        else:
            print("\n[+] No suspicious relationships found.")

    except Exception as e:
        print(f"[-] {e}")
        return


if __name__ == "__main__":
    main()