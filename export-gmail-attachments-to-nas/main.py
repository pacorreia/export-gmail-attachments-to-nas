import time
import signal
import os
import json
import sys
import argparse
from logging_config import configure_logging
from gmail_service import authenticate_gmail, process_emails, get_last_run_timestamp, update_last_run_timestamp
from shared import exit_requested

script_logger = configure_logging()

def signal_handler(sig, frame):
    global exit_requested
    script_logger.info("Exit signal received. Shutting down gracefully...")
    exit_requested = True

def main():
    global exit_requested
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
  
      # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Email Attachment Extraction")
    parser.add_argument("--username", required=False, help="NAS server username")
    parser.add_argument("--password", required=False, help="NAS server password")
    parser.add_argument("--credentials", required=True, help="Path to credentials.json")
    parser.add_argument("--criteria", required=True, help="Path to criteria.json")
    args = parser.parse_args()
    args = parser.parse_args()
    
    username = os.getenv('NAS_USERNAME') or args.username
    password = os.getenv('NAS_PASSWORD') or args.password
    criteria_path=args.criteria
    credentials_path=args.credentials
    
    if not username or not password or not criteria_path or not credentials_path:
        script_logger.error("Please provide a username, password, criteria file, and credentials file.")
        sys.exit(1)
  
      # Load criteria.json once
    try:
        with open(args.criteria, 'r', encoding='utf-8') as f:
            criteria_data = json.load(f)
    except Exception as e:
        script_logger.error(f"Error loading criteria.json: {e}")
        sys.exit(1)

    while not exit_requested:
        try:
            last_run = get_last_run_timestamp(criteria_data)
            service = authenticate_gmail(credentials_path)
            script_logger.info("Starting to process emails...")
            process_emails(service, last_run,username, password, criteria_data)
            script_logger.info("Finished processing emails.")
            update_last_run_timestamp(criteria_path, criteria_data)
            for _ in range(300):  # Sleep for 5 minutes, checking for exit requests
                if exit_requested:
                    break
                time.sleep(1)
        except Exception as e:
            script_logger.error(f"Error processing email: {e}")
            continue

    script_logger.info("Program terminated.")

if __name__ == "__main__":
    main()