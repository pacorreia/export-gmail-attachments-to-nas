import os
import sys
import json
import time
import signal
import argparse
import threading
from .logging_config import configure_logging

script_logger = configure_logging()
exit_event = threading.Event()

def signal_handler(sig, frame):
    script_logger.info("Exit signal received. Shutting down gracefully...")
    exit_event.set()

def parse_arguments():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('--username', required=True, help='NAS username')
    parser.add_argument('--password', required=True, help='NAS password')
    parser.add_argument('--credentials', required=True, help='Path to credentials JSON file')
    parser.add_argument('--criteria', required=True, help='Path to criteria JSON file')
    args = parser.parse_args()
    return args

def setup (): # pragma: no cover
    args = parse_arguments()
    configure_logging()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    return args
  
def main_loop(args):

  while not exit_event.is_set():
    username = os.getenv('NAS_USERNAME') or args.username
    password = os.getenv('NAS_PASSWORD') or args.password
    criteria_path=args.criteria
    credentials_path=args.credentials
    
    if not username or not password or not criteria_path or not credentials_path:
        script_logger.error("Please provide a username, password, criteria file, and credentials file.")
        sys.exit(1)

    from .gmail_service import authenticate_gmail, process_emails, get_last_run_timestamp, update_last_run_timestamp
    
    while not exit_event.is_set():
        try:
            # Load criteria.json once
            try:
                with open(args.criteria, 'r', encoding='utf-8') as f:
                    criteria_data = json.load(f)
            except Exception as e:
                script_logger.error(f"Error loading criteria.json: {e}")
                sys.exit(1)
            last_run = get_last_run_timestamp(criteria_data)
            service = authenticate_gmail(credentials_path)
            script_logger.info("Starting to process emails...")
            process_emails(service, last_run,username, password, criteria_data, exit_event)
            script_logger.info("Finished processing emails.")
            update_last_run_timestamp(criteria_path, criteria_data)
            for _ in range(300):  # Sleep for 5 minutes, checking for exit requests
                if exit_event.is_set():
                    break
                time.sleep(1)
        except Exception as e:
            script_logger.error(f"Error processing email: {e}")
            continue

    script_logger.info("Program terminated.")

def main(): # pragma: no cover
    args = setup()
    main_loop(args)

if __name__ == "__main__":  # pragma: no cover
    main()