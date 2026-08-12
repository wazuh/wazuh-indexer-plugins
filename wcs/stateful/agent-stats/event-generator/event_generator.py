#!/bin/python3

import argparse
import datetime
import json
import logging
import random
import requests
import urllib3

# Constants and Configuration
LOG_FILE = 'generate_data.log'
GENERATED_DATA_FILE = 'generatedData.json'
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
# Default values
INDEX_NAME = "wazuh-agent-stats"
USERNAME = "admin"
PASSWORD = "admin"
IP = "127.0.0.1"
PORT = "9200"

# Configure logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO)

# Suppress warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def generate_random_agent_statistics():
    """Generate the statistics reported by the agent module."""
    return {
        "status": random.choice(["connected", "disconnected", "pending"]),
        "last_keepalive": generate_random_date(),
        "messages": {"count": random.randint(0, 10000)},
        "tasks": {
            "dispatched": {"total": random.randint(0, 1000)},
            "discarded_duplicate": {"total": random.randint(0, 100)},
            "failed": {"total": random.randint(0, 100)},
        },
    }


def generate_random_logcollector_files():
    """Generate the per-log-source counters of a logcollector period."""
    return [
        {
            "location": random.choice(
                ["/var/log/syslog", "/var/log/auth.log", "df -P"]),
            "events": random.randint(0, 5000),
            "bytes": random.randint(0, 1000000),
            "targets": [
                {
                    "name": random.choice(["agent", "json", "syslog"]),
                    "drops": random.randint(0, 10),
                }
                for _ in range(random.randint(1, 3))
            ],
        }
        for _ in range(random.randint(0, 3))
    ]


def generate_random_logcollector_statistics():
    """Generate the statistics reported by the logcollector module."""
    return {
        "global": {
            "start": generate_random_date(),
            "end": generate_random_date(),
            "files": generate_random_logcollector_files(),
        },
        "interval": {
            "start": generate_random_date(),
            "end": generate_random_date(),
            "files": generate_random_logcollector_files(),
        },
    }


def generate_random_wazuh():
    return {
        "schema": {"version": "1"},
        "cluster": {
            "name": f"wazuh-cluster-{random.randint(0, 10)}",
            "node": f"wazuh-cluster-node-{random.randint(0, 10)}",
        },
        "agent": {
            "id": f"{random.randint(0, 999):03d}",
            "statistics": {
                "agent": generate_random_agent_statistics(),
                "logcollector": generate_random_logcollector_statistics(),
            },
        },
    }


def generate_random_date():
    start_date = datetime.datetime.now()
    end_date = start_date - datetime.timedelta(days=10)
    random_date = start_date + (end_date - start_date) * random.random()
    return random_date.strftime(DATE_FORMAT)


def generate_random_data(number):
    data = []
    for _ in range(number):
        event_data = {
            'wazuh': generate_random_wazuh(),
            'state': {
                'modified_at': generate_random_date(),
                "document_version": random.randint(1, 10)
            },
        }
        data.append(event_data)
    return data


def inject_events(protocol, ip, port, index, username, password, data):
    url = f'{protocol}://{ip}:{port}/{index}/_doc'
    session = requests.Session()
    session.auth = (username, password)
    session.verify = False
    headers = {'Content-Type': 'application/json'}
    try:
        for event_data in data:
            response = session.post(url, json=event_data, headers=headers)
            if response.status_code != 201:
                logging.error(f'Error: {response.status_code}')
                logging.error(response.text)
                break
        logging.info('Data injection completed successfully.')
    except Exception as e:
        logging.error(f'Error: {str(e)}')


def main():
    parser = argparse.ArgumentParser(
        description="Generate and optionally inject events into an OpenSearch index or Command Manager."
    )
    parser.add_argument(
        "--protocol",
        choices=['http', 'https'],
        default='https',
        help="Specify the protocol to use: http or https."
    )
    args = parser.parse_args()
    try:
        number = int(input("How many events do you want to generate? "))
    except ValueError:
        logging.error("Invalid input. Please enter a valid number.")
        return

    logging.info(f"Generating {number} events...")
    data = generate_random_data(number)

    with open(GENERATED_DATA_FILE, 'a') as outfile:
        for event_data in data:
            json.dump(event_data, outfile)
            outfile.write('\n')

    logging.info('Data generation completed.')
    if input("Do you want to inject the generated data into your indexer? (y/n) ").strip().lower() == 'y':
        ip = input(f"Enter the IP of your Indexer (default: '{IP}'): ") or IP
        port = input(
            f"Enter the port of your Indexer (default: '{PORT}'): ") or PORT
        index = input(
            f"Enter the index name (default: '{INDEX_NAME}'): ") or INDEX_NAME
        username = input(f"Username (default: '{USERNAME}'): ") or USERNAME
        password = input(f"Password (default: '{PASSWORD}'): ") or PASSWORD
        inject_events(args.protocol, ip, port, index, username, password, data)


if __name__ == "__main__":
    main()
