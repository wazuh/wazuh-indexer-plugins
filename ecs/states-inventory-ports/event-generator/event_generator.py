#!/bin/python3

import argparse
import datetime
import json
import logging
import random
import requests
import urllib3

# Constants and Configuration
LOG_FILE = "generate_data.log"
GENERATED_DATA_FILE = "generatedData.json"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
# Default values
INDEX_NAME = "wazuh-states-inventory-ports"
USERNAME = "admin"
PASSWORD = "admin"
IP = "127.0.0.1"
PORT = "9200"

# Configure logging
logging.basicConfig(level=logging.INFO)

# Suppress warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def generate_random_data(number):
    data = []
    for _ in range(number):
        event_data = {
            "agent": generate_random_agent(),
            "checksum": generate_random_checksum(),
            "destination": generate_random_destination(),
            "file": generate_random_file(),
            "host": generate_random_host(True),
            "interface": {"state": random.choice(["LISTEN", "ESTABLISHED"])},
            "network": {"transport": random.choice(["TCP", "UDP", "ICMP"])},
            "process": generate_random_process(),
            "source": generate_random_source(),
            "wazuh": generate_random_wazuh(),
        }
        data.append(event_data)
    return data


def generate_random_date():
    start_date = datetime.datetime.now()
    end_date = start_date - datetime.timedelta(days=10)
    random_date = start_date + (end_date - start_date) * random.random()
    return random_date.strftime(DATE_FORMAT)


def generate_random_agent():
    return {
        "id": f"{random.randint(0, 99):03d}",
        "name": f"Agent{random.randint(0, 99)}",
        "version": f"v{random.randint(0, 9)}-stable",
        "host": generate_random_host(False),
    }


def generate_random_checksum():
    return {
        'hash': {
            'sha1': ''.join(random.choices("ABCDEF0123456789", k=40)),
        }
    }


def generate_random_host(is_root_level=False):
    if is_root_level:
        return {
            "network": {
                "egress": {"queue": random.randint(0, 1000)},
                "ingress": {"queue": random.randint(0, 1000)},
            }
        }
    else:
        return {
            "architecture": random.choice(["x86_64", "arm64"]),
            "ip": f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
        }


def generate_random_destination():
    return {
        "ip": f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
        "port": random.randint(0, 65535),
    }


def generate_random_file():
    return {"inode": f"inode{random.randint(0, 9999)}"}


def generate_random_process():
    return {
        "name": f"process{random.randint(0, 9999)}",
        "pid": random.randint(0, 99999),
    }


def generate_random_source():
    return {
        "ip": f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
        "port": random.randint(0, 65535),
    }


def generate_random_wazuh():
    return {
        "cluster": {
            "name": f"wazuh-cluster-{random.randint(0, 10)}",
            "node": f"wazuh-cluster-node-{random.randint(0, 10)}",
        },
        "schema": {"version": "1.7.0"},
    }


def inject_events(data, ip, port, username, password, index, protocol):
    url = f"{protocol}://{ip}:{port}/{index}/_doc"
    session = requests.Session()
    session.auth = (username, password)
    session.verify = False
    headers = {"Content-Type": "application/json"}

    try:
        for event_data in data:
            response = session.post(url, json=event_data, headers=headers)
            if response.status_code != 201:
                logging.error(f"Error: {response.status_code}")
                logging.error(response.text)
                break
        logging.info("Data injection completed successfully.")
    except Exception as e:
        logging.error(f"Error: {str(e)}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate and optionally inject documents into a Wazuh Indexer cluster."
    )
    parser.add_argument(
        "--protocol",
        choices=['http', 'https'],
        default='https',
        help="Specify the protocol to use: http or https. Default is 'https'."
    )
    args = parser.parse_args()

    try:
        number = int(input("How many events do you want to generate? "))
    except ValueError:
        logging.error("Invalid input. Please enter a valid number.")
        return

    logging.info(f"Generating {number} events...")
    data = generate_random_data(number)

    with open(GENERATED_DATA_FILE, "a") as outfile:
        for event_data in data:
            json.dump(event_data, outfile)
            outfile.write("\n")

    logging.info("Data generation completed.")

    inject = (
        input("Do you want to inject the generated data into your indexer? (y/n) ")
        .strip()
        .lower()
    )
    if inject == "y":
        ip = input(f"Enter the IP of your Indexer (default: '{IP}'): ") or IP
        port = input(f"Enter the port of your Indexer (default: '{PORT}'): ") or PORT
        index = input(f"Enter the index name (default: '{INDEX_NAME}'): ") or INDEX_NAME
        username = input(f"Username (default: '{USERNAME}'): ") or USERNAME
        password = input(f"Password (default: '{PASSWORD}'): ") or PASSWORD
        inject_events(data, ip, port, username, password, index, args.protocol)


if __name__ == "__main__":
    main()
