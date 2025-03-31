#!/bin/python3

import argparse
import datetime
import json
import logging
import random
import requests
import urllib3
import uuid

LOG_FILE = 'generate_data.log'
GENERATED_DATA_FILE = 'generatedData.json'
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
# Default values
INDEX_NAME = "wazuh-cve"
USERNAME = "admin"
PASSWORD = "admin"
IP = "127.0.0.1"
PORT = "9200"

# Configure logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO)

# Suppress warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def generate_random_date(initial_date=None, days_range=30):
    if initial_date is None:
        initial_date = datetime.datetime.now(datetime.timezone.utc)
    random_days = random.randint(0, days_range)
    new_timestamp = initial_date + datetime.timedelta(days=random_days)
    return new_timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')


def generate_random_cve():
    return {
        "inserted_at": generate_random_date(),
        "name": f"CVE-{random.randint(2000, 2025)}-{random.randint(1000, 9999)}",
        "offset": str(uuid.uuid4()),
        "version": "4.0",
        "payload": {
            "containers": {
                "cna": {
                    "affected": {
                        "cpes": [f"cpe:/a:vendor:product:{random.randint(1, 10)}"],
                        "defaultStatus": random.choice(["affected", "unaffected"]),
                        "product": f"Product {random.randint(1, 100)}",
                        "vendor": f"Vendor {random.randint(1, 100)}",
                        "versions": [{
                            "status": random.choice(["known", "unknown"]),
                            "version": f"{random.randint(1, 10)}.0"
                        }]
                    },
                    "descriptions": [{
                        "lang": "en",
                        "value": f"Description for CVE {random.randint(1000, 9999)}"
                    }],
                    "metrics": {
                        "cvssV2_0": {
                            "accessComplexity": random.choice(["LOW", "MEDIUM", "HIGH"]),
                            "accessVector": random.choice(["NETWORK", "LOCAL"]),
                            "authentication": random.choice(["NONE", "SINGLE", "MULTIPLE"]),
                            "availabilityImpact": random.choice(["NONE", "PARTIAL", "COMPLETE"]),
                            "baseScore": str(round(random.uniform(0, 10), 1)),
                            "confidentialityImpact": random.choice(["NONE", "PARTIAL", "COMPLETE"]),
                            "integrityImpact": random.choice(["NONE", "PARTIAL", "COMPLETE"]),
                            "vectorString": f"(AV:{random.choice(['N', 'L'])}/AC:{random.choice(['L', 'H'])}/PR:{random.choice(['N', 'L', 'H'])})",
                            "version": "2.0"
                        }
                    },
                    "problemTypes": [{
                        "descriptions": [{
                            "cweId": f"CWE-{random.randint(1, 100)}",
                            "description": "Example problem type",
                            "lang": "en"
                        }]
                    }],
                    "providerMetadata": {
                        "dateUpdated": generate_random_date(),
                        "orgId": "ExampleOrg",
                        "shortName": "EXO",
                        "x_subShortName": "EXOSUB"
                    },
                    "references": [{
                        "url": f"https://example.com/cve/{random.randint(1000, 9999)}"
                    }]
                }
            }
        }
    }


def generate_random_data(number):
    return [generate_random_cve() for _ in range(number)]


def inject_events(protocol, ip, port, index, username, password, data):
    try:
        for event_data in data:
            doc_id = str(uuid.uuid4())
            url = f'{protocol}://{ip}:{port}/{index}/_doc/{doc_id}'
            send_post_request(username, password, url, event_data)
        logging.info('Data injection completed successfully.')
    except Exception as e:
        logging.error(f'Error: {str(e)}')


def send_post_request(username, password, url, event_data):
    session = requests.Session()
    session.auth = (username, password)
    session.verify = False
    headers = {'Content-Type': 'application/json'}
    response = session.post(url, data=json.dumps(event_data), headers=headers)
    if response.status_code not in [201, 200]:
        logging.error(f'Error: {response.status_code}')
        logging.error(response.text)
    return response


def main():
    parser = argparse.ArgumentParser(
        description="Generate and inject CVE documents into Wazuh Indexer.")
    parser.add_argument("--protocol", choices=['http', 'https'],
                        default='https', help="Specify the protocol to use: http or https.")
    args = parser.parse_args()

    try:
        number = int(input("How many CVE documents do you want to generate? "))
    except ValueError:
        logging.error("Invalid input. Please enter a valid number.")
        return

    logging.info(f"Generating {number} CVE documents...")
    data = generate_random_data(number)

    with open(GENERATED_DATA_FILE, 'a') as outfile:
        json.dump(data, outfile)
        outfile.write('\n')

    logging.info('Data generation completed.')

    inject = input(
        "Do you want to inject the generated data into Wazuh Indexer? (y/n) ").strip().lower()
    if inject == 'y':
        ip = input(f"Enter the IP of your Indexer (default: '{IP}'): ") or IP
        port = input(
            f"Enter the port of your Indexer (default: '{PORT}'): ") or PORT
        index = INDEX_NAME
        username = input(f"Username (default: '{USERNAME}'): ") or USERNAME
        password = input(f"Password (default: '{PASSWORD}'): ") or PASSWORD

        inject_events(args.protocol, ip, port, index, username, password, data)


if __name__ == "__main__":
    main()
