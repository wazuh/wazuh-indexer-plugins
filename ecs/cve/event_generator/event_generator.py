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
INDEX_NAME = "wazuh-cve"
USERNAME = "admin"
PASSWORD = "admin"
IP = "127.0.0.1"
PORT = "9200"

logging.basicConfig(filename=LOG_FILE, level=logging.INFO)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def generate_random_date():
    return datetime.datetime.now(datetime.timezone.utc).strftime(DATE_FORMAT)


def generate_random_cve():
    return {
        "cve": {
            "name": f"CVE-{random.randint(2000, 2025)}-{random.randint(1000, 9999)}",
            "data_type": "CVE",
            "data_version": "4.0",
            "cve_metadata": {
                "assigner_org_id": str(uuid.uuid4()),
                "assigner_short_name": "OrgX",
                "date_published": generate_random_date(),
                "date_updated": generate_random_date(),
                "state": random.choice(["PUBLISHED", "DRAFT", "REJECTED"])
            },
            "affected": {
                "vendor": f"Vendor{random.randint(1, 10)}",
                "product": f"Product{random.randint(1, 50)}",
                "cpes": [f"cpe:/a:vendor{random.randint(1, 10)}:product{random.randint(1, 50)}"],
                "default_status": random.choice(["affected", "unaffected"])
            },
            "descriptions": {
                "lang": "en",
                "value": f"Description of CVE-{random.randint(2000, 2025)}-{random.randint(1000, 9999)}"
            },
            "metrics": {
                "cvss_v2": {
                    "base_score": round(random.uniform(0.0, 10.0), 1),
                    "vector_string": f"AV:{random.choice(['L', 'N'])}/AC:{random.choice(['L', 'H'])}",
                    "version": "2.0"
                }
            },
            "inserted_at": generate_random_date()
        }
    }


def generate_cve_data(number):
    return [generate_random_cve() for _ in range(number)]


def inject_events(protocol, ip, port, index, username, password, data):
    session = requests.Session()
    session.auth = (username, password)
    session.verify = False
    headers = {'Content-Type': 'application/json'}

    for event_data in data:
        doc_id = str(uuid.uuid4())
        url = f'{protocol}://{ip}:{port}/{index}/_doc/{doc_id}'
        response = session.post(
            url, data=json.dumps(event_data), headers=headers)
        if response.status_code not in [200, 201]:
            logging.error(f'Error {response.status_code}: {response.text}')
    logging.info('Data injection completed successfully.')


def main():
    parser = argparse.ArgumentParser(
        description="Generate and inject CVE documents into Wazuh Indexer.")
    parser.add_argument(
        "--protocol", choices=['http', 'https'], default='https', help="Specify the protocol.")
    args = parser.parse_args()

    try:
        number = int(input("How many CVE events do you want to generate? "))
    except ValueError:
        logging.error("Invalid input. Please enter a valid number.")
        return

    logging.info(f"Generating {number} CVE events...")
    data = generate_cve_data(number)

    with open(GENERATED_DATA_FILE, 'a') as outfile:
        json.dump(data, outfile)
        outfile.write('\n')

    logging.info('Data generation completed.')

    inject = input(
        "Do you want to inject the generated data into Wazuh Indexer? (y/n) ").strip().lower()
    if inject == 'y':
        ip = input(
            f"Enter the IP of your Wazuh indexer node (default: '{IP}'): ") or IP
        port = input(f"Enter the port (default: '{PORT}'): ") or PORT
        index = input(
            f"Enter the index name (default: '{INDEX_NAME}'): ") or INDEX_NAME
        username = input(f"Username (default: '{USERNAME}'): ") or USERNAME
        password = input(f"Password (default: '{PASSWORD}'): ") or PASSWORD
        inject_events(args.protocol, ip, port, index, username, password, data)


if __name__ == "__main__":
    main()
