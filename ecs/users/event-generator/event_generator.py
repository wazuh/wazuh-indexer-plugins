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
INDEX_NAME = "wazuh-users"
USERNAME = "admin"
PASSWORD = "admin"
IP = "127.0.0.1"
PORT = "9200"

logging.basicConfig(filename=LOG_FILE, level=logging.INFO)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def generate_random_date():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def generate_random_user():
    return {
        "id": str(uuid.uuid4()),
        "username": f"user_{random.randint(1, 1000)}",
        "password": f"password{random.randint(1000, 9999)}",
        "allow_run_as": random.choice([True, False]),
        "created_at": generate_random_date(),
        "roles": [f"role_{random.randint(1, 10)}"]
    }


def generate_random_data(number):
    return [{"user": generate_random_user()} for _ in range(number)]


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
        description="Generate and inject events into Wazuh Users index.")
    parser.add_argument("--protocol", choices=['http', 'https'],
                        default='https', help="Specify the protocol to use: http or https.")
    args = parser.parse_args()

    try:
        number = int(input("How many events do you want to generate? "))
    except ValueError:
        logging.error("Invalid input. Please enter a valid number.")
        return

    logging.info(f"Generating {number} events...")
    data = generate_random_data(number)

    with open(GENERATED_DATA_FILE, 'a') as outfile:
        json.dump(data, outfile)
        outfile.write('\n')

    logging.info('Data generation completed.')

    inject = input(
        "Do you want to inject the generated data into your index? (y/n) ").strip().lower()
    if inject == 'y':
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
