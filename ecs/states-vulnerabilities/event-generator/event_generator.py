#!/bin/python3

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
INDEX_NAME = "wazuh-states-vulnerabilities"
USERNAME = "admin"
PASSWORD = "admin"
IP = "127.0.0.1"
PORT = "9200"

# Configure logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO)

# Suppress warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def generate_random_date():
    start_date = datetime.datetime.now()
    end_date = start_date - datetime.timedelta(days=10)
    random_date = start_date + (end_date - start_date) * random.random()
    return random_date.strftime(DATE_FORMAT)


def generate_random_agent():
    agent = {
        'id': f'agent{random.randint(0, 99)}',
        'name': f'Agent{random.randint(0, 99)}',
        'type': random.choice(['filebeat', 'windows', 'linux', 'macos']),
        'version': f'v{random.randint(0, 9)}-stable',
        'groups': [f'group{random.randint(0, 99)}', f'group{random.randint(0, 99)}'],
        'host': generate_random_host()
    }
    return agent


def generate_random_host():
    host = {
        'architecture': random.choice(['x86_64', 'arm64']),
        'boot': {
            'id': f'bootid{random.randint(0, 9999)}'
        },
        'cpu': {
            'usage': random.uniform(0, 100)
        },
        'disk': {
            'read': {
                'bytes': random.randint(1000, 1000000)
            },
            'write': {
                'bytes': random.randint(1000, 1000000)
            }
        },
        'domain': f'domain{random.randint(0, 1000)}',
        'geo': generate_random_geo(),
        'hostname': f'host{random.randint(0, 1000)}',
        'id': f'id{random.randint(0, 1000)}',
        'ip': f'{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}',
        'mac': f'{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}',
        'name': f'host{random.randint(0, 1000)}',
        'network': {
            'egress': {
                'bytes': random.randint(1000, 1000000),
                'packets': random.randint(100, 10000)
            },
            'ingress': {
                'bytes': random.randint(1000, 1000000),
                'packets': random.randint(100, 10000)
            }
        },
        'os': {
            'family': random.choice(['debian', 'ubuntu', 'macos', 'ios', 'android', 'RHEL']),
            'full': f'{random.choice(["debian", "ubuntu", "macos", "ios", "android", "RHEL"])} {random.randint(0, 99)}.{random.randint(0, 99)}',
            'kernel': f'{random.randint(0, 9)}.{random.randint(0, 9)}.{random.randint(0, 9)}',
            'name': random.choice(['Linux', 'Windows', 'macOS']),
            'platform': random.choice(['platform1', 'platform2']),
            'type': random.choice(['os_type1', 'os_type2']),
            'version': f'{random.randint(0, 9)}.{random.randint(0, 9)}.{random.randint(0, 9)}'
        },
        'pid_ns_ino': f'pid_ns{random.randint(0, 9999)}',
        'risk': {
            'calculated_level': random.choice(['low', 'medium', 'high']),
            'calculated_score': random.uniform(0, 10),
            'calculated_score_norm': random.uniform(0, 1),
            'static_level': random.choice(['low', 'medium', 'high']),
            'static_score': random.uniform(0, 10),
            'static_score_norm': random.uniform(0, 1)
        },
        'type': random.choice(['type1', 'type2']),
        'uptime': random.randint(1000, 1000000)
    }
    return host


def generate_random_geo():
    geo = {
        'city_name': 'CityName',
        'continent_code': 'NA',
        'continent_name': 'North America',
        'country_iso_code': 'US',
        'country_name': 'United States',
        'location': {
            'lat': round(random.uniform(-90, 90), 6),
            'lon': round(random.uniform(-180, 180), 6)
        },
        'name': f'location{random.randint(0, 999)}',
        'postal_code': f'{random.randint(10000, 99999)}',
        'region_iso_code': 'US-CA',
        'region_name': 'California',
        'timezone': 'America/Los_Angeles'
    }
    return geo


def generate_random_package():
    package = {
        'architecture': random.choice(['x86_64', 'arm64']),
        'build_version': f'build{random.randint(0, 9999)}',
        'checksum': f'checksum{random.randint(0, 9999)}',
        'description': f'description{random.randint(0, 9999)}',
        'install_scope': random.choice(['system', 'user']),
        'installed': generate_random_date(),
        'license': random.choice(['GPL', 'MIT', 'Apache']),
        'name': f'package{random.randint(0, 9999)}',
        'path': f'/path/to/package{random.randint(0, 9999)}',
        'reference': f'reference{random.randint(0, 9999)}',
        'size': random.randint(1000, 100000),
        'type': random.choice(['deb', 'rpm']),
        'version': f'{random.randint(0, 9)}.{random.randint(0, 9)}.{random.randint(0, 9)}'
    }
    return package


def generate_random_vulnerability():
    vulnerability = {
        'category': random.choice(['security', 'compliance']),
        'classification': f'classification{random.randint(0, 9999)}',
        'description': f'description{random.randint(0, 9999)}',
        'detected_at': generate_random_date(),
        'enumeration': f'enumeration{random.randint(0, 9999)}',
        'id': f'id{random.randint(0, 9999)}',
        'published_at': generate_random_date(),
        'reference': f'reference{random.randint(0, 9999)}',
        'report_id': f'report{random.randint(0, 9999)}',
        'scanner': {
            'source': random.choice(['Nessus', 'OpenVAS']),
            'vendor': random.choice(['Tenable', 'Greenbone']),
            'condition': random.choice(['is', 'is not']),
            'reference': f'https://cti.wazuh.com/vulnerabilities/cves/CVE-{id}'
        },
        'score': {
            'base': random.uniform(0, 10),
            'environmental': random.uniform(0, 10),
            'temporal': random.uniform(0, 10),
            'version': random.choice(['v2', 'v3'])
        },
        'severity': random.choice(['low', 'medium', 'high']),
        'under_evaluation': random.choice([True, False])
    }
    return vulnerability


def generate_random_data(number):
    data = []
    for _ in range(number):
        event_data = {
            'agent': generate_random_agent(),
            'host': generate_random_host(),
            'package': generate_random_package(),
            'vulnerability': generate_random_vulnerability()
        }
        data.append(event_data)
    return data


def inject_events(ip, port, index, username, password, data):
    url = f'https://{ip}:{port}/{index}/_doc'
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

    inject = input(
        "Do you want to inject the generated data into your indexer? (y/n) ").strip().lower()
    if inject == 'y':
        ip = input(f"Enter the IP of your Indexer (default: '{IP}'): ") or IP
        port = input(f"Enter the port of your Indexer (default: '{PORT}'): ") or PORT
        index = input(f"Enter the index name (default: '{INDEX_NAME}'): ") or INDEX_NAME
        username = input(f"Username (default: '{USERNAME}'): ") or USERNAME
        password = input(f"Password (default: '{PASSWORD}'): ") or PASSWORD
        inject_events(ip, port, index, username, password, data)


if __name__ == "__main__":
    main()
