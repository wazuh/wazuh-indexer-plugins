#!/usr/bin/env python3
"""
Event generator for Engine Filters.

This script generates sample filter documents for the .engine-filters index.
Filters are user-generated rules used by the Wazuh Engine to decide whether
an event should continue through the processing pipeline.
"""

import argparse
import json
import random
import uuid
from datetime import datetime, timedelta


class FilterGenerator:
    """Generates sample filter documents for testing."""

    FILTER_TYPES = ["pre-filter", "post-filter"]

    SAMPLE_CHECKS = [
        "$host.os.platform == 'ubuntu'",
        "$host.os.platform == 'windows'",
        "$event.severity >= 'high'",
        "$source.ip in ['10.0.0.0/8', '172.16.0.0/12']",
        "$destination.port == 22 or $destination.port == 3389",
        "$event.category == 'authentication' and $event.outcome == 'failure'",
        "$user.name != 'admin'",
        "$process.name in ['cmd.exe', 'powershell.exe']",
        "$file.extension in ['.exe', '.dll', '.sys']",
        "$event.action == 'network-connection'"
    ]

    DESCRIPTIONS = [
        "Filter for Ubuntu systems only",
        "Filter for Windows systems",
        "High severity events filter",
        "Internal network filter",
        "SSH and RDP connection filter",
        "Failed authentication filter",
        "Non-admin user filter",
        "Windows command execution filter",
        "Executable file filter",
        "Network connection filter"
    ]

    AUTHORS = [
        {"name": "Wazuh, Inc.", "url": "https://wazuh.com"},
        {"name": "Security Team", "url": "https://example.com"},
        {"name": "Compliance Team", "url": "https://compliance.example.com"}
    ]

    def generate_filter(self, index=0):
        """Generate a single filter document."""
        filter_type = random.choice(self.FILTER_TYPES)
        check_index = index % len(self.SAMPLE_CHECKS)
        author = random.choice(self.AUTHORS)

        # Generate a date within the last year
        days_ago = random.randint(0, 365)
        date = datetime.now() - timedelta(days=days_ago)

        return {
            "filter": {
                "name": f"filter/{filter_type.split('-')[0]}/{index}",
                "id": str(uuid.uuid4()),
                "enabled": random.choice([True, True, True, False]),  # 75% enabled
                "type": filter_type,
                "check": self.SAMPLE_CHECKS[check_index],
                "metadata": {
                    "description": self.DESCRIPTIONS[check_index],
                    "author": {
                        "name": author["name"],
                        "url": author["url"],
                        "date": date.strftime("%Y/%m/%d")
                    }
                }
            }
        }

    def generate_batch(self, count):
        """Generate a batch of filter documents."""
        return [self.generate_filter(i) for i in range(count)]


def main():
    """Main function to generate filter documents."""
    parser = argparse.ArgumentParser(
        description="Generate sample filter documents for .engine-filters index"
    )
    parser.add_argument(
        "-n", "--number",
        type=int,
        default=10,
        help="Number of filter documents to generate (default: 10)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path (default: stdout)"
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty print JSON output"
    )

    args = parser.parse_args()

    generator = FilterGenerator()
    filters = generator.generate_batch(args.number)

    if args.pretty:
        output = json.dumps(filters, indent=2)
    else:
        output = json.dumps(filters)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Generated {args.number} filter documents to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
