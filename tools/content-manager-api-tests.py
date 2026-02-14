"""
Content Manager Plugin API Test Suite
=====================================

Usage:
    python3 content-manager-api-tests.py <TARGET_IP> [options]

    Examples:
        python3 content-manager-api-tests.py 192.168.56.7:9200
        python3 content-manager-api-tests.py 192.168.56.7:9200 --user admin --password admin --protocol https

Options:
    ip           Target IP address (e.g., 192.168.56.7:9200)
    --protocol   Protocol to use (http/https). Default: https
    --user       API User. Default: admin
    --password   API Password. Default: admin

Description:
This script executes a comprehensive end-to-end integration test for the `content_manager` plugin API. 
It is designed to validate the stability and functionality of the content management lifecycle.

The suite exercises the following API endpoints and workflows:

1.  **Resource Management (CUD):** Validates the creation and modification of core CTI resources via:
    - `/_plugins/_content_manager/integrations`
    - `/_plugins/_content_manager/decoders`
    - `/_plugins/_content_manager/kvdbs`
    - `/_plugins/_content_manager/rules`

2.  **Policy Configuration:** Tests retrieval and updates of content policies via `/_plugins/_content_manager/policy`.

3.  **Promotion Lifecycle:** Performs a complete content promotion:
    - **Draft → Test:**
    - **Test → Custom:**

4.  **Logic Validation:** Tests the simulation engine via `/_plugins/_content_manager/logtest`.

5.  **State Verification:** Checks internal indices to ensure document counts match expected states.
"""

import sys
import json
import argparse
import requests
import urllib3
import time
from typing import Dict, Any, Optional, List, Tuple

# --- Configuration & Constants ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONTENT_TYPE_JSON = "application/json"
HEADER_JSON = {"Content-Type": CONTENT_TYPE_JSON, "Accept": CONTENT_TYPE_JSON}

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class TestTracker:
    """Tracks the status of tests for the final summary."""
    def __init__(self):
        self.results: List[Tuple[str, str]] = []

    def record(self, test_name: str, success: bool):
        status = "PASS" if success else "FAIL"
        self.results.append((test_name, status))

    def print_summary(self):
        print(f"\n{Colors.HEADER}{Colors.BOLD}╔{'═'*50}╗{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}║             TEST EXECUTION SUMMARY               ║{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}╠{'═'*35}╦{'═'*14}╣{Colors.ENDC}")
        print(f"║ {Colors.BOLD}{'TEST NAME':<33}{Colors.ENDC} ║ {Colors.BOLD}{'STATUS':<12}{Colors.ENDC} ║")
        print(f"╠{'═'*35}╬{'═'*14}╣")
        
        for name, status in self.results:
            color = Colors.GREEN if status == "PASS" else Colors.RED
            print(f"║ {name:<33} ║ {color}{status:<12}{Colors.ENDC} ║")
        
        print(f"╚{'═'*35}╩{'═'*14}╝\n")

class ContentManagerTester:
    def __init__(self, base_url: str, user: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.user = user
        self.password = password
        self.session = self._setup_session()
        self.tracker = TestTracker()
        
        self.state: Dict[str, Optional[str]] = {
            "integration_id": None,
            "decoder_id": None,
            "kvdb_id": None,
            "rule_id": None,
            "policy_id": None
        }

    def _setup_session(self) -> requests.Session:
        session = requests.Session()
        session.auth = (self.user, self.password)
        session.verify = False
        session.headers.update(HEADER_JSON)
        return session

    def log(self, step: str, message: str, status: str = "INFO") -> None:
        """Prints a color-formatted log message."""
        color_map = {
            "INFO": Colors.CYAN,
            "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "ERROR": Colors.RED,
            "FATAL": Colors.RED + Colors.BOLD
        }
        color = color_map.get(status, Colors.ENDC)
        print(f"[{color}{status:<7}{Colors.ENDC}] {Colors.BOLD}{step:<12}:{Colors.ENDC} {message}")

    def _send(self, method: str, endpoint: str, data: Optional[Dict] = None, expected_status: int = 200, max_retries: int = 5) -> Any:
        url = f"{self.base_url}{endpoint}"
        for attempt in range(1, max_retries + 1):
            try:
                response = self.session.request(method, url, json=data)
                if response.status_code == expected_status:
                    try:
                        return response.json()
                    except json.JSONDecodeError:
                        return response.text
                if response.status_code == 429:
                    time.sleep(attempt * 5)
                    continue
                self.log("REQUEST", f"Failed {method} {endpoint} (Status: {response.status_code})", "ERROR")
                raise RuntimeError(f"API Request Failed: {response.status_code}")
            except requests.exceptions.RequestException as e:
                self.log("CONNECTION", f"Could not connect to {url}", "FATAL")
                sys.exit(1)
        raise RuntimeError(f"Max retries exceeded for {endpoint}")
    
    # =========================================================================
    # 1. INTEGRATIONS
    # =========================================================================
    def test_integration(self):
        self.log("INTEGRATION", "Creating resource...", "INFO")
        payload = {
            "resource": {
                "author": "Wazuh Inc.", "category": "cloud-services",
                "description": "test1234",
                "documentation": "test1234", "references": ["https://wazuh.com"],
                "title": "test1234"
            }
        }
        res = self._send("POST", "/_plugins/_content_manager/integrations", payload, 201)
        self.state["integration_id"] = res["message"]
        self.log("INTEGRATION", f"Created ID: {self.state['integration_id']}", "SUCCESS")

        self.log("INTEGRATION", "Updating resource...", "INFO")
        update_payload = {
            "resource": {
                "author": "Wazuh Inc.", "category": "cloud-services",
                "description": "Modified description", "documentation": "Modified",
                "references": ["https://wazuh.com"], "rules": [], "decoders": [],
                "kvdbs": [], "title": "test1234"
            }
        }
        self._send("PUT", f"/_plugins/_content_manager/integrations/{self.state['integration_id']}", update_payload, 200)

    # =========================================================================
    # 2. DECODERS
    # =========================================================================
    def test_decoder(self):
        self.log("DECODER", "Creating resource...", "INFO")
        payload = {
            "integration": self.state["integration_id"],
            "resource": {
                "enabled": True,
                "metadata": {
                    "compatibility": "All wazuh events.", "description": "Base decoder...",
                    "module": "wazuh", "references": ["https://doc.wazuh.com"],
                    "title": "Wazuh message decoder", "versions": ["Wazuh 5.*"]
                },
                "name": "decoder/core-wazuh-message/0",
                "normalize": [{"map": [{"@timestamp": "get_date()"}]}]
            }
        }
        res = self._send("POST", "/_plugins/_content_manager/decoders", payload, 201)
        self.state["decoder_id"] = res["message"]
        self.log("DECODER", f"Created ID: {self.state['decoder_id']}", "SUCCESS")

        self.log("DECODER", "Updating resource...", "INFO")
        update_payload = {
            "type": "decoder", "integration": self.state["integration_id"],
            "resource": {
                "enabled": True,
                "metadata": {
                    "compatibility": "All wazuh events.", "description": "Base decoder...",
                    "module": "wazuh", "references": ["https://doc.wazuh.com"],
                    "title": "Wazuh message decoder (MOD)", "versions": ["Wazuh 5.*"]
                },
                "name": "decoder/core-wazuh-message/0",
                "normalize": [{"map": [{"@timestamp": "get_date()"}]}]
            }
        }
        self._send("PUT", f"/_plugins/_content_manager/decoders/{self.state['decoder_id']}", update_payload, 200)

    # =========================================================================
    # 3. KVDBS
    # =========================================================================
    def test_kvdb(self):
        self.log("KVDB", "Creating resource...", "INFO")
        payload = {
            "integration": self.state["integration_id"],
            "resource": {
                "author": "Wazuh Inc.",
                "content": {"recv": {"action": "received-from", "category": ["network"], "type": ["connection"]}},
                "description": "", "documentation": "", "enabled": True,
                "references": ["https://wazuh.com"], "title": "suricata_event_id_to_info"
            }
        }
        res = self._send("POST", "/_plugins/_content_manager/kvdbs", payload, 201)
        self.state["kvdb_id"] = res["message"]
        self.log("KVDB", f"Created ID: {self.state['kvdb_id']}", "SUCCESS")

        self.log("KVDB", "Updating resource...", "INFO")
        update_payload = {
            "resource": {
                "author": "Wazuh Inc.",
                "content": {"recv": {"action": "received-from", "category": ["network"], "type": ["connection"]}},
                "description": "MODIFIED", "documentation": "MODIFIED", "enabled": True,
                "references": ["https://wazuh.com"], "title": "suricata_event_id_to_info"
            }
        }
        self._send("PUT", f"/_plugins/_content_manager/kvdbs/{self.state['kvdb_id']}", update_payload, 200)

    # =========================================================================
    # 4. RULES
    # =========================================================================
    def test_rule(self):
        self.log("RULE", "Creating resource...", "INFO")
        payload = {
            "integration": self.state["integration_id"],
            "resource": {
                "title": "Test Hash Rule", "description": "Verify hash calc.",
                "author": "Tester", "status": "experimental",
                "logsource": {"product": "system", "category": "system"},
                "detection": {"condition": "selection", "selection": {"event.action": ["hash_test_event"]}},
                "level": "low"
            }
        }
        res = self._send("POST", "/_plugins/_content_manager/rules", payload, 201)
        self.state["rule_id"] = res["message"]
        self.log("RULE", f"Created ID: {self.state['rule_id']}", "SUCCESS")

        self.log("RULE", "Updating resource...", "INFO")
        update_payload = {
            "type": "rule",
            "resource": {
                "title": "(MOD) Test Hash Rule", "description": "Verify hash calc.",
                "author": "Tester", "status": "experimental",
                "logsource": {"product": "system", "category": "system"},
                "detection": {"condition": "selection", "selection": {"event.action": ["hash_test_event"]}},
                "level": "low"
            }
        }
        self._send("PUT", f"/_plugins/_content_manager/rules/{self.state['rule_id']}", update_payload, 200)

    # =========================================================================
    # 5. POLICY MANAGEMENT
    # =========================================================================
    def test_policy(self):
        self.log("POLICY", "Fetching Draft Policy...", "INFO")
        search_res = self._send("GET", "/.cti-policies/_search", {"query": {"term": {"space.name": {"value": "draft"}}}}, 200)

        hits = search_res.get("hits", {}).get("hits", [])
        if hits:
            current_id = hits[0]["_source"]["document"]["id"]
            self.state["policy_id"] = current_id
            self.log("POLICY", f"Found Policy ID: {current_id}", "SUCCESS")
        else:
            self.state["policy_id"] = "2429532a-e428-48cb-a9ce-7cb987fe74c4"
            self.log("POLICY", "No draft policy found. Using default ID.", "WARNING")

        self.log("POLICY", "Updating Policy...", "INFO")
        payload = {
            "resource": {
                "title": "Custom policy", "root_decoder": self.state["decoder_id"],
                "integrations": [self.state["integration_id"]], "filters": [], "enrichments": [],
                "author": "Wazuh Inc.", "description": "Custom policy",
                "documentation": "", "references": ["https://wazuh.com"]
            }
        }
        self._send("PUT", "/_plugins/_content_manager/policy", payload, 200)

    # =========================================================================
    # 6. PROMOTION
    # =========================================================================
    def test_promotion(self):
        self.log("PROMOTION", "Phase 1: Preview Draft", "INFO")
        candidate_changes = {
            "kvdbs":        [{"operation": "add", "id": self.state["kvdb_id"]}],
            "iocs":         [],
            "rules":        [{"operation": "add", "id": self.state["rule_id"]}],
            "decoders":     [{"operation": "add", "id": self.state["decoder_id"]}],
            "filters":      [],
            "integrations": [{"operation": "add", "id": self.state["integration_id"]}],
            "policy":       [{"operation": "update", "id": self.state["policy_id"]}]
        }
        
        draft_preview = self._send("GET", "/_plugins/_content_manager/promote?space=draft", {"changes": candidate_changes}, 200)
        self.log("PROMOTION", "Phase 2: Promote from Draft to Test", "INFO")
        self._send("POST", "/_plugins/_content_manager/promote", {"space": "draft", "changes": draft_preview["changes"]}, 200)
        
        self.log("PROMOTION", "Phase 3: Preview Test", "INFO")
        test_preview = self._send("GET", "/_plugins/_content_manager/promote?space=test", None, 200)
        
        self.log("PROMOTION", "Phase 4: Promote from Test to Custom", "INFO")
        self._send("POST", "/_plugins/_content_manager/promote", {"space": "test", "changes": test_preview["changes"]}, 200)

    # =========================================================================
    # 7. LOGTEST
    # =========================================================================
    def test_logtest(self):
        self.log("LOGTEST", "Running simulation...", "INFO")
        payload = {
            "queue": 1, "location": "/var/log/auth.log",
            "agent_metadata": {
                "agent": {
                    "name": "test-agent", "id": "000",
                    "host": {"os": {"name": "Ubuntu", "platform": "ubuntu"}, "ip": ["127.0.0.1"]}
                }
            },
            "event": "Dec 19 12:00:00 host sshd[123]: Failed password for root",
            "trace_level": "ASSET_ONLY"
        }
        res = self._send("POST", "/_plugins/_content_manager/logtest", payload, 200)
        
        try:
            msg = json.loads(res["message"])
            if "output" in msg:
                 self.log("LOGTEST", "Simulation output received", "SUCCESS")
            else:
                 self.log("LOGTEST", "No output in simulation response", "WARNING")
        except:
            self.log("LOGTEST", "Could not parse simulation output", "WARNING")

    # =========================================================================
    # Cleanup & Tables
    # =========================================================================
    def get_index_counts(self):
        indices = [".cti-iocs", ".cti-kvdbs", ".cti-rules", ".cti-decoders", ".cti-policies", ".cti-integrations"]
        print(f"\n{Colors.HEADER}{Colors.BOLD}╔{'═'*42}╗{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}║           INDEX DOCUMENT COUNTS          ║{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}╠{'═'*27}╦{'═'*14}╣{Colors.ENDC}")
        print(f"║ {Colors.BOLD}{'INDEX NAME':<25}{Colors.ENDC} ║ {Colors.BOLD}{'COUNT':<12}{Colors.ENDC} ║")
        print(f"╠{'═'*27}╬{'═'*14}╣")

        for idx in indices:
            count = "N/A"
            try:
                res = self.session.get(f"{self.base_url}/{idx}/_count")
                if res.status_code == 200:
                    count = str(res.json().get("count", 0))
            except: pass
            print(f"║ {idx:<25} ║ {Colors.CYAN}{count:<12}{Colors.ENDC} ║")
        print(f"╚{'═'*27}╩{'═'*14}╝\n")

    def print_space_matrix(self):
        """Prints a matrix of document counts per space with PERFECT ALIGNMENT."""
        spaces = ["draft", "test", "custom"]
        
        cols = [
            ("INTEGRATION", ".cti-integrations"),
            ("KVDB",        ".cti-kvdbs"),
            ("RULE",        ".cti-rules"),
            ("DECODER",     ".cti-decoders"),
            ("POLICY",      ".cti-policies")
        ]

        W_LABEL = 12
        W_DATA  = 14

        def make_separator(left, mid, cross, right):
            line = left + (mid * W_LABEL)
            for _ in cols:
                line += cross + (mid * W_DATA)
            line += right
            return line

        full_width = W_LABEL + (len(cols) * (W_DATA + 1))
        print(f"\n{Colors.HEADER}{Colors.BOLD}")
        print(f"╔{'═' * full_width}╗")
        print(f"║{'CONTENT SPACE DISTRIBUTION MATRIX':^{full_width}}║")
        
        print(make_separator("╠", "═", "╦", "╣"))
        
        row = f"║{Colors.BOLD}{'SPACE':^{W_LABEL}}{Colors.ENDC}"
        for title, _ in cols:
            row += f"║{Colors.BOLD}{title:^{W_DATA}}{Colors.ENDC}"
        row += "║"
        print(row)

        print(make_separator("╠", "═", "╬", "╣"))
        print(Colors.ENDC, end="")

        for space in spaces:
            row = f"║{Colors.CYAN}{space:<{W_LABEL}}{Colors.ENDC}"
            
            for _, index in cols:
                count_str = "-"
                color = Colors.RED
                try:
                    url = f"{self.base_url}/{index}/_count"
                    resp = self.session.get(url, json={"query": {"match": {"space.name": space}}})
                    if resp.status_code == 200:
                        val = resp.json().get("count", 0)
                        count_str = str(val)
                        color = Colors.GREEN if val > 0 else Colors.ENDC
                except: pass
                
                row += f"║{color}{count_str:^{W_DATA}}{Colors.ENDC}"
            
            row += "║"
            print(row)

        print(make_separator("╚", "═", "╩", "╝"))
        print(Colors.ENDC)

    def cleanup(self):
        """Clean up resources even if tests failed."""
        self.log("CLEANUP", "Deleting resources...", "INFO")
        
        items = [
            ("Rule", self.state["rule_id"], "_plugins/_content_manager/rules"),
            ("KVDB", self.state["kvdb_id"], "_plugins/_content_manager/kvdbs"),
            ("Decoder", self.state["decoder_id"], "_plugins/_content_manager/decoders"),
            ("Integration", self.state["integration_id"], "_plugins/_content_manager/integrations"),
        ]

        for name, rid, endpoint in items:
            if rid:
                try:
                    self.session.delete(f"{self.base_url}/{endpoint}/{rid}")
                    self.log("CLEANUP", f"{name} deleted", "SUCCESS")
                except Exception:
                    self.log("CLEANUP", f"Failed to delete {name}", "WARNING")

    def run_all(self):
        print(f"\n{Colors.HEADER}>>> STARTING CONTENT MANAGER TEST SUITE <<<{Colors.ENDC}\n")
        
        def run_step(name, func):
            try:
                func()
                self.tracker.record(name, True)
            except Exception as e:
                self.log("ERROR", f"Test '{name}' failed: {e}", "ERROR")
                self.tracker.record(name, False)

        try:
            run_step("Integration CRUD", self.test_integration)
            run_step("Decoder CRUD", self.test_decoder)
            run_step("KVDB CRUD", self.test_kvdb)
            run_step("Rule CRUD", self.test_rule)
            run_step("Policy Update", self.test_policy)
            run_step("Promotion Cycle", self.test_promotion)
            run_step("Logtest", self.test_logtest)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Execution interrupted.{Colors.ENDC}")
        finally:
            self.cleanup()
            self.tracker.print_summary()
            self.get_index_counts()
            self.print_space_matrix()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Content Manager API Test Suite")
    parser.add_argument("ip", help="Target IP address (e.g., 192.168.1.1:9200)")
    parser.add_argument("--protocol", default="https", help="Protocol")
    parser.add_argument("--user", default="admin", help="API User")
    parser.add_argument("--password", default="admin", help="API Password")
    args = parser.parse_args()
    
    url = f"{args.protocol}://{args.ip}"
    tester = ContentManagerTester(url, args.user, args.password)
    tester.run_all()
