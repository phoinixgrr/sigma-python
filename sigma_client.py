import requests
import os
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
import re
import random
import json
import logging
import time

from log_config import setup_logging
setup_logging()

logger = logging.getLogger(__name__)

RETRY_TOTAL = int(os.getenv("SIGMA_RETRY_TOTAL", "5"))
RETRY_BACKOFF_FACTOR = float(os.getenv("SIGMA_RETRY_BACKOFF", "0.5"))
RETRY_STATUS_FORCELIST = [500, 502, 503, 504]
RETRY_ATTEMPTS_FOR_HTML = int(os.getenv("SIGMA_RETRY_HTML", "5"))
ACTION_ATTEMPTS = int(os.getenv("SIGMA_ACTION_MAX_ATTEMPTS", "5"))

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

ALARM_STATUS_MAP = {
    "AΦOΠΛIΣMENO": {"status": "Disarmed", "zones_bypassed": None},
    "OΠΛIΣMENO ME ZΩNEΣ BYPASS": {"status": "Armed", "zones_bypassed": True},
    "OΠΛIΣMENO": {"status": "Armed", "zones_bypassed": False},
    "ΠEPIMETPIKH OΠΛIΣH ME ZΩNEΣ BYPASS": {"status": "Perimeter Armed", "zones_bypassed": True},
    "ΠEPIMETPIKH OΠΛIΣH": {"status": "Armed", "zones_bypassed": False},
}

def _to_bool(val):
    if not val:
        return None
    v = val.strip().upper()
    if v in ("ΝΑΙ", "NAI", "YES"):
        return True
    if v in ("OXI", "NO"):
        return False
    return None

def _to_openclosed(val):
    if not val:
        return None
    v = val.strip().lower()
    if v == "κλειστή":
        return "Closed"
    if v == "ανοικτή":
        return "Open"
    return val

def _parse_alarm_status(raw_val):
    if not raw_val:
        return None, None
    cleaned_val = raw_val.strip().upper()
    mapping = ALARM_STATUS_MAP.get(cleaned_val)
    logger.debug(f"Raw alarm status: {raw_val}, Normalized: {cleaned_val}, Parsed: {mapping}")
    if mapping:
        return mapping["status"], mapping["zones_bypassed"]
    return None, None

def retry_html_request(func):
    def wrapper(*args, **kwargs):
        for attempt in range(RETRY_ATTEMPTS_FOR_HTML):
            try:
                return func(*args, **kwargs)
            except (AttributeError, TypeError, IndexError) as e:
                logger.warning(f"HTML parsing failed on attempt {attempt+1}/{RETRY_ATTEMPTS_FOR_HTML}: {e}")
                time.sleep(RETRY_BACKOFF_FACTOR * (2 ** attempt))
        raise RuntimeError(f"HTML parsing failed after {RETRY_ATTEMPTS_FOR_HTML} attempts.")
    return wrapper

class SigmaClient:
    def __init__(self, base_url, username, password, max_attempts=3):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.max_attempts = max_attempts
        self.session = requests.Session()
        self._session_authenticated = False  # ✅ Initialize here

        # Retry setup
        retry = Retry(
            total=RETRY_TOTAL,
            backoff_factor=RETRY_BACKOFF_FACTOR,
            status_forcelist=RETRY_STATUS_FORCELIST,
            allowed_methods=["GET", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    @retry_html_request
    def _get_soup(self, path):
        url = f"{self.base_url}/{path.lstrip('/')}"
        logger.debug(f"Fetching URL: {url} (attempt 1)")
        resp = self.session.get(url)
        resp.raise_for_status()
        return BeautifulSoup(resp.text, 'html.parser')

    def _encrypt(self, secret, token):
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + ord(token[i % len(token)])) % 256
            S[i], S[j] = S[j], S[i]
        i = j = 0
        num = random.randint(1, 7)
        prefix = token[1:1 + num]
        suffix_len = 14 - num - len(secret)
        suffix = token[num:num + suffix_len]
        newpass = prefix + secret + suffix + str(num) + str(len(secret))
        out_chars = []
        for ch in newpass:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            K = S[(S[i] + S[j]) % 256]
            out_chars.append(chr(ord(ch) ^ K))
        cipher = ''.join(out_chars)
        hexstr = ''.join(f"{ord(c):02x}" for c in cipher)
        gen_val = str(len(cipher))
        return hexstr, gen_val

    @retry_html_request
    def _submit_login(self):
        soup = self._get_soup('login.html')
        token = soup.find('input', {'name': 'gen_input'})['value']
        encrypted, gen_val = self._encrypt(self.password, token)
        data = {
            'username': self.username,
            'password': encrypted,
            'gen_input': gen_val,
            'Submit': 'Apply'
        }
        logger.debug("Submitting login credentials...")
        self.session.post(f"{self.base_url}/login.html", data=data).raise_for_status()

    @retry_html_request
    def _submit_pin(self):
        soup = self._get_soup('user.html')
        token = soup.find('input', {'name': 'gen_input'})['value']
        encrypted, gen_val = self._encrypt(self.password, token)
        data = {'password': encrypted, 'gen_input': gen_val, 'Submit': 'code'}
        logger.debug("Submitting PIN...")
        self.session.post(f"{self.base_url}/ucode", data=data).raise_for_status()

    def login(self):
        self._submit_login()
        self._submit_pin()
        self._session_authenticated = True
        logger.info("Session login completed and session is now marked as authenticated.")

    def perform_action(self, action):
        action_map = {
            "arm": "arm.html",
            "disarm": "disarm.html",
            "stay": "stay.html"
        }
        expected_status_map = {
            "arm": "Armed",
            "stay": "Perimeter Armed",
            "disarm": "Disarmed"
        }

        if action not in action_map:
            raise ValueError(f"Unknown action: {action}")

        expected_status = expected_status_map[action]

        for attempt in range(1, self.max_attempts + 1):
            try:
                logger.info(f"Action attempt {attempt}/{self.max_attempts}: {action}")

                self.login()
                logger.debug("Checking current alarm status before action...")
                part_soup = self.select_partition(part_id='1')
                pre_data = self.get_zones_with_status(part_soup)
                current_status, _ = _parse_alarm_status(pre_data['alarm_status'])
                logger.info(f"Current alarm status: {current_status}")

                # Pre-check: skip redundant actions
                if current_status == expected_status:
                    logger.warning(f"System already in expected state '{expected_status}', skipping action.")
                    return None

                # Perform the action
                url = f"{self.base_url}/{action_map[action]}"
                logger.info(f"Performing alarm action '{action}' at URL: {url}")
                resp = self.session.get(url, timeout=5)
                resp.raise_for_status()

                logger.debug("Waiting before verifying alarm state...")
                time.sleep(4)

                # Check post-action status
                part_soup = self.select_partition(part_id='1')
                post_data = self.get_zones_with_status(part_soup)
                final_status, _ = _parse_alarm_status(post_data['alarm_status'])
                logger.info(f"Post-action alarm status: {final_status}")

                if final_status == expected_status:
                    logger.info(f"Action '{action}' verified successfully.")
                    return resp
                else:
                    raise ValueError(
                        f"Expected status '{expected_status}' not reached after action. Got '{final_status}'."
                    )

            except Exception as e:
                logger.warning(f"Action flow failed on attempt {attempt}: {e}")
                time.sleep(RETRY_BACKOFF_FACTOR * (2 ** (attempt - 1)))
                if attempt == self.max_attempts:
                    logger.exception("Max action retry attempts exceeded. Final failure.")
                    raise


    @retry_html_request
    def select_partition(self, part_id='1'):
        logger.debug(f"Selecting partition {part_id}...")
        self.session.get(f"{self.base_url}/panel.html").raise_for_status()
        data = {'part': f'part{part_id}', 'Submit': 'code'}
        headers = {'Referer': f"{self.base_url}/panel.html"}
        resp = self.session.post(f"{self.base_url}/part.cgi", data=data, headers=headers)
        resp.raise_for_status()
        return BeautifulSoup(resp.text, 'html.parser')

    def try_zones_directly(self):
        if not self._session_authenticated:
            logger.info("Session is not authenticated yet — skipping direct zones fetch.")
            return None

        try:
            logger.info("Using existing session to fetch zones.html directly...")
            part_soup = self.select_partition(part_id='1')
            return self.get_zones_with_status(part_soup)
        except Exception as e:
            logger.warning(f"Direct zones.html fetch failed: {e}")
            return None

    def safe_get_status(self):
        try:
            data = self.try_zones_directly()

            # General failure condition: treat any missing key parts as invalid
            if not data or not data.get("alarm_status") or not data.get("zones"):
                raise ValueError("zones.html fetch returned incomplete or invalid data")

            logger.info("Successfully fetched data via existing session (zones.html).")
            return data

        except Exception as e:
            logger.warning(f"Direct zones.html fetch failed or invalid: {e}")
            logger.info("Fallback to full authentication flow...")
            self.login()
            part_soup = self.select_partition(part_id='1')
            return self.get_zones_with_status(part_soup)


    @retry_html_request
    def get_zones_with_status(self, soup):
        logger.debug("Getting zones...")

        # Find the link to the zones page from the partition page
        link = soup.find('a', string=re.compile('ζωνών', re.I))
        url = link['href'] if link and link.get('href') else 'zones.html'
        full_url = f"{self.base_url}/{url.lstrip('/')}"

        # Fetch zones.html
        resp = self.session.get(full_url, headers={'Referer': f"{self.base_url}/part.cgi"})
        resp.raise_for_status()

        # 💥 DEBUG: Dump raw HTML to log file
        with open("/tmp/zones_debug.html", "w", encoding="utf-8") as f:
            f.write(resp.text)

        logger.debug("Saved raw zones.html response to /tmp/zones_debug.html")

        # Parse zones.html content
        zones_soup = BeautifulSoup(resp.text, 'html.parser')
        text = zones_soup.get_text("\n", strip=True)

        # Extract alarm status from heading like "Τμήμα 1 : ΑΦΟΠΛΙΣΜΕΝΟ"
        alarm_match = re.search(r"Τμήμα\s*\d+\s*:\s*(.+)", text)
        alarm_status = alarm_match.group(1).strip() if alarm_match else None

        # Extract battery voltage from "Μπαταρία: 13.5 Volt"
        battery_match = re.search(r"Μπαταρία:\s*([\d.]+)\s*Volt", text)
        battery_volt = float(battery_match.group(1)) if battery_match else None

        # Extract AC power status from "Παροχή 230V: NAI"
        ac_match = re.search(r"Παροχή\s*230V:\s*(ΝΑΙ|NAI|OXI|Yes|No)", text, re.IGNORECASE)
        ac_power = ac_match.group(1) if ac_match else None

        # Parse the zones table
        table = zones_soup.find('table', class_='normaltable')
        zones = []
        if table:
            for row in table.find_all('tr')[1:]:  # Skip header
                cols = row.find_all('td')
                if len(cols) >= 4:
                    zone_data = {
                        'zone': cols[0].get_text(strip=True),
                        'description': cols[1].get_text(strip=True),
                        'status': cols[2].get_text(strip=True),
                        'bypass': cols[3].get_text(strip=True),
                    }
                    logger.debug(f"Parsed zone: {zone_data}")
                    zones.append(zone_data)

        return {
            'alarm_status': alarm_status,
            'battery_volt': battery_volt,
            'ac_power': ac_power,
            'zones': zones
        }
    
if __name__ == "__main__":
    BASE_URL = os.getenv("SIGMA_BASE_URL")
    USERNAME = os.getenv("SIGMA_USERNAME")
    PASSWORD = os.getenv("SIGMA_PASSWORD")
    ACTION = os.getenv("SIGMA_ACTION")  # optional: arm, disarm, stay

    MAX_TOTAL_ATTEMPTS = int(os.getenv("SIGMA_MAX_ATTEMPTS", 5))

    for attempt in range(1, MAX_TOTAL_ATTEMPTS + 1):
        try:
            logger.info(f"Attempt {attempt}/{MAX_TOTAL_ATTEMPTS} to interact with Sigma Alarm")
            client = SigmaClient(BASE_URL, USERNAME, PASSWORD, max_attempts=MAX_TOTAL_ATTEMPTS)

            if ACTION:
                logger.info(f"Performing action: {ACTION}")
                client.perform_action(ACTION)
                print(json.dumps({"action": ACTION, "success": True}))
            else:
                data = client.safe_get_status()

                parsed_status, zones_bypassed = _parse_alarm_status(data['alarm_status'])

                if not parsed_status or data['battery_volt'] is None or not data['zones']:
                    raise ValueError("Parsed data incomplete or invalid, retrying full flow")

                output = {
                    "status": parsed_status,
                    "zones_bypassed": zones_bypassed,
                    "battery_volt": data['battery_volt'],
                    "ac_power": _to_bool(data['ac_power']),
                    "zones": [
                        {
                            "zone": z['zone'],
                            "description": z['description'],
                            "status": _to_openclosed(z['status']),
                            "bypass": _to_bool(z['bypass'])
                        }
                        for z in data['zones']
                    ]
                }

                output["session_reused"] = client._session_authenticated

                print(json.dumps(output, indent=2, ensure_ascii=False))
            break

        except Exception as e:
            logger.warning(f"Flow failed on attempt {attempt}: {e}")
            if attempt == MAX_TOTAL_ATTEMPTS:
                logger.exception("Max retry attempts exceeded. Final failure.")
