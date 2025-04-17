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

import logging
logger = logging.getLogger(__name__)

RETRY_TOTAL = int(os.getenv("SIGMA_RETRY_TOTAL", "5"))
RETRY_BACKOFF_FACTOR = float(os.getenv("SIGMA_RETRY_BACKOFF", "0.5"))
RETRY_STATUS_FORCELIST = [500, 502, 503, 504]
RETRY_ATTEMPTS_FOR_HTML = int(os.getenv("SIGMA_RETRY_HTML", "5"))

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
    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()

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

    @retry_html_request
    def select_partition(self, part_id='1'):
        logger.debug(f"Selecting partition {part_id}...")
        self.session.get(f"{self.base_url}/panel.html").raise_for_status()
        data = {'part': f'part{part_id}', 'Submit': 'code'}
        headers = {'Referer': f"{self.base_url}/panel.html"}
        resp = self.session.post(f"{self.base_url}/part.cgi", data=data, headers=headers)
        resp.raise_for_status()
        return BeautifulSoup(resp.text, 'html.parser')

    @retry_html_request
    def get_part_status(self, soup):
        p_tag = soup.find('p')
        alarm_status = None
        if p_tag:
            spans = p_tag.find_all('span')
            if len(spans) >= 2:
                alarm_status = spans[1].get_text(strip=True)
        logger.debug(f"Extracted alarm_status: {alarm_status}")

        text = soup.get_text("\n", strip=True)
        battery = re.search(r"(\d+\.?\d*)\s*Volt", text)
        ac = re.search(r"Παροχή\s*230V:\s*(ΝΑΙ|NAI|OXI|Yes|No)", text, re.IGNORECASE)
        logger.debug(f"Extracted battery: {battery.group(1) if battery else None}, AC: {ac.group(1) if ac else None}")
        return {
            'alarm_status': alarm_status,
            'battery_volt': float(battery.group(1)) if battery else None,
            'ac_power': ac.group(1) if ac else None
        }

    @retry_html_request
    def get_zones(self, soup):
        logger.debug("Getting zones...")
        link = soup.find('a', string=re.compile('ζωνών', re.I))
        url = link['href'] if link and link.get('href') else 'zones.html'
        full_url = f"{self.base_url}/{url.lstrip('/')}"
        resp = self.session.get(full_url, headers={'Referer': f"{self.base_url}/part.cgi"})
        resp.raise_for_status()

        table = BeautifulSoup(resp.text, 'html.parser').find('table', class_='normaltable')
        zones = []
        if table:
            for row in table.find_all('tr')[1:]:
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
        return zones


if __name__ == '__main__':
    MAX_TOTAL_ATTEMPTS = 3
    for attempt in range(1, MAX_TOTAL_ATTEMPTS + 1):
        try:
            logger.info(f"Attempt {attempt}/{MAX_TOTAL_ATTEMPTS} to fetch Sigma Alarm data")

            client = SigmaClient(BASE_URL, USERNAME, PASSWORD)
            client.login()

            part_soup = client.select_partition(part_id='1')
            status = client.get_part_status(part_soup)
            zones = client.get_zones(part_soup)

            parsed_status, zones_bypassed = _parse_alarm_status(status['alarm_status'])

            if not parsed_status or status['battery_volt'] is None or not zones:
                raise ValueError("Parsed data incomplete or invalid, retrying full flow")

            output = {
                "status": parsed_status,
                "zones_bypassed": zones_bypassed,
                "battery_volt": status['battery_volt'],
                "ac_power": _to_bool(status['ac_power']),
                "zones": [
                    {
                        "zone": z['zone'],
                        "description": z['description'],
                        "status": _to_openclosed(z['status']),
                        "bypass": _to_bool(z['bypass'])
                    }
                    for z in zones
                ]
            }

            print(json.dumps(output, indent=2, ensure_ascii=False))
            break  # ✅ Exit loop on success

        except Exception as e:
            logger.warning(f"Full flow failed on attempt {attempt}: {e}")
            if attempt == MAX_TOTAL_ATTEMPTS:
                logger.exception("Max retry attempts exceeded. Final failure.")

