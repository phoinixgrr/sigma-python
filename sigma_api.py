from flask import Flask, jsonify, request
import os
from sigma_client import SigmaClient, _parse_alarm_status, _to_bool, _to_openclosed
from log_config import setup_logging

setup_logging()
import logging
logger = logging.getLogger(__name__)

app = Flask(__name__)

BASE_URL = os.getenv("SIGMA_BASE_URL")
USERNAME = os.getenv("SIGMA_USERNAME")
PASSWORD = os.getenv("SIGMA_PASSWORD")
MAX_TOTAL_ATTEMPTS = int(os.getenv("SIGMA_MAX_ATTEMPTS", "3"))

if not all([BASE_URL, USERNAME, PASSWORD]):
    raise ValueError("Environment variables SIGMA_BASE_URL, SIGMA_USERNAME, and SIGMA_PASSWORD must be set")

@app.route("/status", methods=["GET"])
def get_sigma_status():
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
            return jsonify(output)

        except Exception as e:
            logger.warning(f"Full flow failed on attempt {attempt}: {e}")
            if attempt == MAX_TOTAL_ATTEMPTS:
                logger.exception("Max retry attempts exceeded. Final failure.")
                return jsonify({"error": str(e)}), 500

@app.route("/arm", methods=["POST"])
def arm():
    return _perform_alarm_action("arm")

@app.route("/disarm", methods=["POST"])
def disarm():
    return _perform_alarm_action("disarm")

@app.route("/arm_stay", methods=["POST"])
def arm_stay():
    return _perform_alarm_action("stay")

def _perform_alarm_action(action):
    try:
        client = SigmaClient(BASE_URL, USERNAME, PASSWORD)
        client.perform_action(action)
        return jsonify({"success": True, "action": action}), 200
    except Exception as e:
        logger.exception(f"Failed to perform action '{action}'")
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
