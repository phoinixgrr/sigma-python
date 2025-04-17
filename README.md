
# Sigma Alarm System API

A lightweight Flask API for retrieving status and zone information from a Sigma alarm system.

---

## Features

- Logs in and authenticates with the Sigma alarm panel
- Parses alarm status, AC power, battery level, and zone data
- Provides a single `/status` endpoint returning JSON
- Resilient to flaky network and partial HTML responses (retry logic)

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/yourname/sigma-alarm-api.git
cd sigma-alarm-api
```

### 2. Configure the environment

Create a `.env` file or export the following variables:

```env
SIGMA_BASE_URL=http://192.168.1.1:5053
SIGMA_USERNAME=<your_username>
SIGMA_PASSWORD=<your_password_or_pin>
SIGMA_MAX_ATTEMPTS=3
SIGMA_RETRY_TOTAL=3
SIGMA_RETRY_BACKOFF=0.5
SIGMA_RETRY_HTML=3
SIGMA_LOG_LEVEL=INFO
```

---

## Running the API

### Option A: Locally

```bash
pip install -r requirements.txt
export FLASK_APP=sigma_api.py
flask run
```

Access it at [http://localhost:8080/status](http://localhost:8080/status)

---

### Option B: Using Docker

```bash
docker build -t sigma-alarm-api .
docker run -p 8080:8080 --env-file .env sigma-alarm-api
```

Test it:

```bash
curl http://localhost:8080/status | jq
```

---

## Environment Variables

| Variable               | Description                                         | Required | Default |
|------------------------|-----------------------------------------------------|----------|---------|
| `SIGMA_BASE_URL`       | Base URL of the Sigma alarm web UI                  | ✅       | –       |
| `SIGMA_USERNAME`       | Login username                                      | ✅       | –       |
| `SIGMA_PASSWORD`       | Login password or PIN                               | ✅       | –       |
| `SIGMA_MAX_ATTEMPTS`   | Retry attempts for full flow                        | ❌       | 3       |
| `SIGMA_RETRY_TOTAL`    | Retry attempts for HTTP requests                    | ❌       | 3       |
| `SIGMA_RETRY_BACKOFF`  | Backoff factor for retries                          | ❌       | 0.5     |
| `SIGMA_RETRY_HTML`     | Retry attempts for HTML parsing failures            | ❌       | 3       |
| `SIGMA_LOG_LEVEL`      | Logging level (`DEBUG`, `INFO`, `WARNING`, etc.)   | ❌       | INFO    |

---

## File Structure

```
sigma_api.py       # Flask app
sigma_client.py    # Sigma alarm communication logic
log_config.py      # Centralized logging config
requirements.txt   # Dependencies
Dockerfile         # Docker image definition
```

---

## License

MIT – use freely, modify, distribute.
