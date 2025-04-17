import logging
import os

def setup_logging():
    log_level = os.getenv("SIGMA_LOG_LEVEL", "INFO").upper()

    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )