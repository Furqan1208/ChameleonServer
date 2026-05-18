import logging
import sys
import os
import json


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_record["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(log_record, ensure_ascii=False)


def configure_logging(level: str | None = None) -> None:
    root = logging.getLogger()
    if root.handlers:
        return
    level = (level or os.getenv("LOG_LEVEL", "INFO")).upper()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    root.setLevel(level)
    root.addHandler(handler)


def get_logger(name: str = __name__) -> logging.Logger:
    configure_logging()
    return logging.getLogger(name)
