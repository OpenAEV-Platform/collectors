"""Entry point for the Wazuh collector module."""
from .collector import run_collector

if __name__ == "__main__":
    run_collector()
