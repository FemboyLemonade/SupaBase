import json

from pathlib import Path

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"

def load_tables_config():

    """
    Load the tables config.
    """

    with open(CONFIG_DIR / "tables.json", "r", encoding = "utf-8") as tables_file:
        j = json.load(tables_file)

    return j