from pathlib import Path
import sys

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

from core.database import fetch_one


def main() -> None:
    row = fetch_one("SELECT VERSION() AS version")
    print(row["version"] if row else "No result")


if __name__ == "__main__":
    main()
