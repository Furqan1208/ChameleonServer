import json
import sys
from pathlib import Path
from typing import Optional

from toon_python import encode


class ToonService:
    def tooner(self, file_path: Path, output_path: Optional[Path] = None) -> Path:
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                report_data = json.load(file)

            toon_output = encode(report_data)

            if output_path is None:
                output_path = file_path.with_suffix(".toon")

            with open(output_path, "w", encoding="utf-8") as output_file:
                output_file.write(toon_output)

            return output_path

        except json.JSONDecodeError as e:
            print(f"Error parsing JSON file: {e}", file=sys.stderr)
            raise RuntimeError(f"Invalid JSON file: {e}") from e
        except FileNotFoundError:
            print(f"File not found: {file_path}", file=sys.stderr)
            raise RuntimeError(f"File not found: {file_path}") from None
        except Exception as e:
            print(f"Error during TOON encoding: {e}", file=sys.stderr)
            raise RuntimeError(f"Failed to encode report data to TOON: {e}") from e
