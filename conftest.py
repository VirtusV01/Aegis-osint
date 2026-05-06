"""Root conftest — adds src/ to sys.path for the src-layout package structure."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))