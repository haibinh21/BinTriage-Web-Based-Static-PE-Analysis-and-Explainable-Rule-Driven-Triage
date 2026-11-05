import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ANALYZER = PROJECT_ROOT / "app" / "analysis" / "analyzer.py"


def run_analyzer(*arguments):
    return subprocess.run(
        [sys.executable, str(ANALYZER), *arguments],
        capture_output=True,
        text=True,
        timeout=10,
    )

def test_missing_argument():
    result = run_analyzer()

    assert result.returncode == 2
    assert "Cách dùng:" in result.stderr
    assert result.stdout == ""


def test_missing_file(tmp_path):
    missing_file = tmp_path / "missing.exe"

    result = run_analyzer(str(missing_file))

    assert result.returncode == 1
    assert "Không đọc được file" in result.stderr
    assert result.stdout == ""


def test_invalid_pe(tmp_path):
    invalid_file = tmp_path / "invalid.exe"
    invalid_file.write_bytes(b"This is a text file.")

    result = run_analyzer(str(invalid_file))

    assert result.returncode == 1
    assert "File không phải PE hợp lệ hoặc bị hỏng" in result.stderr
    assert result.stdout == ""