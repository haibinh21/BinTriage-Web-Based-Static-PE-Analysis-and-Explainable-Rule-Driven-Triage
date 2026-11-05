import json
import subprocess
import sys
from app.analysis.analyzer import analyze_file
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

def test_valid_pe():
    sample = PROJECT_ROOT / "tests" / "fixtures" / "hello-pe.exe"

    result = run_analyzer(str(sample))

    assert result.returncode == 0
    assert result.stderr == ""

    report = json.loads(result.stdout)

    assert report["file_name"] == "hello-pe.exe"
    assert report["file_size"] == 1024
    assert report["machine"] == "0x8664"
    assert report["pe_type"] == "0x20b"
    assert report["imports"] == []
    assert report["sha256"] == (
        "94ed43781cf8ac9d18a30c603284fea846787"
        "f2c24a05658be5d720e9e275883"
    )

    assert report["section_count"] == 1
    assert len(report["sections"]) == 1

    section = report["sections"][0]
    assert section["name"] == ".text"
    assert section["file_offset"] == 512
    assert section["raw_size"] == 512
    assert section["preview_hex"] == "31 c0 c3"

def test_pe_with_named_import():
    sample = PROJECT_ROOT / "tests" / "fixtures" / "pe-with-import.exe"

    result = run_analyzer(str(sample))

    assert result.returncode == 0
    assert result.stderr == ""

    report = json.loads(result.stdout)

    assert report["imports"] == [
        {
            "dll": "KERNEL32.dll",
            "functions": [
                {"name": "ExitProcess", "ordinal": None}
            ],
        }
    ]

def test_pe_with_ordinal_import():
    sample = PROJECT_ROOT / "tests" / "fixtures" / "pe-with-ordinal.exe"

    result = run_analyzer(str(sample))

    assert result.returncode == 0
    assert result.stderr == ""

    report = json.loads(result.stdout)

    assert report["imports"] == [
        {
            "dll": "KERNEL32.dll",
            "functions": [
                {"name": None, "ordinal": 7}
            ],
        }
    ]

def test_analyze_file_returns_report():
    sample = PROJECT_ROOT / "tests" / "fixtures" / "hello-pe.exe"

    report = analyze_file(sample)

    assert isinstance(report, dict)
    assert report["file_name"] == "hello-pe.exe"
    assert report["section_count"] == 1
    assert report["sections"][0]["name"] == ".text"