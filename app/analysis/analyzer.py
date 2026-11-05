import hashlib
import json
import sys
from pathlib import Path

import pefile

if len(sys.argv) != 2:
    print("Cách dùng: python app/analysis/analyzer.py <đường_dẫn_file_PE>", file=sys.stderr)
    sys.exit(2)

path = Path(sys.argv[1])

try:
    data = path.read_bytes()
except OSError as error:
    print(f"Không đọc được file '{path}': {error.strerror}", file=sys.stderr)
    sys.exit(1)

try:
    pe = pefile.PE(data=data)
except pefile.PEFormatError:
    print(f"File không phải PE hợp lệ hoặc bị hỏng: '{path}'", file=sys.stderr)
    sys.exit(1)

sections = []

for section in pe.sections:
    name = section.Name.rstrip(b"\x00").decode("ascii")
    start = section.PointerToRawData
    size = section.SizeOfRawData

    info = {
        "name": name,
        "file_offset": start,
        "raw_size": size,
        "preview_hex": data[start:start + min(3, size)].hex(" "),
    }
    sections.append(info)

imports = []

for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
    dll_name = entry.dll.decode("ascii", errors="replace")
    functions = []

    for imported_function in entry.imports:
        function_name = None

        if imported_function.name is not None:
            function_name = imported_function.name.decode(
                "ascii", errors="replace"
            )

        functions.append({
            "name": function_name,
            "ordinal": imported_function.ordinal,
        })

    imports.append({
        "dll": dll_name,
        "functions": functions,
    })

report = {
    "file_name": path.name,
    "section_count": len(sections),
    "sections": sections,
    "file_size": len(data),
    "sha256": hashlib.sha256(data).hexdigest(),
    "machine": hex(pe.FILE_HEADER.Machine),
    "pe_type": hex(pe.OPTIONAL_HEADER.Magic),
    "parser_warnings": pe.get_warnings(),
    "timestamp_raw": pe.FILE_HEADER.TimeDateStamp,
    "imports": imports,
}

print(json.dumps(report, indent=2))
