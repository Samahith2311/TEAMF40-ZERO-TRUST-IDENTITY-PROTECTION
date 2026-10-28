import zipfile
import os
import sys
import fnmatch
from pathlib import Path

EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".vite",
    "dist",
    "certs",
    "data",
    "cybersecurity-vibecoding-skillpack",
    ".system_generated"
}

EXCLUDED_FILES = {
    ".DS_Store",
    "desktop.ini",
    ".env",
    "zero_trust_track2_submission.zip"
}

EXCLUDED_PATTERNS = [
    "*.zip",
    "*.pyc",
    "MASTER_*.md",
    "*.pdf",
    "*.swp"
]

def should_exclude(rel_path: Path) -> bool:
    # Check directory components
    for part in rel_path.parts[:-1]:
        if part in EXCLUDED_DIRS:
            return True
        for pat in EXCLUDED_PATTERNS:
            if fnmatch.fnmatch(part, pat):
                return True

    # Check file name
    file_name = rel_path.name
    if file_name in EXCLUDED_FILES:
        return True
    for pat in EXCLUDED_PATTERNS:
        if fnmatch.fnmatch(file_name, pat):
            return True

    return False

def create_submission_package(output_zip: str = "zero_trust_track2_submission.zip") -> str:
    root = Path(__file__).resolve().parent.parent
    out_path = root / output_zip

    total_files = 0
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(root.rglob("*")):
            if not p.is_file():
                continue
            rel_p = p.relative_to(root)
            if should_exclude(rel_p):
                continue

            rel_str = str(rel_p).replace("\\", "/")
            zf.write(p, arcname=rel_str)
            total_files += 1

    file_size_kb = out_path.stat().st_size / 1024.0
    print(f"Submission archive created: {output_zip} ({file_size_kb:.1f} KB, {total_files} files)")

    # Verify archive integrity
    with zipfile.ZipFile(out_path, "r") as zf:
        bad_file = zf.testzip()
        if bad_file:
            raise RuntimeError(f"Corrupt file in archive: {bad_file}")
        print("Archive integrity verified (testzip passed).")

    return str(out_path)

if __name__ == "__main__":
    create_submission_package()
