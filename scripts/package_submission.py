import zipfile
import os
import sys
from pathlib import Path

EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".vite",
    "dist"
}

EXCLUDED_FILES = {
    ".DS_Store",
    "desktop.ini",
    ".env"
}

def create_submission_package(output_zip: str = "zero_trust_track2_submission.zip") -> str:
    root = Path.cwd()
    out_path = root / output_zip

    total_files = 0
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            rel_parts = p.relative_to(root).parts
            if any(part in EXCLUDED_DIRS for part in rel_parts):
                continue
            if p.name in EXCLUDED_FILES or p.name.endswith(".pyc") or p.name == output_zip:
                continue

            rel_str = str(p.relative_to(root))
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

