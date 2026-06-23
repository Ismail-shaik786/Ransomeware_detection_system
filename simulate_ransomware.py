"""
simulate_ransomware.py
======================
SAFE EDUCATIONAL SIMULATION ONLY.
===================================

This script mimics the behavioural PATTERNS of ransomware without
doing any actual harm:

  ✔  Creates harmless dummy text files in a temp test folder
  ✔  Rapidly renames them (e.g. adds .locked extension)
  ✔  Simulates bulk modifications

It does NOT:
  ✖  Encrypt any real data
  ✖  Modify files outside the specified test directory
  ✖  Communicate over the network
  ✖  Persist or self-replicate

Purpose: Trigger the Ransomware Guard detection engine for testing.

Usage
-----
    python simulate_ransomware.py [--dir <test_dir>] [--files 20] [--delay 0.2]

Defaults
--------
  --dir    ./sim_test_folder   (created automatically)
  --files  20
  --delay  0.2  (seconds between operations)
"""

import argparse
import os
import time

SUSPICIOUS_EXT = ".locked"


def create_dummy_files(folder: str, count: int) -> list:
    """Create *count* harmless dummy text files in *folder*."""
    os.makedirs(folder, exist_ok=True)
    created = []
    for i in range(count):
        path = os.path.join(folder, f"document_{i:04d}.txt")
        with open(path, "w") as fh:
            fh.write(f"This is harmless test file number {i}.\n" * 10)
        created.append(path)
    print(f"[SIM] Created {len(created)} dummy files in '{folder}'")
    return created


def simulate_mass_rename(files: list, delay: float) -> None:
    """Rename each file to add the .locked extension (simulated encryption)."""
    renamed = []
    for path in files:
        new_path = path + SUSPICIOUS_EXT
        try:
            os.rename(path, new_path)
            renamed.append(new_path)
            print(f"[SIM] Renamed → {os.path.basename(new_path)}")
            time.sleep(delay)
        except OSError as exc:
            print(f"[SIM] Could not rename {path}: {exc}")
    print(f"[SIM] Mass rename complete: {len(renamed)} files renamed.")
    return renamed


def simulate_rapid_modifications(folder: str, delay: float) -> None:
    """Rapidly write random-ish bytes to existing files (simulates overwrite)."""
    count = 0
    for fname in os.listdir(folder):
        fpath = os.path.join(folder, fname)
        if os.path.isfile(fpath):
            try:
                with open(fpath, "wb") as fh:
                    # Write high-entropy-looking bytes (alternating patterns)
                    fh.write(bytes(range(256)) * 40)
                count += 1
                time.sleep(delay)
            except OSError:
                pass
    print(f"[SIM] Rapid modification: {count} files overwritten with test data.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Safe Ransomware Behaviour Simulator")
    parser.add_argument(
        "--dir", default="/home/ismail/Desktop/folder",
        help="Target test directory (will be CREATED; do not point at real data)"
    )
    parser.add_argument("--files", type=int, default=20, help="Number of dummy files")
    parser.add_argument("--delay", type=float, default=0.2, help="Delay between ops (s)")
    args = parser.parse_args()

    folder = os.path.abspath(args.dir)

    print("=" * 56)
    print("  SAFE RANSOMWARE BEHAVIOUR SIMULATOR")
    print("  (Educational / Testing Use Only)")
    print("=" * 56)
    print(f"  Target folder : {folder}")
    print(f"  File count    : {args.files}")
    print(f"  Op delay      : {args.delay}s")
    print("=" * 56)
    print()

    # Phase 1: Create dummy files
    files = create_dummy_files(folder, args.files)
    time.sleep(1)

    # Phase 2: Rapid modifications (triggers heavy-mod detector)
    print("\n[SIM] Phase 2: Rapid Modifications…")
    simulate_rapid_modifications(folder, args.delay)
    time.sleep(1)

    # Phase 3: Mass rename to suspicious extensions (triggers rename detector)
    print("\n[SIM] Phase 3: Mass Rename to .locked…")
    simulate_mass_rename(files, args.delay)

    print("\n[SIM] Simulation complete.  Check Ransomware Guard terminal for alerts.")
    print(f"[SIM] Test files are in: {folder}")
    print("[SIM] You may safely delete that folder when done.\n")


if __name__ == "__main__":
    main()
