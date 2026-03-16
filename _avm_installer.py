"""Download and install AVM (Anchor Version Manager) on Windows.

Tries prebuilt binary from GitHub releases first, falls back to cargo install.
Note: As of 2026, AVM does not publish prebuilt Windows binaries.
If cargo install fails due to AppLocker/WDAC, use WSL.
"""
import json, os, platform, shutil, subprocess, sys, tempfile, urllib.request

BIN_DIR = os.path.join(os.path.expanduser("~"), ".avm", "bin")
REPO = "solana-foundation/anchor"


def try_prebuilt():
    """Try to find a prebuilt AVM binary for Windows. Returns True if found."""
    api = f"https://api.github.com/repos/{REPO}/releases?per_page=10"
    req = urllib.request.Request(api, headers={"Accept": "application/vnd.github.v3+json"})
    try:
        with urllib.request.urlopen(req) as resp:
            releases = json.loads(resp.read().decode())
    except Exception as e:
        print(f"  Could not check releases: {e}")
        return False

    for release in releases:
        for asset in release.get("assets", []):
            name = asset["name"].lower()
            if "avm" in name and ("windows" in name or "msvc" in name):
                url = asset["browser_download_url"]
                print(f"  Found prebuilt: {asset['name']}")
                print(f"  Downloading {url}...")
                os.makedirs(BIN_DIR, exist_ok=True)
                with tempfile.TemporaryDirectory() as tmp:
                    dl = os.path.join(tmp, asset["name"])
                    urllib.request.urlretrieve(url, dl)
                    dst = os.path.join(BIN_DIR, "avm.exe")
                    shutil.copy2(dl, dst)
                    print(f"  Installed to {dst}")
                    return True
    return False


def main():
    print("AVM installer (Windows)")
    os.makedirs(BIN_DIR, exist_ok=True)

    if try_prebuilt():
        return

    print("  No prebuilt AVM binary for Windows — trying cargo install...")
    print("  (If this fails with 'Application Control policy', use WSL instead)")
    result = subprocess.run(["cargo", "install", "--git",
                             "https://github.com/coral-xyz/anchor", "avm", "--force"])
    if result.returncode != 0:
        print()
        print("  cargo install failed. On Windows with AppLocker/WDAC,")
        print("  cargo cannot run build scripts from temp directories.")
        print()
        print("  Workarounds:")
        print("    1. Use WSL: wsl --install, then install inside WSL")
        print("    2. Set CARGO_TARGET_DIR to a non-temp directory:")
        print('       set CARGO_TARGET_DIR=%USERPROFILE%\\.cargo-target')
        print("       then retry: cargo install --git https://github.com/coral-xyz/anchor avm --force")
        sys.exit(1)


if __name__ == "__main__":
    main()
