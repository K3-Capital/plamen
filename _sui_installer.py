"""Download and install suiup (Sui version manager) on Windows.

Called by plamen.py Setup flow. Downloads the prebuilt binary from GitHub releases,
extracts it, and places it in ~/.local/bin/.
"""
import json, os, platform, shutil, sys, tempfile, urllib.request, zipfile

BIN_DIR = os.path.join(os.path.expanduser("~"), ".local", "bin")
REPO = "MystenLabs/suiup"


def get_latest_release_url():
    """Query GitHub API for the latest suiup release zip for this platform."""
    api = f"https://api.github.com/repos/{REPO}/releases/latest"
    headers = {"Accept": "application/vnd.github.v3+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(api, headers=headers)
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode())

    arch = "x86_64" if platform.machine() in ("AMD64", "x86_64") else platform.machine()
    suffix = f"Windows-msvc-{arch}.zip"

    for asset in data.get("assets", []):
        if asset["name"].endswith(suffix):
            return asset["browser_download_url"], data["tag_name"]

    raise RuntimeError(f"No Windows release found matching *{suffix} in {data.get('tag_name')}")


def main():
    print("suiup installer (Windows)")

    try:
        url, version = get_latest_release_url()
    except urllib.error.URLError as e:
        print(f"Failed to query GitHub releases: {e}", file=sys.stderr)
        print("Check your internet connection. If rate-limited, set GITHUB_TOKEN env var.",
              file=sys.stderr)
        sys.exit(1)

    print(f"Version: {version}")
    print(f"Downloading {url}...")
    os.makedirs(BIN_DIR, exist_ok=True)

    try:
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = os.path.join(tmp, "suiup.zip")
            urllib.request.urlretrieve(url, zip_path)

            with zipfile.ZipFile(zip_path, 'r') as zf:
                for name in zf.namelist():
                    if name.endswith("suiup.exe") or name == "suiup.exe":
                        zf.extract(name, tmp)
                        src = os.path.join(tmp, name)
                        dst = os.path.join(BIN_DIR, "suiup.exe")
                        shutil.move(src, dst)
                        print(f"Installed suiup to {dst}")
                        break
                else:
                    zf.extractall(tmp)
                    for root, dirs, files in os.walk(tmp):
                        for f in files:
                            if f == "suiup.exe":
                                shutil.move(os.path.join(root, f),
                                            os.path.join(BIN_DIR, "suiup.exe"))
                                print(f"Installed suiup to {BIN_DIR}")
                                break

    except urllib.error.URLError as e:
        print(f"Download failed: {e}", file=sys.stderr)
        sys.exit(1)
    except PermissionError as e:
        print(f"Permission denied: {e}", file=sys.stderr)
        sys.exit(1)

    exe = os.path.join(BIN_DIR, "suiup.exe")
    if os.path.isfile(exe):
        print(f"Success! suiup installed at {exe}")
    else:
        print("Error: suiup.exe not found after extraction", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
