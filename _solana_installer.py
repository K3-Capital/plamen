"""Download and install Solana CLI on Windows from prebuilt binaries.

Downloads the latest release from anza-xyz/agave GitHub releases.
"""
import os, platform, shutil, sys, tarfile, tempfile, urllib.request

INSTALL_DIR = os.path.join(os.path.expanduser("~"),
                           ".local", "share", "solana", "install", "active_release", "bin")

# Architecture-aware URL
_ARCH = "x86_64" if platform.machine() in ("AMD64", "x86_64") else platform.machine()
URL = (f"https://github.com/anza-xyz/agave/releases/latest/download/"
       f"solana-release-{_ARCH}-pc-windows-msvc.tar.bz2")


def main():
    print("Solana CLI installer (Windows prebuilt)")
    if _ARCH not in ("x86_64",):
        print(f"Warning: architecture {_ARCH} may not have prebuilt binaries", file=sys.stderr)
    print(f"Downloading {URL}...")
    os.makedirs(INSTALL_DIR, exist_ok=True)

    try:
        with tempfile.TemporaryDirectory() as tmp:
            archive = os.path.join(tmp, "solana.tar.bz2")
            urllib.request.urlretrieve(URL, archive)
            print("Extracting...")

            extract_kwargs = {}
            if sys.version_info >= (3, 12):
                extract_kwargs["filter"] = "data"
            with tarfile.open(archive, "r:bz2") as tf:
                tf.extractall(tmp, **extract_kwargs)

            src_bin = os.path.join(tmp, "solana-release", "bin")
            if not os.path.isdir(src_bin):
                print(f"Error: expected {src_bin} not found", file=sys.stderr)
                sys.exit(1)

            count = 0
            for name in os.listdir(src_bin):
                src = os.path.join(src_bin, name)
                dst = os.path.join(INSTALL_DIR, name)
                if os.path.isfile(src):
                    shutil.copy2(src, dst)
                    count += 1

            print(f"Installed {count} files to {INSTALL_DIR}")

            solana_exe = os.path.join(INSTALL_DIR, "solana.exe")
            if os.path.isfile(solana_exe):
                print(f"Success! solana.exe at {solana_exe}")
            else:
                print("Warning: solana.exe not found after install", file=sys.stderr)

    except urllib.error.URLError as e:
        print(f"Download failed: {e}", file=sys.stderr)
        print("Check your internet connection and try again.", file=sys.stderr)
        sys.exit(1)
    except PermissionError as e:
        print(f"Permission denied: {e}", file=sys.stderr)
        print(f"Try closing any running Solana processes and retry.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
