#!/usr/bin/env bash
# Install everything a phone check needs:
#   - system packages: adb, usbmuxd, libusb, pipx
#   - mvt and pymobiledevice3 (with pipx)
#   - androidqf (fixed version, checked against the SHA-256 written below)
#   - a small virtualenv for the sta scripts (requirements.txt: PyYAML, APKiD with YARA)
#
# Usage: ./install.sh            install or upgrade
#        ./install.sh --check    only report what is missing
#        ./install.sh --no-system  skip the package manager (no sudo)
#        ./install.sh --docker   build the container image instead (Linux, needs docker)
set -euo pipefail
DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
# Windows (Git Bash): the PowerShell installer does the work.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    args=()
    for arg in "$@"; do
      case "$arg" in
        --check) args+=(-Check) ;;
        --no-system) args+=(-NoSystem) ;;
        *) echo "Unknown option on Windows: $arg" >&2; exit 2 ;;
      esac
    done
    exec powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(cygpath -w "$DIR/install.ps1")" "${args[@]}" ;;
esac
BIN="$HOME/.local/bin"
SYSTEM=1

for arg in "$@"; do
  case "$arg" in
    --check) exec "$DIR/sta" doctor ;;
    --no-system) SYSTEM=0 ;;
    --docker)
      # Rebuild with fresh tools, then restart the container so it uses the new image.
      export STA_DIR="$DIR"
      docker compose -f "$DIR/compose.yaml" build --pull
      docker compose -f "$DIR/compose.yaml" down
      mkdir -p "$DIR/.sta" && echo docker >"$DIR/.sta/runtime"
      STA_RUNTIME=docker exec "$DIR/sta" doctor ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

say() { printf '\n==> %s\n' "$*"; }

install_system() {
  if [[ "$(uname)" == "Darwin" ]]; then
    say "Installing Homebrew packages"
    brew install python pipx libusb sqlite age
    brew install --cask android-platform-tools
    return
  fi
  if command -v pacman >/dev/null; then
    say "Installing Arch packages (sudo)"
    sudo pacman -S --needed --noconfirm python python-pipx android-tools android-udev usbmuxd libusb sqlite age
  elif command -v apt-get >/dev/null; then
    say "Installing Debian/Ubuntu packages (sudo)"
    sudo apt-get update
    sudo apt-get install -y python3 python3-venv python3-pip pipx sqlite3 libusb-1.0-0 adb usbmuxd age
  elif command -v dnf >/dev/null; then
    say "Installing Fedora packages (sudo)"
    sudo dnf install -y python3 pipx android-tools usbmuxd libusb1 sqlite age
  else
    echo "Unknown package manager. Install by hand: python3, pipx, adb, usbmuxd, libusb, sqlite3, age." >&2
  fi
}

install_pipx_tool() {
  local name="$1"
  if pipx list --short 2>/dev/null | grep -q "^$name "; then
    say "Upgrading $name"
    pipx upgrade "$name"
  else
    say "Installing $name"
    pipx install "$name"
  fi
}

# Same version as docker/Dockerfile. The SHA-256 values are written here, not
# read from the release, so a changed file on GitHub cannot get installed.
# (A case, not an associative array: macOS has bash 3.2.)
ANDROIDQF_VERSION=1.8.3
androidqf_sha256() {
  case "$1" in
    androidqf_linux_amd64_1.8.3) echo 59e6071fd41c4cee71f31f9a179ac3ebf9e783cece8422d89a73452335369ebe ;;
    androidqf_linux_arm64_1.8.3) echo c2c729058e4cb96150e98b0a9f1ab211e179743a4e5d64dd37a3e9f3fd49d619 ;;
    androidqf_macos_universal_1.8.3_signed) echo 466156b828472a9e81485829ca7e2e853f7ca068b799e21aafca59e998f3b89b ;;
  esac
}

install_androidqf() {
  local os arch asset tmp sum
  case "$(uname)" in
    Linux) os=linux ;;
    Darwin) os=macos ;;
    *) echo "androidqf: unsupported OS $(uname)" >&2; return 1 ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo "androidqf: unsupported CPU $(uname -m)" >&2; return 1 ;;
  esac
  if [[ "$os" == "macos" ]]; then
    asset="androidqf_macos_universal_${ANDROIDQF_VERSION}_signed"
  else
    asset="androidqf_${os}_${arch}_${ANDROIDQF_VERSION}"
  fi

  say "Installing androidqf $ANDROIDQF_VERSION"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  curl -fsSL "https://github.com/mvt-project/androidqf/releases/download/v$ANDROIDQF_VERSION/$asset" -o "$tmp/$asset"
  if command -v sha256sum >/dev/null; then sum="$(sha256sum "$tmp/$asset")"; else sum="$(shasum -a 256 "$tmp/$asset")"; fi
  if [[ "${sum%% *}" != "$(androidqf_sha256 "$asset")" ]]; then
    echo "androidqf checksum does not match. Not installing." >&2; return 1
  fi
  mkdir -p "$BIN"
  install -m 0755 "$tmp/$asset" "$BIN/androidqf"
  echo "androidqf $ANDROIDQF_VERSION installed in $BIN/androidqf"
}

# EC-DIGIT-CSIRC's sysdiagnose analysis framework (saf). No releases and not on
# PyPI, so pin a commit: git checks it by its hash. Optional: without it the
# check reads only shutdown.log from a sysdiagnose.
SAF_COMMIT=2962575f0e114093f3d7da3cad20f8bc99f94cb6
install_saf() {
  say "Installing saf (sysdiagnose analysis framework) at commit ${SAF_COMMIT:0:12}"
  if ! command -v git >/dev/null; then
    echo "git is missing: saf not installed. The check still reads shutdown.log." >&2; return 0
  fi
  pipx install --force "git+https://github.com/EC-DIGIT-CSIRC/sysdiagnose@$SAF_COMMIT" >/dev/null \
    || echo "saf did not install. The check still reads shutdown.log." >&2
}

install_venv() {
  say "Creating $DIR/.venv for the sta scripts"
  python3 -m venv "$DIR/.venv"
  "$DIR/.venv/bin/pip" install --quiet --upgrade pip
  # Pinned versions from requirements.txt (apkid brings yara), then the sta
  # package itself, editable, so ./sta runs the code in src/.
  "$DIR/.venv/bin/pip" install --quiet -r "$DIR/requirements.txt"
  "$DIR/.venv/bin/pip" install --quiet --no-deps -e "$DIR"
}

[[ $SYSTEM == 1 ]] && install_system
pipx ensurepath >/dev/null 2>&1 || true
export PATH="$BIN:$PATH"
install_pipx_tool mvt
install_pipx_tool pymobiledevice3
install_androidqf
install_saf
install_venv
mkdir -p "$DIR/.sta" && echo local >"$DIR/.sta/runtime"

say "Checking"
"$DIR/sta" doctor
echo
echo "Done. If 'mvt' is not found in a new terminal, open a new one (pipx changed your PATH)."
echo "Start a check with: ./start"
