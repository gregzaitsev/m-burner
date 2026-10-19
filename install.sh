#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C.UTF-8
if [[ ${EUID} -ne 0 ]]; then
  echo 'Run: sudo bash install.sh' >&2
  exit 1
fi
command -v apt-get >/dev/null || { echo 'Debian/Ubuntu with apt-get is required.' >&2; exit 1; }
src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
dest=/opt/m-burner
# Use isolated official sources and package indexes. A broken unrelated PPA
# must not prevent installation, and cached third-party packages must not leak in.
. /etc/os-release
codename=${VERSION_CODENAME:-}
[[ $codename =~ ^[a-z][a-z0-9-]*$ ]] || { echo 'Cannot determine distribution codename.' >&2; exit 1; }
case "$ID" in
  ubuntu)
    keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg
    case "$(dpkg --print-architecture)" in
      amd64|i386) mirror=http://archive.ubuntu.com/ubuntu; security=http://security.ubuntu.com/ubuntu ;;
      *) mirror=http://ports.ubuntu.com/ubuntu-ports; security=$mirror ;;
    esac
    components='main universe'
    ;;
  debian)
    keyring=/usr/share/keyrings/debian-archive-keyring.gpg
    mirror=http://deb.debian.org/debian
    security=http://security.debian.org/debian-security
    components=main
    ;;
  *) echo 'Supported distributions: Debian and Ubuntu.' >&2; exit 1 ;;
esac
[[ -r $keyring ]] || { echo "Missing distribution signing keyring: $keyring" >&2; exit 1; }
apt_work=$(mktemp -d /tmp/m-burner-install.XXXXXXXX)
trap 'rm -rf -- "$apt_work"' EXIT
chmod 0755 "$apt_work"
mkdir -p "$apt_work/lists/partial"
cat > "$apt_work/sources.list" <<EOF
deb [signed-by=$keyring] $mirror $codename $components
deb [signed-by=$keyring] $mirror $codename-updates $components
deb [signed-by=$keyring] $security $codename-security $components
EOF
apt_options=(-o "Dir::Etc::sourcelist=$apt_work/sources.list"
             -o 'Dir::Etc::sourceparts=-' -o "Dir::State::lists=$apt_work/lists"
             -o 'APT::Update::Error-Mode=any')
echo 'Installing dependencies from official distribution repositories only; system sources are unchanged.'
apt-get "${apt_options[@]}" update
apt-get "${apt_options[@]}" install -y --no-install-recommends \
  python3 python3-venv xorriso dvd+rw-tools eject udisks2 util-linux
install -d -m 0755 "$dest"
python3 -m venv "$dest/venv"
"$dest/venv/bin/python" -m pip install --require-hashes --only-binary=:all: -r "$src/requirements.txt"
install -m 0644 "$src/m_burner.py" "$dest/m_burner.py"
install -m 0644 "$src/requirements.txt" "$dest/requirements.txt"
install -m 0644 "$src/README.md" "$dest/README.md"
cat > "$dest/launcher" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec /opt/m-burner/venv/bin/python /opt/m-burner/m_burner.py "$@"
EOF
install -m 0755 "$dest/launcher" /usr/local/bin/m-burner
echo 'Done. Run m-burner as a regular user, NOT through sudo.'
echo 'Your user needs read/write access to the optical device /dev/srN.'
