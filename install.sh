#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then
  echo 'Запустите: sudo bash install.sh' >&2
  exit 1
fi
command -v apt-get >/dev/null || { echo 'Поддерживаются Debian/Ubuntu с apt-get.' >&2; exit 1; }
src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
dest=/opt/m-burner
apt-get update
apt-get install -y --no-install-recommends \
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
echo 'Готово. Запускайте m-burner от обычного пользователя, НЕ через sudo.'
echo 'Пользователю нужен доступ на чтение и запись к оптическому /dev/srN.'
