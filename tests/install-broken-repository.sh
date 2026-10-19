#!/bin/bash
# Run ONLY in a disposable Ubuntu container with the repository at /src.
set -euo pipefail
printf 'deb [trusted=no] file:/nonexistent-third-party noble main\n' > /etc/apt/sources.list.d/broken-third-party.list
find /etc/apt -type f -print0 | sort -z | xargs -0 sha256sum > /tmp/apt-before.sha256
if apt-get update > /tmp/baseline.log 2>&1; then
  echo 'ERROR: broken repository should fail ordinary apt-get update'
  exit 1
fi
bash /src/install.sh
sha256sum --quiet -c /tmp/apt-before.sha256
m-burner --help > /tmp/help.txt
/opt/m-burner/venv/bin/python -m pip check
if compgen -G '/tmp/m-burner-install.*' > /dev/null; then
  echo 'ERROR: temporary APT files were not removed'
  exit 1
fi
printf 'PASS: installation with broken third-party repository; original APT files unchanged; CLI works; temporary files removed.\n'
