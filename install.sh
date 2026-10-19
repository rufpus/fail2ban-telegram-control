#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
source_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$source_dir/installer.py" install --source "$source_dir" "$@"
