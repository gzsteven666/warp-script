#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

awk '
  /^  cat > "\$\{SINGBOX_PATCHER\}" <<'\''EOF_SINGBOX_PATCHER'\''/ { capture=1; next }
  /^EOF_SINGBOX_PATCHER$/ { capture=0 }
  capture
' "${repo_dir}/warp.sh" > "${tmp_dir}/patcher"
chmod +x "${tmp_dir}/patcher"

cache_dir="${tmp_dir}/cache"
config_dir="${tmp_dir}/sing-box/conf"
mkdir -p "${cache_dir}" "${config_dir}"

cat > "${config_dir}/config.json" <<'EOF_CONFIG'
{
  "log": {
    "level": "warn"
  },
  "inbounds": [
    {
      "type": "socks",
      "tag": "test-in",
      "listen": "127.0.0.1",
      "listen_port": 1080
    }
  ],
  "route": {
    "rules": [
      {
        "action": "sniff"
      }
    ]
  }
}
EOF_CONFIG

printf '%s\n' "${config_dir}/config.json" > "${cache_dir}/singbox_config"
printf '%s\n' "gemini-only" > "${cache_dir}/routing_mode"
printf '%s\n' "off" > "${cache_dir}/netflix_mode"
printf '%s\n' "gemini.google.com" "generativelanguage.googleapis.com" > "${cache_dir}/gemini_domains.txt"
printf '%s\n' "netflix.com" "nflxvideo.net" > "${cache_dir}/netflix_domains.txt"

run_patcher() {
  WARP_CACHE_DIR="${cache_dir}" WARP_SINGBOX_BIN="/usr/bin/true" \
    "${tmp_dir}/patcher" "$1"
}

run_patcher apply
first_hash="$(shasum -a 256 "${config_dir}/config.json" | awk '{print $1}')"
run_patcher apply
second_hash="$(shasum -a 256 "${config_dir}/config.json" | awk '{print $1}')"
[[ "${first_hash}" == "${second_hash}" ]]

python3 - "${config_dir}/config.json" <<'PY_APPLY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["inbounds"][0]["tag"] == "test-in"
assert [item["tag"] for item in data["outbounds"]] == ["warp-direct", "warp-out"]
assert data["route"]["final"] == "warp-direct"
managed = [
    rule for rule in data["route"]["rules"]
    if "__warp_script_v2_managed__" in rule.get("domain_keyword", [])
]
assert len(managed) == 2
assert "gemini.google.com" in managed[0]["domain"]
assert "netflix.com" not in managed[0]["domain"]
PY_APPLY

printf '%s\n' "on" > "${cache_dir}/netflix_mode"
run_patcher apply
python3 - "${config_dir}/config.json" <<'PY_NETFLIX'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
managed = next(
    rule for rule in data["route"]["rules"]
    if rule.get("outbound") == "warp-out"
)
assert "netflix.com" in managed["domain"]
assert "nflxvideo.net" in managed["domain"]
PY_NETFLIX

run_patcher remove
python3 - "${config_dir}/config.json" <<'PY_REMOVE'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
assert "outbounds" not in data
assert "final" not in data["route"]
assert data["route"]["rules"] == [{"action": "sniff"}]
assert data["inbounds"][0]["tag"] == "test-in"
PY_REMOVE

echo "sing-box patcher tests passed"
