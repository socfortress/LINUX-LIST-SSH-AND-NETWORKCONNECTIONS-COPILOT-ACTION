#!/bin/sh
set -eu

ScriptName="List-SSH-Network-Connections"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/logs/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
runStart="$(date +%s)"

WriteLog() {
  Message="$1"; Level="${2:-INFO}"
  ts="$(date '+%Y-%m-%d %H:%M:%S%z')"
  line="[$ts][$Level] $Message"
  printf '%s\n' "$line" >&2
  printf '%s\n' "$line" >> "$LogPath" 2>/dev/null || true
}

RotateLog() {
  [ -f "$LogPath" ] || return 0
  size_kb=$(awk -v s="$(wc -c <"$LogPath")" 'BEGIN{printf "%.0f", s/1024}')
  [ "$size_kb" -le "$LogMaxKB" ] && return 0
  i=$((LogKeep-1))
  while [ $i -ge 1 ]; do
    src="$LogPath.$i"; dst="$LogPath.$((i+1))"
    [ -f "$src" ] && mv -f "$src" "$dst" || true
    i=$((i-1))
  done
  mv -f "$LogPath" "$LogPath.1"
}

iso_now(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
escape_json(){ printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

BeginNDJSON(){ TMP_AR="$(mktemp)"; }

AddRecord() {
  ts="$(iso_now)"
  proto="$(escape_json "${1:-}")"
  recvq="$(escape_json "${2:-}")"
  sendq="$(escape_json "${3:-}")"
  local_addr="$(escape_json "${4:-}")"
  remote_addr="$(escape_json "${5:-}")"
  state="$(escape_json "${6:-}")"
  pid="$(escape_json "${7:-}")"
  program="$(escape_json "${8:-}")"
  program_path="$(escape_json "${9:-}")"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"proto":"%s","recvq":"%s","sendq":"%s","local":"%s","remote":"%s","state":"%s","pid":"%s","program":"%s","program_path":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" "$proto" "$recvq" "$sendq" "$local_addr" "$remote_addr" "$state" "$pid" "$program" "$program_path" >> "$TMP_AR"
}

AddError(){
  ts="$(iso_now)"; msg="$(escape_json "$1")"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"error","message":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" "$msg" >> "$TMP_AR"
}

CommitNDJSON(){
  ar_dir="$(dirname "$ARLog")"
  [ -d "$ar_dir" ] || WriteLog "Directory missing: $ar_dir (will attempt write anyway)" WARN
  if mv -f "$TMP_AR" "$ARLog" 2>/dev/null; then
    :
  else
    WriteLog "Primary write FAILED to $ARLog" WARN
    if mv -f "$TMP_AR" "$ARLog.new" 2>/dev/null; then
      WriteLog "Wrote NDJSON to $ARLog.new (fallback)" WARN
    else
      keep="/tmp/active-responses.$$.ndjson"
      cp -f "$TMP_AR" "$keep" 2>/dev/null || true
      WriteLog "Failed to write both $ARLog and $ARLog.new; saved $keep" ERROR
      rm -f "$TMP_AR" 2>/dev/null || true
      exit 1
    fi
  fi
  for p in "$ARLog" "$ARLog.new"; do
    if [ -f "$p" ]; then
      sz=$(wc -c < "$p" 2>/dev/null || echo 0)
      ino=$(ls -li "$p" 2>/dev/null | awk '{print $1}')
      head1=$(head -n1 "$p" 2>/dev/null || true)
      WriteLog "VERIFY: path=$p inode=$ino size=${sz}B first_line=${head1:-<empty>}" INFO
    fi
  done
}

proc_path_for_pid(){
  pid="$1"
  [ -n "$pid" ] && [ "$pid" != "-" ] && [ -L "/proc/$pid/exe" ] \
    && readlink -f "/proc/$pid/exe" 2>/dev/null || echo "-"
}

RotateLog
WriteLog "=== SCRIPT START : $ScriptName (host=$HostName) ==="
BeginNDJSON

if command -v ss >/dev/null 2>&1; then
  ss -H -tunap 2>/dev/null | while IFS= read -r line; do
    [ -n "$line" ] || continue
    proto=$(printf '%s' "$line" | awk '{print $1}')
    recvq=$(printf '%s' "$line" | awk '{print $2}')
    sendq=$(printf '%s' "$line" | awk '{print $3}')
    local_addr=$(printf '%s' "$line" | awk '{print $4}')
    remote_addr=$(printf '%s' "$line" | awk '{print $5}')
    state=$(printf '%s' "$line" | awk '{print (NF>=6)?$6:"-"}')
    procseg=$(printf '%s' "$line" | sed -n 's/.*users:\[\(.*\)\].*/\1/p')
    pid=$(printf '%s' "$procseg" | sed -n 's/.*pid=\([0-9]\+\).*/\1/p')
    [ -n "$pid" ] || pid="-"
    program=$(printf '%s' "$procseg" | sed -n 's/.*name="\([^"]*\)".*/\1/p')
    [ -n "$program" ] || program="-"
    program_path="$(proc_path_for_pid "$pid")"
    AddRecord "$proto" "$recvq" "$sendq" "$local_addr" "$remote_addr" "$state" "$pid" "$program" "$program_path"
  done
elif command -v netstat >/dev/null 2>&1; then
  netstat -tunap 2>/dev/null | awk 'BEGIN{hdr=1} /^Proto/ {next} /^(tcp|udp)/ {print}' | while IFS= read -r line; do
    proto=$(printf '%s' "$line" | awk '{print $1}')
    recvq=$(printf '%s' "$line" | awk '{print $2}')
    sendq=$(printf '%s' "$line" | awk '{print $3}')
    local_addr=$(printf '%s' "$line" | awk '{print $4}')
    remote_addr=$(printf '%s' "$line" | awk '{print $5}')
    state=$(printf '%s' "$line" | awk '{print ($1 ~ /^udp/)? "-": $6}')
    pp=$(printf '%s' "$line" | awk '{print $NF}') # e.g., 1234/program
    pid=$(printf '%s' "$pp" | awk -F'/' '{print $1}')
    program=$(printf '%s' "$pp" | awk -F'/' '{print $2}')
    [ -n "$pid" ] || pid="-"
    [ -n "$program" ] || program="-"
    program_path="$(proc_path_for_pid "$pid")"
    AddRecord "$proto" "$recvq" "$sendq" "$local_addr" "$remote_addr" "$state" "$pid" "$program" "$program_path"
  done
else
  AddError "Neither ss nor netstat is available"
fi

CommitNDJSON
dur=$(( $(date +%s) - runStart ))
WriteLog "=== SCRIPT END : ${dur}s ==="
