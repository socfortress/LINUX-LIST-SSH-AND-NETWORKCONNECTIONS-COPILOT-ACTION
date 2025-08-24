#!/bin/sh
set -eu

ScriptName="List-SSH-Network-Connections"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/active-response/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
runStart="$(date +%s)"

WriteLog() {
  Message="$1"; Level="${2:-INFO}"
  ts="$(date '+%Y-%m-%d %H:%M:%S%z')"
  line="[$ts][$Level] $Message"
  printf '%s\n' "$line"
  printf '%s\n' "$line" >> "$LogPath"
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

escape_json() {
  s=$1
  s=$(printf '%s' "$s" | sed 's/\\/\\\\/g; s/"/\\"/g')
  printf '%s' "$s"
}

BeginNDJSON() {
  TMP_AR="$(mktemp)"
}

AddRecord() {
  ts="$(date '+%Y-%m-%d %H:%M:%S%z')"
  proto="$(escape_json "$1")"
  recvq="$(escape_json "$2")"
  sendq="$(escape_json "$3")"
  local_addr="$(escape_json "$4")"
  remote_addr="$(escape_json "$5")"
  state="$(escape_json "$6")"
  pidprog="$(escape_json "$7")"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"proto":"%s","recvq":"%s","sendq":"%s","local":"%s","remote":"%s","state":"%s","pid_prog":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" "$proto" "$recvq" "$sendq" "$local_addr" "$remote_addr" "$state" "$pidprog" >> "$TMP_AR"
}

AddError() {
  ts="$(date '+%Y-%m-%d %H:%M:%S%z')"
  msg="$(escape_json "$1")"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"error","message":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" "$msg" >> "$TMP_AR"
}

CommitNDJSON() {
  if mv -f "$TMP_AR" "$ARLog" 2>/dev/null; then
    :
  else
    mv -f "$TMP_AR" "$ARLog.new" 2>/dev/null || printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"error","message":"atomic move failed"}\n' "$(date '+%Y-%m-%d %H:%M:%S%z')" "$HostName" "$ScriptName" > "$ARLog.new"
  fi
}

RotateLog
WriteLog "START $ScriptName"

BeginNDJSON

if command -v ss >/dev/null 2>&1; then

  ss -H -tunap 2>/dev/null | while IFS= read -r line; do
    [ -n "$line" ] || continue
    proto=$(printf '%s' "$line" | awk '{print $1}')
    recvq=$(printf '%s' "$line" | awk '{print $2}')
    sendq=$(printf '%s' "$line" | awk '{print $3}')
    local_addr=$(printf '%s' "$line" | awk '{print $4}')
    remote_addr=$(printf '%s' "$line" | awk '{print $5}')
    state=$(printf '%s' "$line" | awk '{print $6}')
    pidprog=$(printf '%s' "$line" | sed -n 's/.*users:\[\(.*\)\].*/\1/p')
    [ -z "$pidprog" ] && pidprog="-"
    AddRecord "$proto" "$recvq" "$sendq" "$local_addr" "$remote_addr" "$state" "$pidprog"
  done
elif command -v netstat >/dev/null 2>&1; then
  netstat -tunap 2>/dev/null | grep -E '^(tcp|udp)' | grep -v 'Proto' | while IFS= read -r line; do
    proto=$(echo "$line" | awk '{print $1}')
    recvq=$(echo "$line" | awk '{print $2}')
    sendq=$(echo "$line" | awk '{print $3}')
    local_addr=$(echo "$line" | awk '{print $4}')
    remote_addr=$(echo "$line" | awk '{print $5}')
    state=$(echo "$line" | awk '{print $6}')
    pidprog=$(echo "$line" | awk '{print $7}')
    [ -n "$proto" ] || continue
    AddRecord "$proto" "$recvq" "$sendq" "$local_addr" "$remote_addr" "$state" "$pidprog"
  done
else
  AddError "Neither ss nor netstat is available"
fi

CommitNDJSON

dur=$(( $(date +%s) - runStart ))
WriteLog "END $ScriptName in ${dur}s"
