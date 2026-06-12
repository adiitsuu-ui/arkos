#!/usr/bin/env bash
set -u

BASE=/tmp/arkos-testnet
LOGS="$BASE/logs"
RUN="$BASE/run"
ARKOS=/home/lunna/arkos/target/release/arkos
MINER=/home/lunna/arkos/target/release/soak_miner
REPORTER=/home/lunna/arkos/scripts/soak_report.py
DURATION_SECONDS=${SOAK_DURATION_SECONDS:-259200}
SNAPSHOT_INTERVAL_SECONDS=${SNAPSHOT_INTERVAL_SECONDS:-1800}
MINE_TARGET_HEIGHT=${SOAK_MINE_TARGET_HEIGHT:-520}
LOOP_SLEEP_SECONDS=${SOAK_LOOP_SLEEP_SECONDS:-60}

mkdir -p "$LOGS" "$RUN"

if [[ ! -f "$RUN/token" ]]; then
  printf 'testnet-%s\n' "$(date +%s)" > "$RUN/token"
fi
TOKEN=$(cat "$RUN/token")

declare -A DATADIR LISTEN RPC MINER_ADDR PEER
DATADIR[node-a]="$BASE/node-a"
DATADIR[node-b]="$BASE/node-b"
DATADIR[node-c]="$BASE/node-c"
LISTEN[node-a]="127.0.0.1:19444"
LISTEN[node-b]="127.0.0.1:19446"
LISTEN[node-c]="127.0.0.1:19448"
RPC[node-a]="127.0.0.1:19445"
RPC[node-b]="127.0.0.1:19447"
RPC[node-c]="127.0.0.1:19449"
MINER_ADDR[node-a]="1111111111111111111111111111111111111111"
MINER_ADDR[node-b]="2222222222222222222222222222222222222222"
MINER_ADDR[node-c]="3333333333333333333333333333333333333333"
PEER[node-a]=""
PEER[node-b]="127.0.0.1:19444"
PEER[node-c]="127.0.0.1:19444"

json_event() {
  python3 - "$@" >> "$LOGS/events.jsonl" <<'PY'
import json, sys, time
event = {"ts": int(time.time())}
for arg in sys.argv[1:]:
    k, _, v = arg.partition("=")
    try:
        event[k] = json.loads(v)
    except Exception:
        event[k] = v
print(json.dumps(event, sort_keys=True))
PY
}

pid_file() {
  printf '%s/%s.pid' "$RUN" "$1"
}

is_running() {
  local node=$1
  local file
  file=$(pid_file "$node")
  [[ -f "$file" ]] && kill -0 "$(cat "$file")" 2>/dev/null
}

start_node() {
  local node=$1
  mkdir -p "${DATADIR[$node]}"
  local args=( "$ARKOS" --datadir "${DATADIR[$node]}" --network testnet --listen "${LISTEN[$node]}" --rpc-listen "${RPC[$node]}" --rpc-token "$TOKEN" )
  if [[ -n "${PEER[$node]}" ]]; then
    args+=( --peer "${PEER[$node]}" )
  fi
  args+=( node )
  if [[ "$node" != "node-c" ]]; then
    args+=( --miner "${MINER_ADDR[$node]}" )
  fi
  setsid nohup "${args[@]}" >> "$LOGS/$node.log" 2>&1 &
  printf '%s\n' "$!" > "$(pid_file "$node")"
  json_event type=start node="$node" pid="$(cat "$(pid_file "$node")")"
}

stop_node() {
  local node=$1
  local reason=${2:-stop}
  if is_running "$node"; then
    local pid
    pid=$(cat "$(pid_file "$node")")
    kill "$pid" 2>/dev/null || true
    sleep 10
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
    fi
    json_event type=stop node="$node" reason="$reason" pid="$pid"
  fi
}

rpc_call() {
  local node=$1
  local method=$2
  local params=${3:-{}}
  curl -fsS --max-time 10 \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
    "http://${RPC[$node]}/rpc"
}

height_of() {
  local node=$1
  rpc_call "$node" getMiningInfo '{}' 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("result",{}).get("height",""))' 2>/dev/null || true
}

tip_of() {
  local node=$1
  local line
  line=$(grep -E 'Best chain is now block|Genesis block:' "$LOGS/$node.log" 2>/dev/null | tail -1 || true)
  if [[ "$line" == *"Best chain is now block"* ]]; then
    printf '%s\n' "$line" | sed -E 's/.*Best chain is now block ([0-9a-f]+) at height.*/\1/'
  elif [[ "$line" == *"Genesis block:"* ]]; then
    printf '%s\n' "$line" | sed -E 's/.*Genesis block: ([0-9a-f]+).*/\1/'
  fi
}

active_nodes() {
  for node in node-a node-b node-c; do
    if is_running "$node" && [[ -n "$(height_of "$node")" ]]; then
      printf '%s\n' "$node"
    fi
  done
}

wait_node_ready() {
  local node=$1
  local limit=${2:-120}
  local start now
  start=$(date +%s)
  while true; do
    if is_running "$node" && [[ -n "$(height_of "$node")" ]]; then
      return 0
    fi
    now=$(date +%s)
    if (( now - start >= limit )); then
      return 1
    fi
    sleep 2
  done
}

wait_nodes_ready() {
  local node
  for node in "$@"; do
    wait_node_ready "$node" 120 || json_event type=rpc_not_ready node="$node"
  done
}

snapshot() {
  python3 - "$BASE" "$LOGS" "$(date +%s)" "$(du -sk "$BASE" 2>/dev/null | awk '{print $1}')" \
    node-a "$(is_running node-a && echo true || echo false)" "$(cat "$(pid_file node-a)" 2>/dev/null || true)" "$(height_of node-a)" "$(tip_of node-a)" "$(ps -o rss= -p "$(cat "$(pid_file node-a)" 2>/dev/null || echo 0)" 2>/dev/null | awk '{print $1}')" \
    node-b "$(is_running node-b && echo true || echo false)" "$(cat "$(pid_file node-b)" 2>/dev/null || true)" "$(height_of node-b)" "$(tip_of node-b)" "$(ps -o rss= -p "$(cat "$(pid_file node-b)" 2>/dev/null || echo 0)" 2>/dev/null | awk '{print $1}')" \
    node-c "$(is_running node-c && echo true || echo false)" "$(cat "$(pid_file node-c)" 2>/dev/null || true)" "$(height_of node-c)" "$(tip_of node-c)" "$(ps -o rss= -p "$(cat "$(pid_file node-c)" 2>/dev/null || echo 0)" 2>/dev/null | awk '{print $1}')" \
    >> "$LOGS/snapshots.log" <<'PY'
import json, sys
base, logs, ts, disk = sys.argv[1:5]
args = sys.argv[5:]
nodes = {}
for i in range(0, len(args), 6):
    node, running, pid, height, tip, rss = args[i:i+6]
    nodes[node] = {
        "running": running == "true",
        "pid": int(pid) if pid.isdigit() else None,
        "height": int(height) if height.isdigit() else None,
        "tip": tip or None,
        "rss_kb": int(rss) if rss.isdigit() else None,
    }
print(json.dumps({"ts": int(ts), "disk_kb": int(disk or 0), "nodes": nodes}, sort_keys=True))
PY
}

maybe_snapshot() {
  if [[ -n "${next_snapshot:-}" ]] && (( $(date +%s) >= next_snapshot )); then
    snapshot
    next_snapshot=$(( $(date +%s) + SNAPSHOT_INTERVAL_SECONDS ))
  fi
}

mine_once() {
  local nodes=()
  local node
  while IFS= read -r node; do
    nodes+=( "$node" )
  done < <(active_nodes)
  mine_group "${nodes[@]}"
}

mine_group() {
  local nodes=( "$@" )
  if [[ "${#nodes[@]}" -eq 0 ]]; then
    json_event type=mine skipped=true reason=no_active_nodes
    return 0
  fi
  local template_node=${nodes[0]}
  local submit_addrs=()
  for node in "${nodes[@]}"; do
    submit_addrs+=( "${RPC[$node]}" )
  done
  local output
  output=$("$MINER" "${RPC[$template_node]}" "$TOKEN" "${MINER_ADDR[$template_node]}" "${submit_addrs[@]}" 2>&1)
  printf '%s\n' "$output" >> "$LOGS/mining.jsonl"
}

max_height() {
  local max=0
  local h
  for node in node-a node-b node-c; do
    h=$(height_of "$node")
    if [[ "$h" =~ ^[0-9]+$ ]] && (( h > max )); then
      max=$h
    fi
  done
  printf '%s\n' "$max"
}

converged() {
  local h_a h_b h_c t_a t_b t_c
  h_a=$(height_of node-a); h_b=$(height_of node-b); h_c=$(height_of node-c)
  t_a=$(tip_of node-a); t_b=$(tip_of node-b); t_c=$(tip_of node-c)
  [[ -n "$h_a" && "$h_a" == "$h_b" && "$h_b" == "$h_c" && -n "$t_a" && "$t_a" == "$t_b" && "$t_b" == "$t_c" ]]
}

wait_converged() {
  local limit=$1
  local start now
  start=$(date +%s)
  while true; do
    if converged; then
      now=$(date +%s)
      printf '%s\n' "$((now - start))"
      return 0
    fi
    now=$(date +%s)
    if (( now - start >= limit )); then
      printf '%s\n' "$limit"
      return 1
    fi
    sleep 10
  done
}

restart_node() {
  local node=$1
  local before after catch
  before=$(height_of "$node")
  stop_node "$node" scheduled_restart
  start_node "$node"
  wait_node_ready "$node" 120 || json_event type=rpc_not_ready node="$node"
  catch=$(wait_converged 300 || true)
  after=$(height_of "$node")
  json_event type=restart node="$node" height_before="${before:-null}" height_after="${after:-null}" catch_up_seconds="$catch"
}

partition_one() {
  local start h_a h_b h_c catch
  start=$(date +%s)
  h_a=$(height_of node-a); h_b=$(height_of node-b); h_c=$(height_of node-c)
  stop_node node-b partition_18h
  stop_node node-c partition_18h
  PEER[node-b]=""
  PEER[node-c]=""
  start_node node-b
  start_node node-c
  wait_nodes_ready node-b node-c
  for _ in 1 2 3; do
    mine_group node-a
    mine_group node-a
    mine_group node-b node-c
    maybe_snapshot
    sleep "$LOOP_SLEEP_SECONDS"
  done
  local end=$((start + 1800))
  while (( $(date +%s) < end )); do
    maybe_snapshot
    sleep 30
  done
  stop_node node-b partition_18h_reconnect
  stop_node node-c partition_18h_reconnect
  PEER[node-b]="127.0.0.1:19444"
  PEER[node-c]="127.0.0.1:19444"
  start_node node-b
  start_node node-c
  wait_nodes_ready node-b node-c
  catch=$(wait_converged 600 || true)
  json_event type=partition name=partition-18h duration_seconds=1800 convergence_seconds="$catch" divergence="{\"before\":{\"node-a\":\"$h_a\",\"node-b\":\"$h_b\",\"node-c\":\"$h_c\"},\"after\":{\"node-a\":\"$(height_of node-a)\",\"node-b\":\"$(height_of node-b)\",\"node-c\":\"$(height_of node-c)\"}}"
}

partition_two() {
  local start h_a h_b h_c catch
  start=$(date +%s)
  h_a=$(height_of node-a); h_b=$(height_of node-b); h_c=$(height_of node-c)
  stop_node node-c partition_42h
  for _ in 1 2 3 4 5 6; do
    mine_group node-a node-b
    maybe_snapshot
    sleep "$LOOP_SLEEP_SECONDS"
  done
  local end=$((start + 3600))
  while (( $(date +%s) < end )); do
    maybe_snapshot
    sleep 30
  done
  start_node node-c
  wait_node_ready node-c 120 || json_event type=rpc_not_ready node=node-c
  catch=$(wait_converged 600 || true)
  json_event type=partition name=partition-42h duration_seconds=3600 convergence_seconds="$catch" divergence="{\"before\":{\"node-a\":\"$h_a\",\"node-b\":\"$h_b\",\"node-c\":\"$h_c\"},\"after\":{\"node-a\":\"$(height_of node-a)\",\"node-b\":\"$(height_of node-b)\",\"node-c\":\"$(height_of node-c)\"}}"
}

unexpected_exit_check() {
  local node pid
  for node in node-a node-b node-c; do
    if [[ -f "$(pid_file "$node")" ]]; then
      pid=$(cat "$(pid_file "$node")")
      if ! kill -0 "$pid" 2>/dev/null; then
        json_event type=unexpected_exit node="$node" pid="$pid"
        start_node "$node"
      fi
    fi
  done
}

main() {
  rm -f "$LOGS/snapshots.log" "$LOGS/events.jsonl" "$LOGS/mining.jsonl" \
    "$LOGS/node-a.log" "$LOGS/node-b.log" "$LOGS/node-c.log" \
    "$BASE/SOAK_REPORT.md"
  for node in node-a node-b node-c; do
    stop_node "$node" fresh_start
  done
  rm -rf "$BASE/node-a" "$BASE/node-b" "$BASE/node-c"
  mkdir -p "$BASE/node-a" "$BASE/node-b" "$BASE/node-c"

  local start_ts end_ts next_snapshot
  start_ts=$(date +%s)
  end_ts=$((start_ts + DURATION_SECONDS))
  printf '{"start_ts":%s,"duration_seconds":%s,"token":"%s"}\n' "$start_ts" "$DURATION_SECONDS" "$TOKEN" > "$RUN/meta.json"

  start_node node-a
  wait_node_ready node-a 120 || json_event type=rpc_not_ready node=node-a
  start_node node-b
  wait_node_ready node-b 120 || json_event type=rpc_not_ready node=node-b
  start_node node-c
  wait_node_ready node-c 120 || json_event type=rpc_not_ready node=node-c
  snapshot
  json_event type=soak_started duration_seconds="$DURATION_SECONDS"

  next_snapshot=$(( $(date +%s) + SNAPSHOT_INTERVAL_SECONDS ))
  local did_12=0 did_18=0 did_24=0 did_36=0 did_42=0 did_48=0 did_60=0 did_66=0 did_68=0 did_69=0 did_70=0

  while (( $(date +%s) < end_ts )); do
    unexpected_exit_check

    if (( $(max_height) < MINE_TARGET_HEIGHT )); then
      mine_once
    fi

    local elapsed
    elapsed=$(( $(date +%s) - start_ts ))
    if (( did_12 == 0 && elapsed >= 12 * 3600 )); then did_12=1; restart_node node-c; fi
    if (( did_18 == 0 && elapsed >= 18 * 3600 )); then did_18=1; partition_one; fi
    if (( did_24 == 0 && elapsed >= 24 * 3600 )); then did_24=1; restart_node node-b; fi
    if (( did_36 == 0 && elapsed >= 36 * 3600 )); then did_36=1; restart_node node-a; fi
    if (( did_42 == 0 && elapsed >= 42 * 3600 )); then did_42=1; partition_two; fi
    if (( did_48 == 0 && elapsed >= 48 * 3600 )); then did_48=1; restart_node node-c; fi
    if (( did_60 == 0 && elapsed >= 60 * 3600 )); then did_60=1; restart_node node-b; fi
    if (( did_66 == 0 && elapsed >= 66 * 3600 )); then did_66=1; restart_node node-a; fi
    if (( did_68 == 0 && elapsed >= 68 * 3600 )); then did_68=1; restart_node node-c; fi
    if (( did_69 == 0 && elapsed >= 69 * 3600 )); then did_69=1; restart_node node-b; fi
    if (( did_70 == 0 && elapsed >= 70 * 3600 )); then did_70=1; restart_node node-a; fi

    maybe_snapshot
    sleep "$LOOP_SLEEP_SECONDS"
  done

  snapshot
  python3 - "$RUN/meta.json" <<'PY'
import json, sys, time
path = sys.argv[1]
data = json.load(open(path))
data["end_ts"] = int(time.time())
open(path, "w").write(json.dumps(data, sort_keys=True) + "\n")
PY
  "$REPORTER"
  json_event type=soak_finished
}

main "$@"
