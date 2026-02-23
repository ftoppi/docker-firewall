#!/bin/bash
set -euo pipefail

# Design choices:
# - The script does not remove rules when a container is stopped. Instead, it relies the namespace being deleted, and its associated rules with it.
# - The script does not support rules applied at the network level. This is intended to not have to cleanup rules on network destruction.
# - The script is written in Bash, which should tell you it is not meant for performance. It is not meant for busy systems where containers start all the time.
# - The script only supports IPv4.
# - The script relies on jq for JSON parsing.

readonly LOG_LEVEL="${LOG_LEVEL:-INFO}" # set to DEBUG to print debug logs
readonly DRY_RUN="${DRY_RUN:-0}"


_log() {
    if [[ "$#" -eq 1 ]]; then
        local level="INFO"
        local message="$1"
    else
        local level="$1"
        local message="$2"
    fi

    if [[ -n "${INVOCATION_ID:-}" ]]; then
        local date=""
    else
        local date="$(date -Iseconds)"
    fi

    if [[ "$level" == "DEBUG" ]] && [[ "$LOG_LEVEL" != "DEBUG" ]]; then
        return
    fi

    printf "%s %8s %s\n" "$date" "$level" "$message"
}


# Function to parse the labels and apply iptables rules
apply_iptables_rules() {
    local CONTAINER_ID="$1"

    local LABELS=$(docker inspect --format '{{json .Config.Labels}}' "$CONTAINER_ID")
    if [[ -z "$LABELS" ]]; then
        _log "ERROR" "Failed to get labels for container $CONTAINER_ID"
        return 1
    fi

    local PID=$(docker inspect --format '{{.State.Pid}}' "$CONTAINER_ID")
    if [[ -z "$PID" ]]; then
        _log "ERROR" "Failed to get PID for container $CONTAINER_ID"
        return 1
    fi

    local RULES=$(echo "$LABELS" | jq -r | grep -P '^  "firewall\.rules\.')
    if [[ -z "$RULES" ]]; then
        _log "INFO" "No firewall rules found for container $CONTAINER_ID"
        return 1
    fi

    local RULE_IDS=$(echo "$RULES" | cut -d '.' -f 3 | sort -u | egrep '^[[:alnum:]]*$')
    if [[ -z "$RULE_IDS" ]]; then
        _log "INFO" "No firewall rule ids found for container $CONTAINER_ID"
        return 1
    fi

    _log "Rules to process: $(echo $RULE_IDS | wc -w)"

    for RULE_ID in $RULE_IDS; do
        _log "DEBUG" "Rule ID=$RULE_ID"

        local RULE=$(echo "$RULES" | grep -P "firewall\.rules\.${RULE_ID}\.")

        local CHAIN_COUNT=$(echo "$RULE" | cut -d '.' -f 4 | sort -u | wc -l)

        _log "DEBUG" "Rule $RULE_ID CHAIN_COUNT=$CHAIN_COUNT"

        if [[ "$CHAIN_COUNT" -ne 1 ]]; then
            _log "WARNING" "Rule $RULE_ID chain count ($CHAIN_COUNT) is invalid, ignoring rule"
            continue
        fi

        local CHAIN=$(echo "$RULE" | head -n1 | cut -d '.' -f 4)

        _log "DEBUG" "Rule $RULE_ID CHAIN=$CHAIN"

        if [[ ! "$CHAIN" =~ ^INPUT|OUTPUT|FORWARD$ ]]; then
        	_log "WARNING" "Rule $RULE_ID CHAIN=$CHAIN is invalid, ignoring rule"
        	continue
    	fi

        local ACTION=$(echo "$RULE" | grep -E "firewall.rules.${RULE_ID}.${CHAIN}.action" | cut -d '"' -f 4)

        _log "DEBUG" "Rule $RULE_ID ACTION=$ACTION"

        if [[ ! "$ACTION" =~ ^ACCEPT|REJECT|DROP|LOG$ ]]; then
        	_log "WARNING" "Rule $RULE_ID ACTION=$ACTION is invalid"
        	continue
    	fi

        # start building command
        local cmd="iptables -A $CHAIN -j $ACTION"

    	if [[ "$ACTION" = "REJECT" ]]; then
            local REJECT_WITH=$(echo "$RULE" | grep -E "firewall.rules.${RULE_ID}.${CHAIN}.reject_with" | cut -d '"' -f 4)

            _log "DEBUG" "Rule $RULE_ID REJECT_WITH=$REJECT_WITH"

    	    if [[ ! "$REJECT_WITH" =~ ^icmp-net-unreachable|icmp-host-unreachable|icmp-port-unreachable|icmp-proto-unreachable|icmp-net-prohibited|icmp-host-prohib‐ited|icmp-admin-prohibited$ ]]; then
    	        _log "WARNING" "Rule $RULE_ID REJECT_WITH=$REJECT_WITH is invalid"
    	        continue
    	    fi

    	    cmd="$cmd --reject-with $REJECT_WITH"
    	fi

        local PROTOCOL=$(echo "$RULE" | grep -E "firewall.rules.${RULE_ID}.${CHAIN}.protocol" | cut -d '"' -f 4)

        _log "DEBUG" "Rule $RULE_ID PROTOCOL=$PROTOCOL"

        if [[ ! "$PROTOCOL" =~ ^all|tcp|udp|icmp|ip$ ]]; then
        	_log "WARNING" "Rule $RULE_ID PROTOCOL=$PROTOCOL is invalid"
        	continue
    	fi

        local SRC=$(echo "$RULE" | grep -E "firewall.rules.${RULE_ID}.${CHAIN}.src" | cut -d '"' -f 4)

        if [[ -z "$SRC" ]]; then
            SRC="0.0.0.0/0"
        fi

        _log "DEBUG" "Rule $RULE_ID SRC=$SRC"

        if [[ ! "$SRC" =~ ^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\/([0-9]|[1-2][0-9]|3[0-2]))?$ ]]; then
        	_log "WARNING" "Rule $RULE_ID SRC=$SRC is invalid"
        	continue
        fi

        local DST=$(echo "$RULE" | grep -E "firewall.rules.${RULE_ID}.${CHAIN}.dst" | cut -d '"' -f 4)

        if [[ -z "$DST" ]]; then
            DST="0.0.0.0/0"
        fi

        _log "DEBUG" "Rule $RULE_ID DST=$DST"

        if [[ ! "$DST" =~ ^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\/([0-9]|[1-2][0-9]|3[0-2]))?$ ]]; then
        	_log "WARNING" "Rule $RULE_ID DST=$DST is invalid"
        	continue
        fi

        cmd="$cmd -p $PROTOCOL -s $SRC -d $DST"

        _log "DEBUG" "cmd=$cmd"

        local SPORT="N/A"
        local DPORT="N/A"

        if [[ "$PROTOCOL" =~ ^tcp|udp$ ]]; then
            _log "DEBUG" "looking for port numbers"

            local SPORT=$(echo "$RULE" | grep -E "firewall.rules.${RULE_ID}.${CHAIN}.sport" | cut -d '"' -f 4)

            _log "DEBUG" "Rule $RULE_ID SPORT=$SPORT"

            if [[ "$SPORT" =~ ^[0-9]+$ ]] && [[ "$SPORT" -gt "0" ]]; then
                cmd="$cmd --sport $SPORT"
            fi

            local DPORT=$(echo "$RULE" | grep -E "firewall.rules.${RULE_ID}.${CHAIN}.dport" | cut -d '"' -f 4)

            _log "DEBUG" "Rule $RULE_ID DPORT=$DPORT"

            if [[ "$DPORT" =~ ^[0-9]+$ ]] && [[ "$DPORT" -gt "0" ]]; then
                cmd="$cmd --dport $DPORT"
            fi

            _log "DEBUG" "cmd=$cmd"
        fi

        _log "DEBUG" "Container=${CONTAINER_ID:0:8} PID=$PID RULE_ID=$RULE_ID is valid, applying CHAIN=$CHAIN ACTION=$ACTION PROTOCOL=$PROTOCOL SRC=$SRC DST=$DST SPORT=$SPORT DPORT=$DPORT"
        _log "DEBUG" "cmd=$cmd"

        if [[ "$DRY_RUN" -eq 1 ]]; then
            _log "DRY RUN MODE - Container=${CONTAINER_ID:0:8} would run: nsenter -n -t $PID $cmd"
            continue
        fi

        if ! nsenter -n -t "$PID" $cmd; then
            _log "WARNING" "Container=${CONTAINER_ID:0:8} PID=$PID RULE_ID=$RULE_ID failed"
            continue
        fi

        _log "Container=${CONTAINER_ID:0:8} PID=$PID RULE_ID=$RULE_ID applied successfully cmd=$cmd"
    done
}

if [[ "$(id -u)" -ne 0 ]]; then
    _log "ERROR" "This script must be run as root."
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "Error: jq is not installed."
    exit 1
fi

if ! command -v nsenter &> /dev/null; then
    echo "Error: nsenter is not installed."
    exit 1
fi

_log "docker-firewall started, listening for events"

_log "DEBUG" "debug log enabled"

# Listen to Docker events
docker events --filter type=container --filter event=start --filter label=firewall.enable=true | while read event; do
    CONTAINER_ID=$(echo "$event" | awk '{print $4}')
    CONTAINER_NAME=$(echo "$event" | sed -e 's/^.*, name=\(\S*\)).*$/\1/')
    _log "Container started name=$CONTAINER_NAME id=${CONTAINER_ID:0:8}"
    apply_iptables_rules "$CONTAINER_ID"
    _log "Container rules processed"
done
