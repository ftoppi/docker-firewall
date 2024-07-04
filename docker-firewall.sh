#!/bin/bash
set -o nounset

LOG_LEVEL="" # DEBUG to print debug logs

_log() {
    if [[ "$#" -eq 1 ]]; then
        level="INFO"
        message="$1"
    else
        level="$1"
        message="$2"
    fi

    if [[ -n "${INVOCATION_ID:-}" ]]; then
        date=""
    else
        date="$(date -Iseconds)"
    fi

    if [[ "$level" != "DEBUG" ]] || [[ "$LOG_LEVEL" = "DEBUG" ]]; then
        printf "%s %8s %s\n" "$date" "$level" "$message"
    fi
}


# Function to parse the labels and apply iptables rules
apply_iptables_rules() {
    local CONTAINER_ID="$1"

    LABELS=$(docker inspect --format '{{json .Config.Labels}}' "$CONTAINER_ID")
    if [[ -z "$LABELS" ]]; then
        _log "ERROR" "Failed to get labels for container $CONTAINER_ID"
        return 1
    fi

    PID=$(docker inspect --format '{{.State.Pid}}' "$CONTAINER_ID")
    if [[ -z "$PID" ]]; then
        _log "ERROR" "Failed to get PID for container $CONTAINER_ID"
        return 1
    fi

    RULES=$(echo "$LABELS" | jq -r 'to_entries | map(select(.key | startswith("firewall.rules."))) | map({(.key): .value}) | add')
    if [[ -z "$RULES" ]]; then
        _log "INFO" "No firewall rules found for container $CONTAINER_ID"
        return 1
    fi

    RULE_IDS=$(echo "$RULES" | jq -r '. | keys_unsorted[] | split(".") | .[2]' | sort -u | egrep '^[[:alnum:]]*$')
    if [[ -z "$RULE_IDS" ]]; then
        _log "INFO" "No firewall rule ids found for container $CONTAINER_ID"
        return 1
    fi

    for RULE_ID in $RULE_IDS; do
        _log "DEBUG" "Rule ID=$RULE_ID"

        CHAIN=$(echo "$RULES" | jq -r --arg RULE_ID "$RULE_ID" '. | keys[] | select(startswith("firewall.rules.\($RULE_ID).")) | split(".")[3]' | head -n 1)

        if [[ ! "$CHAIN" =~ ^INPUT|OUTPUT|FORWARD$ ]]; then
        	_log "WARNING" "Rule $RULE_ID CHAIN=$CHAIN is invalid"
        	continue
    	fi

        ACTION=$(echo "$RULES" | jq -r --arg RULE_ID "$RULE_ID" --arg CHAIN "$CHAIN" 'to_entries | map(select(.key | startswith("firewall.rules.\($RULE_ID).\($CHAIN).action"))) | from_entries[] // "ACCEPT"')

        if [[ ! "$ACTION" =~ ^ACCEPT|REJECT|DROP|LOG$ ]]; then
        	_log "WARNING" "Rule $RULE_ID ACTION=$ACTION is invalid"
        	continue
    	fi

        # start building command
        cmd="iptables -A $CHAIN -j $ACTION"

    	if [[ "$ACTION" = "REJECT" ]]; then
            REJECT_WITH=$(echo "$RULES" | jq -r --arg RULE_ID "$RULE_ID" --arg CHAIN "$CHAIN" 'to_entries | map(select(.key | startswith("firewall.rules.\($RULE_ID).\($CHAIN).reject_with"))) | from_entries[] // "icmp-admin-prohibited"')

    	    if [[ ! "$REJECT_WITH" =~ ^icmp-net-unreachable|icmp-host-unreachable|icmp-port-unreachable|icmp-proto-unreachable|icmp-net-prohibited|icmp-host-prohib‐ited|icmp-admin-prohibited$ ]]; then
    	        _log "WARNING" "Rule $RULE_ID REJECT_WITH=$REJECT_WITH is invalid"
    	        continue
    	    fi

    	    cmd="$cmd --reject-with $REJECT_WITH"
    	fi

        PROTOCOL=$(echo "$RULES" | jq -r --arg RULE_ID "$RULE_ID" --arg CHAIN "$CHAIN" 'to_entries | map(select(.key | startswith("firewall.rules.\($RULE_ID).\($CHAIN).protocol"))) | from_entries[] // "all"')

        if [[ ! "$PROTOCOL" =~ ^all|tcp|udp|icmp|ip$ ]]; then
        	_log "WARNING" "Rule $RULE_ID PROTOCOL=$PROTOCOL is invalid"
        	continue
    	fi

        SRC=$(echo "$RULES" | jq -r --arg RULE_ID "$RULE_ID" --arg CHAIN "$CHAIN" 'to_entries | map(select(.key | startswith("firewall.rules.\($RULE_ID).\($CHAIN).src"))) | from_entries[] // "0.0.0.0/0"')

        if [[ ! "$SRC" =~ ^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\/([0-9]|[1-2][0-9]|3[0-2]))?$ ]]; then
        	_log "WARNING" "Rule $RULE_ID SRC=$SRC is invalid"
        	continue
        fi

        DST=$(echo "$RULES" | jq -r --arg RULE_ID "$RULE_ID" --arg CHAIN "$CHAIN" 'to_entries | map(select(.key | startswith("firewall.rules.\($RULE_ID).\($CHAIN).dst"))) | from_entries[] // "0.0.0.0/0"')

        if [[ ! "$DST" =~ ^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\/([0-9]|[1-2][0-9]|3[0-2]))?$ ]]; then
        	_log "WARNING" "Rule $RULE_ID DST=$DST is invalid"
        	continue
        fi

        cmd="$cmd -p $PROTOCOL -s $SRC -d $DST"

        SPORT="N/A"
        DPORT="N/A"

        if [[ "$PROTOCOL" =~ ^tcp|udp$ ]]; then
            SPORT=$(echo "$RULES" | jq -r --arg RULE_ID "$RULE_ID" --arg CHAIN "$CHAIN" 'to_entries | map(select(.key | startswith("firewall.rules.\($RULE_ID).\($CHAIN).sport"))) | from_entries[] // "0"')
            if [[ "$SPORT" =~ ^[0-9]+$ ]] && [[ "$SPORT" -gt "0" ]]; then
                cmd="$cmd --sport $SPORT"
            fi

            DPORT=$(echo "$RULES" | jq -r --arg RULE_ID "$RULE_ID" --arg CHAIN "$CHAIN" 'to_entries | map(select(.key | startswith("firewall.rules.\($RULE_ID).\($CHAIN).dport"))) | from_entries[] // "0"')
            if [[ "$DPORT" =~ ^[0-9]+$ ]] && [[ "$DPORT" -gt "0" ]]; then
                cmd="$cmd --dport $DPORT"
            fi
        fi

        _log "DEBUG" "Container=${CONTAINER_ID:0:8} PID=$PID RULE_ID=$RULE_ID is valid, applying CHAIN=$CHAIN ACTION=$ACTION PROTOCOL=$PROTOCOL SRC=$SRC DST=$DST SPORT=$SPORT DPORT=$DPORT"
        _log "DEBUG" "cmd=$cmd"

        nsenter -n -t "$PID" -- $cmd
        retcode="$?"

        if [[ "$retcode" -eq "0" ]]; then
            _log "Container=${CONTAINER_ID:0:8} PID=$PID RULE_ID=$RULE_ID applied successfully cmd=$cmd"
        else
            _log "WARNING" "Container=${CONTAINER_ID:0:8} PID=$PID RULE_ID=$RULE_ID failed with retcode=$retcode"
        fi
    done
}

if ! command -v jq &> /dev/null
then
    echo "Error: jq is not installed."
    exit 1
fi

if ! command -v nsenter &> /dev/null
then
    echo "Error: nsenter is not installed."
    exit 1
fi

# Listen to Docker events
docker events --filter type=container --filter event=start --filter label=firewall.enable=true | while read event; do
    CONTAINER_ID=$(echo $event | awk '{print $4}')
    CONTAINER_NAME=$(echo $event | sed -e 's/^.*, name=\(\S*\)).*$/\1/')
    _log "Container started name=$CONTAINER_NAME id=${CONTAINER_ID:0:8}"
    apply_iptables_rules $CONTAINER_ID
    _log "Container rules processed"
done
