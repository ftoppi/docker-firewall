#!/bin/bash
set -euo pipefail

# Design choices:
# - The script does not remove rules when a container is stopped. Instead, it relies the namespace being deleted, and its associated rules with it.
# - The script does not support rules applied at the network level. This is intended to not have to cleanup rules on network destruction.
# - The script is written in Bash, which should tell you it is not meant for performance. It is not meant for busy systems where containers start all the time.
# - The script only supports IPv4.
# - The script relies on jq for JSON parsing.

readonly DEBUG="${DEBUG:-0}" # set to 1 to print debug logs
readonly DRY_RUN="${DRY_RUN:-0}"

NOW="$(date +%Y%m%d_%H%M%S)"
readonly NOW

readonly BASE_DIR="/dev/shm/dfw.${NOW}"

# initialize base directory
rm -rf -- "$BASE_DIR"
mkdir -p "$BASE_DIR"


_log() {
    if [[ "$#" -eq 1 ]]; then
        local level="INFO"
        local message="$1"
    else
        local level="$1"
        local message="$2"
    fi

    local date

    if [[ -n "${INVOCATION_ID:-}" ]]; then
        date=""
    else
        date="$(date -Iseconds)"
    fi

    if [[ "$level" == "DEBUG" ]] && [[ "$DEBUG" != "1" ]]; then
        return
    fi

    printf "%s %8s %s\n" "$date" "$level" "$message"
}


cleanup() {
    _log "INFO" "Cleanup on exit"
    rm -vrf -- "$BASE_DIR"
    exit 0
}

cleanup_container() {
    _log "INFO" "Cleanup container $1 files"
    find "$BASE_DIR" -type f -name "*_$1" -ls -delete
}

trap cleanup INT


get_container_pid() {
    _pid=$(docker inspect --format '{{.State.Pid}}' "$1" 2>/dev/null)

    if [[ -z "$_pid" ]]; then
        _log "ERROR" "Failed to get PID for container $1"
        return 1
    fi

    echo "$_pid"

    return 0
}


get_container_labels() {
    _log "DEBUG" "get_container_labels $1"

    if ! docker inspect --format '{{json .Config.Labels}}' "$1" > "$BASE_DIR/container_labels_$1"; then
        _log "ERROR" "Failed to get labels for container $1"
        return 1
    fi

    return 0
}


get_container_policies() {
    _log "DEBUG" "get_container_policies $1"

    if ! jq -r 'with_entries(select(.key | startswith("firewall.policies.")))' < "$BASE_DIR/container_labels_$1" > "$BASE_DIR/container_policies_$1"; then
        _log "INFO" "No firewall policies found for container $1"
        return 1
    fi

    return 0
}


process_container_policy() {
    _log "DEBUG" "process_container_policy _pid=$_pid $1"

    echo "$1" | while read -r _chain _action; do
        _log "DEBUG" "Policy Chain=$_chain Action=$_action"
        _chain="$(echo "$_chain" | sed -e 's/^.*\.\([A-Z]*\)":.*$/\1/')"
        _action="$(echo "$_action" | cut -d '"' -f 2)"

        if [[ ! "$_chain" =~ ^(INPUT|OUTPUT|FORWARD)$ ]]; then
            _log "WARNING" "Policy Chain=/$_chain/ is invalid"
            return 1
        fi

        if [[ ! "$_action" =~ ^(ACCEPT|DROP)$ ]]; then
            _log "WARNING" "Action=/$_action/ is invalid"
            return 1
        fi

        _log "DEBUG" "Policy Chain=$_chain Action=$_action is valid"

        cmd="nsenter -n -t $_pid iptables -P $_chain $_action"

        if [[ "$DRY_RUN" -eq 1 ]]; then
            _log "DRY RUN MODE - Container=$object_id would run: $cmd"
            return 0
        fi

        if ! $cmd; then
            _log "WARNING" "Container=$object_id PID=$(cat "$BASE_DIR/container_pid_$1") Policy Chain=$_chain Action=$_action failed"
            return 1
        fi
    done

    return 0
}


process_container_policies() {
    _log "DEBUG" "process_container_policies $1"

    get_container_policies "$1" || return 1

    grep "firewall.policies" "$BASE_DIR/container_policies_$1" | while read -r policy; do
        process_container_policy "$policy"
    done

    return 0
}


get_container_rules() {
    _log "DEBUG" "get_container_rules $1"

    if ! jq -r 'with_entries(select(.key | startswith("firewall.rules.")))' < "$BASE_DIR/container_labels_$1" > "$BASE_DIR/container_rules_$1"; then
        _log "INFO" "No firewall rules found for container $1"
        return 1
    fi

    local _count
    _count=$(( $(wc -l < "$BASE_DIR/container_rules_$1") - 2 ))

    _log "DEBUG" "Found $_count rules for container $1"

    return 0
}


get_container_rule_ids() {
    _log "DEBUG" "get_container_rule_ids $1"

    if ! grep "firewall.rules" "$BASE_DIR/container_rules_$1" | cut -d '.' -f 3 | sort -u | grep -P '^[[:alnum:]]*$' > "$BASE_DIR/container_rule_ids_$1"; then
        _log "INFO" "No firewall rule ids found for container $1"
        return 1
    fi

    local _count
    _count=$(( $(wc -l < "$BASE_DIR/container_rule_ids_$1") - 2 ))

    _log "DEBUG" "Found $_count rule IDs for container $1"

    return 0
}


validate_rule_chain_count() {
    local CHAIN_COUNT

    CHAIN_COUNT=$(echo "$1" | cut -d '.' -f 4 | sort -u | wc -l)

    if [[ "$CHAIN_COUNT" -ne 1 ]]; then
        _log "WARNING" "Rule chain count ($CHAIN_COUNT) is invalid, ignoring rule"
        return 1
    fi

    return 0
}


get_rule_chain() {
    # $1: container|network
    # $2: object id
    # $3: chain id

    if [[ ! "$1" =~ ^(container|network)$ ]]; then
        _log "WARNING" "Call get_rule_chain invalid type=$1 invalid, ignoring rule"
        return 1
    fi

    local _chain

    if ! _chain=$(grep -E "firewall.rules.${3}." "$BASE_DIR/${1}_rules_$2" 2>/dev/null | head -n1 | cut -d '.' -f 4 | tr 'a-z' 'A-Z'); then
        _log "WARNING" "$1 $2 rule $3 is invalid, ignoring rule"
        return 1
    fi

    if [[ ! "$_chain" =~ ^(INPUT|OUTPUT|FORWARD)$ ]]; then
        _log "WARNING" "$1 $2 rule $3 chain=$_chain is invalid, ignoring rule"
        return 1
    fi

    echo "$_chain"
}


get_rule_protocol() {
    # $1: container|network
    # $2: object id
    # $3: chain id

    if [[ ! "$1" =~ ^(container|network)$ ]]; then
        _log "WARNING" "Call get_rule_protocol invalid type=$1 invalid, ignoring rule"
        return 1
    fi

    local _protocol

    # protocol may be omitted
    set +o pipefail
    _protocol=$(grep -P "firewall\.rules\.${3}\.[A-Z]+\.protocol" "$BASE_DIR/${1}_rules_${2}" 2>/dev/null | head -n1 | cut -d '"' -f 4 | tr 'A-Z' 'a-z')
    set -o pipefail

    if [[ -n "$_protocol" ]] && [[ ! "$_protocol" =~ ^tcp|udp$ ]]; then
        _log "WARNING" "$1 $2 rule $3 protocol=$_protocol is invalid, ignoring rule"
        return 1
    fi

    echo "$_protocol"
}


get_rule_action() {
    # $1: container|network
    # $2: object id
    # $3: chain id

    if [[ ! "$1" =~ ^(container|network)$ ]]; then
        _log "WARNING" "Call get_rule_action invalid type=$1, ignoring rule"
        return 1
    fi

    local _action

    if ! _action=$(grep -P "firewall\.rules\.${3}\.[A-Z]+\.action" "$BASE_DIR/${1}_rules_${2}" 2>/dev/null | head -n1 | cut -d '"' -f 4 | tr 'a-z' 'A-Z'); then
        _log "WARNING" "$1 $2 rule $3 is invalid, ignoring rule"
        return 1
    fi

    if [[ ! "$_action" =~ ^(ACCEPT|DROP|REJECT)$ ]]; then
        _log "WARNING" "$1 $2 rule $3 action=$_action is invalid, ignoring rule"
        return 1
    fi

    echo "$_action"
}


get_rule_port() {
    # $1: container|network
    # $2: object id
    # $3: chain id
    # $4: sport|dport

    if [[ ! "$1" =~ ^(container|network)$ ]]; then
        _log "WARNING" "Call get_rule_port invalid type=$1, ignoring rule"
        return 1
    fi

    if [[ ! "$4" =~ ^(sport|dport)$ ]]; then
        _log "WARNING" "Call get_rule_port invalid port=$4, ignoring rule"
        return 1
    fi

    local _port

    set +o pipefail
    _port=$(grep -P "firewall\.rules\.${3}\.[A-Z]+\.${4}" "$BASE_DIR/${1}_rules_${2}" 2>/dev/null | head -n1 | cut -d '"' -f 4)
    set -o pipefail

    if [[ -n "$_port" ]] && [[ ! "$_port" =~ ^[0-9]+$ ]]; then
        _log "WARNING" "$1 $2 rule $3 _port=$_port is invalid, ignoring rule"
        return 1
    fi

    echo "$_port"
}


get_rule_srcdst() {
    # $1: container|network
    # $2: object id
    # $3: chain id
    # $4: src|dst

    if [[ ! "$1" =~ ^(container|network)$ ]]; then
        _log "WARNING" "Call get_rule_srcdst invalid type=$1, ignoring rule"
        return 1
    fi

    if [[ ! "$4" =~ ^(src|dst)$ ]]; then
        _log "WARNING" "Call get_rule_srcdst invalid srcdst=$4, ignoring rule"
        return 1
    fi

    local _srcdst

    set +o pipefail
    _srcdst=$(grep -P "firewall\.rules\.${3}\.[A-Z]+\.${4}" "$BASE_DIR/${1}_rules_${2}" 2>/dev/null | head -n1 | cut -d '"' -f 4)
    set -o pipefail

    if [[ -n "$_srcdst" ]] && [[ ! "$_srcdst" =~ ^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\/(3[0-2]|[12]?[0-9]))?$ ]]; then
        _log "WARNING" "$1 $2 rule $3 _srcdst=$_srcdst is invalid, ignoring rule"
        return 1
    fi

    echo "$_srcdst"
}

get_rule_state() {
    # $1: container|network
    # $2: object id
    # $3: chain id

    if [[ ! "$1" =~ ^(container|network)$ ]]; then
        _log "WARNING" "Call get_rule_state invalid type=$1, ignoring rule"
        return 1
    fi

    local _state

    set +o pipefail
    _state=$(grep -P "firewall\.rules\.${3}\.[A-Z]+\.state" "$BASE_DIR/${1}_rules_${2}" 2>/dev/null | head -n1 | cut -d '"' -f 4 | tr 'a-z' 'A-Z')
    set -o pipefail

    if [[ ! "$_state" =~ ^(RELATED,ESTABLISHED|ESTABLISHED,RELATED|ESTABLISHED|RELATED|)$ ]]; then
        _log "WARNING" "$1 $2 rule $3 state=$_state is invalid, ignoring rule"
        return 1
    fi

    echo "$_state"
}


get_rule() {
    local RULES="$1"
    local RULE_ID="$2"

    local RULE
    RULE=$(echo "$RULES" | grep -P "firewall\.rules\.${RULE_ID}\.")

    if [[ -z "$RULE" ]]; then
        _log "WARNING" "Rule with ID=$RULE_ID is invalid, ignoring rule"
        return 1
    fi

    echo "$RULE"
}


process_container_rule() {
    _log "DEBUG" "process_container_rule_id $1 id=$2"

    local _chain
    local _cmd
    local _src
    local _dst
    local _protocol
    local _state
    local _action

    _chain=$(get_rule_chain         "container" "$1" "$2") || { _log "WARNING" "get_rule_chain failed"; return 1; }
    _cmd="nsenter -n -t $_pid iptables -A $_chain -m comment --comment $2"

    if [[ "$_chain" = "INPUT" ]]; then
        _src=$(get_rule_srcdst         "container" "$1" "$2" "src") || { _log "WARNING" "get_rule_srcdst src failed"; return 1; }
        if [[ -n "$_src" ]]; then
            _cmd="$_cmd -s $_src"
        fi

        _dst="0.0.0.0/0"
    fi

    if [[ "$_chain" = "OUTPUT" ]]; then
        _src="0.0.0.0/0"

        _dst=$(get_rule_srcdst         "container" "$1" "$2" "dst") || { _log "WARNING" "get_rule_srcdst dst failed"; return 1; }
        if [[ -n "$_dst" ]]; then
            _cmd="$_cmd -d $_dst"
        fi
    fi

    _protocol=$(get_rule_protocol   "container" "$1" "$2") || { _log "WARNING" "get_rule_protocol failed"; return 1; }
    if [[ -n "$_protocol" ]]; then
        _cmd="$_cmd -p $_protocol"
    fi

    if [[ -n "$_protocol" ]]; then
        local _sport
        local _dport

        _sport=$(get_rule_port         "container" "$1" "$2" "sport") || { _log "WARNING" "get_rule_port sport failed"; return 1; }
        if [[ -n "$_sport" ]]; then
            _cmd="$_cmd --sport $_sport"
        fi

        _dport=$(get_rule_port         "container" "$1" "$2" "dport") || { _log "WARNING" "get_rule_port dport failed"; return 1; }
        if [[ -n "$_dport" ]]; then
            _cmd="$_cmd --dport $_dport"
        fi
    fi

    _state=$(get_rule_state "container" "$1" "$2") || { _log "WARNING" "get_rule_state failed"; return 1; }

    if [[ -n "$_state" ]] ; then
        _cmd="$_cmd -m state --state $_state"
    fi

    _action=$(get_rule_action       "container" "$1" "$2") || { _log "WARNING" "get_rule_action failed"; return 1; }
    _cmd="$_cmd -j $_action"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        _log "DRY RUN MODE - Container=$1 pid=$_pid would run: $_cmd"
        return 0
    fi

    if ! $_cmd; then
        _log "WARNING" "Container=$1 PID=$(cat "$BASE_DIR/container_pid_$1") Policy Chain=$_chain Action=$_action failed"
        return 1
    fi

    _log INFO "Applied successfully: $_cmd"
}


process_container_rules() {
    _log "DEBUG" "process_container_rules $1"

    local rule_id

    while read rule_id; do
        process_container_rule "$1" "$rule_id" || _log "ERROR" "Something went wrong"
    done < "$BASE_DIR/container_rule_ids_$1"
}


process_event_container() {
    _log "DEBUG" "New event $event_type action=$event_action object_id=$object_id"

    if [[ "$event_action" != "start" ]]; then
        return
    fi

    _pid=$(get_container_pid    "$object_id") || return 1
    _log "DEBUG" "====="

    get_container_labels        "$object_id"  || return 1
    _log "DEBUG" "====="

    process_container_policies  "$object_id"  || return 1
    _log "DEBUG" "====="

    get_container_rules         "$object_id"  || return 1
    get_container_rule_ids      "$object_id"  || return 1
    process_container_rules     "$object_id"  || return 1

    # cleanup_container           "$object_id"
}


toto() {
    _log "Rules to process: $(echo "$RULE_IDS" | wc -w)"

    for RULE_ID in $RULE_IDS; do
        _log "DEBUG" "Rule ID=$RULE_ID"

        if ! RULE=$(get_rule "$RULES" "$RULE_ID"); then
            continue
        fi



        if ! ACTION=$(get_rule_action "$RULE"); then
        	_log "WARNING" "Rule $RULE_ID ACTION=$ACTION is invalid"
        	continue
    	fi

        # start building command
        cmd="iptables -A $CHAIN -j $ACTION"

    	if [[ "$ACTION" = "REJECT" ]]; then
            REJECT_WITH=$(echo "$RULE" | grep -E "firewall.rules.${RULE_ID}.${CHAIN}.reject_with" | cut -d '"' -f 4)

            _log "DEBUG" "Rule $RULE_ID REJECT_WITH=$REJECT_WITH"

    	    if [[ ! "$REJECT_WITH" =~ ^icmp-net-unreachable|icmp-host-unreachable|icmp-port-unreachable|icmp-proto-unreachable|icmp-net-prohibited|icmp-host-prohib‐ited|icmp-admin-prohibited$ ]]; then
    	        _log "WARNING" "Rule $RULE_ID REJECT_WITH=$REJECT_WITH is invalid"
    	        continue
    	    fi

    	    cmd="$cmd --reject-with $REJECT_WITH"
    	fi

        PROTOCOL=$(echo "$RULE" | grep -E "firewall.rules.${RULE_ID}.${CHAIN}.protocol" | cut -d '"' -f 4)

        _log "DEBUG" "Rule $RULE_ID PROTOCOL=$PROTOCOL"

        if [[ ! "$PROTOCOL" =~ ^all|tcp|udp|icmp|ip$ ]]; then
        	_log "WARNING" "Rule $RULE_ID PROTOCOL=$PROTOCOL is invalid"
        	continue
    	fi

        SRC=$(echo "$RULE" | grep -E "firewall.rules.${RULE_ID}.${CHAIN}.src" | cut -d '"' -f 4)

        if [[ -z "$SRC" ]]; then
            SRC="0.0.0.0/0"
        fi

        _log "DEBUG" "Rule $RULE_ID SRC=$SRC"

        if [[ ! "$SRC" =~ ^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\/([0-9]|[1-2][0-9]|3[0-2]))?$ ]]; then
        	_log "WARNING" "Rule $RULE_ID SRC=$SRC is invalid"
        	continue
        fi

        DST=$(echo "$RULE" | grep -E "firewall.rules.${RULE_ID}.${CHAIN}.dst" | cut -d '"' -f 4)

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

        SPORT="N/A"
        DPORT="N/A"

        if [[ "$PROTOCOL" =~ ^tcp|udp$ ]]; then
            _log "DEBUG" "looking for port numbers"

            SPORT=$(echo "$RULE" | grep -E "firewall.rules.${RULE_ID}.${CHAIN}.sport" | cut -d '"' -f 4)

            _log "DEBUG" "Rule $RULE_ID SPORT=$SPORT"

            if [[ "$SPORT" =~ ^[0-9]+$ ]] && [[ "$SPORT" -gt "0" ]]; then
                cmd="$cmd --sport $SPORT"
            fi

            DPORT=$(echo "$RULE" | grep -E "firewall.rules.${RULE_ID}.${CHAIN}.dport" | cut -d '"' -f 4)

            _log "DEBUG" "Rule $RULE_ID DPORT=$DPORT"

            if [[ "$DPORT" =~ ^[0-9]+$ ]] && [[ "$DPORT" -gt "0" ]]; then
                cmd="$cmd --dport $DPORT"
            fi

            _log "DEBUG" "cmd=$cmd"
        fi

        _log "DEBUG" "Container=${object_id:0:8} PID=$PID RULE_ID=$RULE_ID is valid, applying CHAIN=$CHAIN ACTION=$ACTION PROTOCOL=$PROTOCOL SRC=$SRC DST=$DST SPORT=$SPORT DPORT=$DPORT"
        _log "DEBUG" "cmd=$cmd"

        if [[ "$DRY_RUN" -eq 1 ]]; then
            _log "DRY RUN MODE - Container=${object_id:0:8} would run: nsenter -n -t $PID $cmd"
            continue
        fi

        if ! nsenter -n -t "$PID" $cmd; then
            _log "WARNING" "Container=${object_id:0:8} PID=$PID RULE_ID=$RULE_ID failed"
            continue
        fi

        _log "Container=${object_id:0:8} PID=$PID RULE_ID=$RULE_ID applied successfully cmd=$cmd"
    done
}


process_event_network() {
    _log "DEBUG" "New event network   $event"
    return
}


process_event() {
    local event_type
    local event_action
    local object_id

    event_type=$(echo "$1" | awk '{print $2}')
    event_action=$(echo "$1" | awk '{print $3}')
    object_id=$(echo "$1" | awk '{print substr($4, 1, 12)}')

    case "$event_type" in
        "container")
            process_event_container
            ;;

        "network")
            process_event_network
            ;;

        *)
            _log "ERROR" "Event type=$event_type unsupported"
            return 1
            ;;
    esac
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

if [[ "$DRY_RUN" -eq 1 ]]; then
    _log "INFO" "DRY RUN enabled"
fi


# Listen to Docker events
docker events --filter type=container --filter type=network --filter event=start --filter event=create --filter event=destroy --filter label=firewall.enable=true | while read -r event; do
    process_event "$event"
    _log "DEBUG" "=========="
done
