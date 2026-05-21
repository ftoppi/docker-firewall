#!/bin/bash
set -euo pipefail

# Design choices:
# - The script is not targeted at companies and professional environments where security is paramount and related services are legion. I have less than 10 rules (policies included) per container.
# - The script does not remove rules when a container is stopped. Instead, it relies the namespace being deleted, and its associated rules with it.
# - The script does not support rules applied at the network level *YET*. This is intended to not have to cleanup rules on network destruction.
# - The script is written in Bash, which should tell you it is not meant for performance. It is not meant for busy systems where containers start all the time.
# - The script only supports IPv4.
# - The script relies on jq for JSON parsing.
# - The script does not prevent you from making mistakes and blocking access to containers.
# - The script sorts rules by keys before applying them.
# - The script uses legacy iptables rules for now.
# - The script stores temporary files in /dev/shm and deletes them when the rules are successfully processed and when the script exits.
# - The script listens to Docker events and only cares about the 2nd, 3rd and 4th fields: object type, event type and object id. The other fields are ignored. The script then calls docker inspect to gather the required information.

# Todo:
# - Support rules at the network level, which implies cleaning up the rules when the network is destroyed.
# - Support modern netfilter rules instead of legacy iptables rules.
# - Standardize log messages.
# - Benchmark the script.

# Sample docker event for a container:
# 2026-02-26T16:20:50.696813500+01:00 container start  07a46f3102baee08d941d57218ac249aa63a8d91cb2bbd4025146f5643c73fc6 foobar

# Sample labels for a container, in `docker-compose.yml`:
# labels:
#   - firewall.enable=true
#   - firewall.policies.INPUT=DROP
#   - firewall.policies.OUTPUT=DROP
#   - firewall.rules.000.OUTPUT.state=related,established
#   - firewall.rules.000.OUTPUT.action=accept
#   - firewall.rules.010.INPUT.action=accept
#   - firewall.rules.010.INPUT.protocol=tcp
#   - firewall.rules.010.INPUT.dport=80

umask 077

DEBUG="${DEBUG:-0}" # set to 1 to print debug logs
DRY_RUN="${DRY_RUN:-0}"
CLEANUP="${CLEANUP:-1}"
CLEANUP_EXIT="${CLEANUP_EXIT:-1}"
NOW="$(date +%Y%m%d_%H%M%S)"
BASE_DIR=$(mktemp -d -p /dev/shm dfw.XXXXXX)

readonly DEBUG
readonly DRY_RUN
readonly CLEANUP
readonly CLEANUP_EXIT
readonly NOW
readonly BASE_DIR


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
    if [[ "$CLEANUP_EXIT" -eq "1" ]]; then
        _log "INFO" "Cleanup on exit"
        rm -vrf -- "$BASE_DIR"
    fi
    exit 0
}

cleanup_container() {
    if [[ "$CLEANUP" -eq "1" ]]; then
        _log "INFO" "Cleanup container $1 files"
        find "$BASE_DIR" -type f -name "*_$1" -ls -delete
    fi
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
    # $1: policy

    _log "DEBUG" "process_container_policy _pid=$_pid $1"

    echo "$1" | while read -r _chain _action; do
        _log "DEBUG" "Policy Chain=$_chain Action=$_action"
        # shellcheck disable=SC2018,SC2019
        _chain="$(echo "$_chain" | sed -e 's/^.*\.\([A-Z]*\)":.*$/\1/' | tr 'a-z' 'A-Z')"
        # shellcheck disable=SC2018,SC2019
        _action="$(echo "$_action" | cut -d '"' -f 2 | tr 'a-z' 'A-Z')"

        case "$_chain" in
            INPUT|OUTPUT|FORWARD)
                ;;
            *)
                _log "WARNING" "Policy Chain=/$_chain/ is invalid"
                return 1
                ;;
        esac

        case "$_action" in
            ACCEPT|DROP)
                ;;
            *)
                _log "WARNING" "Action=/$_action/ is invalid"
                return 1
                ;;
        esac

        _log "DEBUG" "Policy Chain=$_chain Action=$_action is valid"

        cmd=(nsenter -n -t "$_pid" iptables -P "$_chain" "$_action")

        if [[ "$DRY_RUN" -eq 1 ]]; then
            _log "DRY RUN MODE - Container=$object_id would run: ${cmd[*]}"
            return 0
        fi

        if ! "${cmd[@]}"; then
            _log "WARNING" "Container=$object_id PID=$(cat "$BASE_DIR/container_pid_$1") Policy Chain=$_chain Action=$_action failed"
            return 1
        fi

        _log "INFO" "Applied policy successfully chain=$_chain action=$_action"
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

    # shellcheck disable=SC2018,SC2019
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
    # shellcheck disable=SC2018,SC2019
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

    # shellcheck disable=SC2018,SC2019
    if ! _action=$(grep -P "firewall\.rules\.${3}\.[A-Z]+\.action" "$BASE_DIR/${1}_rules_${2}" 2>/dev/null | head -n1 | cut -d '"' -f 4 | tr 'a-z' 'A-Z'); then
        _log "WARNING" "$1 $2 rule $3 is invalid, ignoring rule"
        return 1
    fi

    if [[ ! "$_action" =~ ^(ACCEPT|DROP|REJECT|LOG)$ ]]; then
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
    # shellcheck disable=SC2018,SC2019
    _state=$(grep -P "firewall\.rules\.${3}\.[A-Z]+\.state" "$BASE_DIR/${1}_rules_${2}" 2>/dev/null | head -n1 | cut -d '"' -f 4 | tr 'a-z' 'A-Z')
    set -o pipefail

    if [[ ! "$_state" =~ ^(RELATED,ESTABLISHED|ESTABLISHED,RELATED|ESTABLISHED|RELATED|)$ ]]; then
        _log "WARNING" "$1 $2 rule $3 state=$_state is invalid, ignoring rule"
        return 1
    fi

    echo "$_state"
}


get_rule_log_prefix() {
    # $1: container|network
    # $2: object id
    # $3: chain id

    if [[ ! "$1" =~ ^(container|network)$ ]]; then
        _log "WARNING" "Call get_rule_log_prefix invalid type=$1, ignoring rule"
        return 1
    fi

    local _log_prefix

    if ! _log_prefix=$(grep -P "firewall\.rules\.${3}\.[A-Z]+\.log-prefix" "$BASE_DIR/${1}_rules_${2}" 2>/dev/null); then
        # no log prefix, it's fine
        true
    fi

    if [[ -n "$_log_prefix" ]]; then
        _log_prefix=$(echo "$_log_prefix" | head -n1 | cut -d '"' -f 4 | tr -dC 'a-zA-Z0-9_');
    fi

    echo "$_log_prefix"
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
    # $1: object id
    # $2: rule id

    _log "DEBUG" "process_container_rule_id $1 id=$2"

    local _chain
    local _cmd
    local _src
    local _dst
    local _protocol
    local _state
    local _action

    _chain=$(get_rule_chain         "container" "$1" "$2") || { _log "WARNING" "get_rule_chain failed"; return 1; }
    _cmd=(nsenter -n -t "$_pid" iptables -A "$_chain" -m comment --comment "$2")

    if [[ "$_chain" = "INPUT" ]]; then
        _src=$(get_rule_srcdst         "container" "$1" "$2" "src") || { _log "WARNING" "get_rule_srcdst src failed"; return 1; }
        if [[ -n "$_src" ]]; then
            _cmd+=(-s "$_src")
        fi

        _dst="0.0.0.0/0"
    fi

    if [[ "$_chain" = "OUTPUT" ]]; then
        _src="0.0.0.0/0"

        _dst=$(get_rule_srcdst         "container" "$1" "$2" "dst") || { _log "WARNING" "get_rule_srcdst dst failed"; return 1; }
        if [[ -n "$_dst" ]]; then
            _cmd+=(-d "$_dst")
        fi
    fi

    _protocol=$(get_rule_protocol   "container" "$1" "$2") || { _log "WARNING" "get_rule_protocol failed"; return 1; }
    if [[ -n "$_protocol" ]]; then
        _cmd+=(-p "$_protocol")
    fi

    if [[ -n "$_protocol" ]]; then
        local _sport
        local _dport

        _sport=$(get_rule_port         "container" "$1" "$2" "sport") || { _log "WARNING" "get_rule_port sport failed"; return 1; }
        if [[ -n "$_sport" ]]; then
            _cmd+=(--sport "$_sport")
        fi

        _dport=$(get_rule_port         "container" "$1" "$2" "dport") || { _log "WARNING" "get_rule_port dport failed"; return 1; }
        if [[ -n "$_dport" ]]; then
            _cmd+=(--dport "$_dport")
        fi
    fi

    _state=$(get_rule_state "container" "$1" "$2") || { _log "WARNING" "get_rule_state failed"; return 1; }

    if [[ -n "$_state" ]] ; then
        _cmd+=(-m state --state "$_state")
    fi

    _action=$(get_rule_action       "container" "$1" "$2") || { _log "WARNING" "get_rule_action failed"; return 1; }
    _cmd+=(-j "$_action")

    if [[ "$_action" = "LOG" ]]; then
        local _log_prefix
        _log_prefix=$(get_rule_log_prefix "container" "$1" "$2") || { _log "WARNING" "get_rule_log_prefix failed"; return 1; }
        if [[ -n "$_log_prefix" ]]; then
            _cmd+=(--log-prefix "$_log_prefix ")
        fi
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        _log "DRY RUN MODE - Container=$1 pid=$_pid would run: ${_cmd[*]}"
        return 0
    fi

    if ! "${_cmd[@]}"; then
        _log "WARNING" "Container=$1 PID=$(cat "$BASE_DIR/container_pid_$1") Policy Chain=$_chain Action=$_action failed"
        return 1
    fi

    _log "INFO" "Applied rule successfully: ${_cmd[*]}"
}


process_container_rules() {
    # $1: object id

    _log "DEBUG" "process_container_rules $1"

    local rule_id

    while read -r rule_id; do
        process_container_rule "$1" "$rule_id" || _log "ERROR" "Something went wrong"
    done < "$BASE_DIR/container_rule_ids_$1"
}


process_event_container() {
    _log "DEBUG" "New event $event_type action=$event_action object_id=$object_id"

    if [[ "$event_action" != "start" ]]; then
        _log "DEBUG" "Container $object_id unsupported action=${event_action}, return"
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

    cleanup_container           "$object_id"
}


process_event_network() {
    _log "DEBUG" "New event network   $event"
    return
}


process_event() {
    object_id="${object_id:0:12}"

    # just in case someone removed the directory
    mkdir -p "$BASE_DIR"

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

if [[ "${BASH_SOURCE[0]}" == "${0}" && "${1:-}" == "run" ]]; then
    _log "docker-firewall started, listening for events"

    _log "DEBUG" "debug log enabled"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        _log "INFO" "DRY RUN enabled"
    fi


    # Listen to Docker events
    docker events --filter type=container --filter type=network --filter event=start --filter event=create --filter event=destroy --filter label=firewall.enable=true | while read -r datetime event_type event_action object_id _rest; do
        process_event
        _log "DEBUG" "=========="
    done
fi
