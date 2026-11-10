#!/bin/bash
# Tests for docker-firewall.sh. No Docker needed: fake docker, nsenter and
# iptables are put on PATH, and the script runs in DRY_RUN mode, which prints
# the iptables commands it would run.
#
# Usage: tests/test-rules.sh [path/to/docker-firewall.sh]
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
script=${1:-$here/docker-firewall.sh}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir "$work/bin"
cat > "$work/bin/docker" <<'EOF'
#!/bin/bash
case "$1" in
    inspect)
        if [[ "$3" == *Pid* ]]; then
            [[ "$4" == gone* ]] && exit 1
            echo 4242
        else
            cat "$LABELS_FILE"
        fi
        ;;
    events) cat "$EVENTS_FILE" ;;
esac
EOF
chmod +x "$work/bin/docker"

# Dry run never calls these. If it ever does, fail loudly.
for tool in nsenter iptables; do
    cat > "$work/bin/$tool" <<EOF
#!/bin/bash
echo "unexpected $tool call: \$*" >&2
exit 1
EOF
    chmod +x "$work/bin/$tool"
done

# The script refuses to run as non-root; the test copy skips that check only.
sed 's/if \[\[ "$(id -u)" -ne 0 \]\]; then/if false; then/' "$script" > "$work/fw.sh"

# run LABELS_JSON CONTAINER_ID... : prints the iptables commands for those containers
run() {
    local labels=$1
    shift
    printf '%s' "$labels" > "$work/labels.json"
    : > "$work/events"
    for id in "$@"; do
        echo "2026-01-01T00:00:00+00:00 container start $id web" >> "$work/events"
    done
    LABELS_FILE="$work/labels.json" EVENTS_FILE="$work/events" \
        PATH="$work/bin:$PATH" DRY_RUN=1 bash "$work/fw.sh" run 2>&1 |
        sed -n 's/.*would run: //p'
}

fail=0
expect() {
    # $1: test name, $2: expected output, $3: actual output
    if [[ "$2" == "$3" ]]; then
        echo "ok    $1"
    else
        echo "FAIL  $1"
        diff <(echo "$2") <(echo "$3") | sed 's/^/      /' || true
        fail=1
    fi
}

expect "rule with dst, protocol, dport and action" \
    "nsenter -n -t 4242 iptables -A OUTPUT -m comment --comment 1 -d 8.8.8.8 -p udp --dport 53 -j DROP" \
    "$(run '{"firewall.enable":"true","firewall.rules.1.OUTPUT.dst":"8.8.8.8","firewall.rules.1.OUTPUT.protocol":"udp","firewall.rules.1.OUTPUT.dport":"53","firewall.rules.1.OUTPUT.action":"DROP"}' 1a)"

expect "protocols icmp and all accepted, tcpx rejected" \
    "nsenter -n -t 4242 iptables -A OUTPUT -m comment --comment 1 -d 1.1.1.1 -p icmp -j ACCEPT
nsenter -n -t 4242 iptables -A OUTPUT -m comment --comment 2 -d 2.2.2.2 -p all -j ACCEPT" \
    "$(run '{"firewall.enable":"true","firewall.rules.1.OUTPUT.dst":"1.1.1.1","firewall.rules.1.OUTPUT.protocol":"icmp","firewall.rules.1.OUTPUT.action":"ACCEPT","firewall.rules.2.OUTPUT.dst":"2.2.2.2","firewall.rules.2.OUTPUT.protocol":"all","firewall.rules.2.OUTPUT.action":"ACCEPT","firewall.rules.3.OUTPUT.dst":"3.3.3.3","firewall.rules.3.OUTPUT.protocol":"tcpx","firewall.rules.3.OUTPUT.action":"ACCEPT"}' 1a)"

expect "misspelled key skips the rule instead of widening it" \
    "" \
    "$(run '{"firewall.enable":"true","firewall.rules.4.OUTPUT.dst":"5.5.5.5","firewall.rules.4.OUTPUT.dprot":"tcp","firewall.rules.4.OUTPUT.dport":"22","firewall.rules.4.OUTPUT.action":"ACCEPT"}' 1a)"

expect "invalid policy action falls back to DROP" \
    "nsenter -n -t 4242 iptables -P INPUT DROP" \
    "$(run '{"firewall.enable":"true","firewall.policies.INPUT":"DROPP"}' 1a)"

expect "a container that vanishes does not stop the next one" \
    "nsenter -n -t 4242 iptables -A OUTPUT -m comment --comment 1 -d 8.8.8.8 -j ACCEPT" \
    "$(run '{"firewall.enable":"true","firewall.rules.1.OUTPUT.dst":"8.8.8.8","firewall.rules.1.OUTPUT.action":"ACCEPT"}' gone1 web2)"

exit "$fail"
