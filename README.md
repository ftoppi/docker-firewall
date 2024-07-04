# Docker Container Firewall Rules Automation Script

This script listens to Docker events and applies iptables firewall rules to Docker containers based on their labels. It is designed to be used with docker compose.

## Features

The script listens for container start events with a label "firewall.enable=true". All other events are ignored.

The script supports the following actions:
- ACCEPT (default)
- REJECT
- DROP
- LOG

⚠️ The first action of a rule is applied to the whole rule.

For the REJECT action, you can specify the type of ICMP packet to send. It supports the standard IPv4 types:
- icmp-net-unreachable
- icmp-host-unreachable
- icmp-port-unreachable
- icmp-proto-unreachable
- icmp-net-prohibited
- icmp-host-prohibited
- icmp-admin-prohibited (default)

The script supports the following chains:
- INPUT
- OUTPUT
- FORWARD

The script supports the following protocols:
- all
- icmp
- tcp
- udp

You can specify source and/or destination IP address or network.

For TCP and UDP, you can specify source and/or destination port (a single port per rule).

## Prerequisites

Before using this script, ensure that the following tools are installed on your system:

- jq: A lightweight and flexible command-line JSON processor.
- nsenter: A tool to run programs in the namespaces of other processes.

To enable logging inside namespaces, run the following command:

```
echo 1 > /proc/sys/net/netfilter/nf_log_all_netns
```

## Usage

1. Copy the script to `/usr/local/bin`.
1. Copy the systemd unit file to `/etc/systemd/system/docker-firewall.service`.
1. Reload systemd: `systemctl daemon-reload`
1. Start and enable the service `systemctl start docker-firewall.service && systemctl enable docker-firewall.service`.
1. Create a new container with labels (see below).

## Labels

Here are example labels:

```
      - firewall.enable=true
      - firewall.rules.1.OUTPUT.dst=172.217.16.196
      - firewall.rules.1.OUTPUT.protocol=tcp
      - firewall.rules.1.OUTPUT.dport=80
      - firewall.rules.1.OUTPUT.action=ACCEPT
      - firewall.rules.2.OUTPUT.dst=8.8.8.8
      - firewall.rules.2.OUTPUT.protocol=udp
      - firewall.rules.2.OUTPUT.dport=53
      - firewall.rules.2.OUTPUT.action=DROP
      - firewall.rules.abc.INPUT.src=9.0.0.0/24
      - firewall.rules.abc.INPUT.sport=53
      - firewall.rules.abc.INPUT.action=REJECT
      - firewall.rules.abc.INPUT.reject_with=icmp-port-unreachable
```

Rule IDs must be alphanumerical. Rules with non-alphanumerical IDs are silently ignored.

Any rule not following the syntax is skipped.
