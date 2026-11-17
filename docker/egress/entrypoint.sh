#!/bin/sh
# Builds the DNS answers and the nginx allowlist from allowlist.txt plus
# EXTRA_ALLOWED_DOMAINS, then runs both daemons. Everything it writes is under /tmp.
set -eu

# This container's fixed address on the network it shares with the runner (compose
# pins it). The runner uses it as its DNS server and every allowed name resolves to it.
self=${EGRESS_IP:?set EGRESS_IP}

{
  grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' /etc/egress/allowlist.txt
  printf '%s\n' "${EXTRA_ALLOWED_DOMAINS:-}" | tr ',' '\n'
} | tr -d ' \r' | grep -E '^\.?[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$' > /tmp/hosts

# DNS only routes (dnsmasq answers for a name and its subdomains); nginx decides.
# local= makes dnsmasq answer IPv6 lookups for these names with "no address" instead
# of refusing them: musl-based tools (uv) treat a refusal as a failed lookup.
sed -E "s|^\.?(.*)$|local=/\1/\naddress=/\1/${self}|" /tmp/hosts > /tmp/dnsmasq.conf
sed -E 's|^(.*)$|    "\1" $ssl_preread_server_name:443;|' /tmp/hosts > /tmp/allowed.map

cat > /tmp/nginx.conf <<CONF
load_module modules/ngx_stream_module.so;
worker_processes 1;
pid /tmp/nginx.pid;
error_log stderr warn;
events { worker_connections 512; }
stream {
  resolver 127.0.0.11 ipv6=off valid=60s;
  log_format egress '\$remote_addr \$ssl_preread_server_name -> \$upstream_addr \$status';
  access_log /dev/stdout egress;
  # "host" matches that host; ".domain" matches it and its subdomains.
  map \$ssl_preread_server_name \$target {
    hostnames;
    default 127.0.0.1:9;   # not on the list: nothing listens there
    include /tmp/allowed.map;
  }
  server {
    listen ${self}:443;
    ssl_preread on;
    proxy_connect_timeout 10s;
    proxy_timeout 600s;
    proxy_pass \$target;
  }
}
CONF

dnsmasq --keep-in-foreground --no-resolv --no-hosts --port=53 --listen-address="${self}" \
  --bind-interfaces --conf-file=/tmp/dnsmasq.conf --pid-file= --log-facility=- &
exec nginx -c /tmp/nginx.conf -g 'daemon off;'
