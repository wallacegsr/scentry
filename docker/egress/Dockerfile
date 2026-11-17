# The runner's only way out. Two small standard daemons:
#   dnsmasq answers every allowlisted name with this container's own address;
#   nginx reads the server name from the TLS hello (it never decrypts anything) and
#   passes the connection on only if that name is on the allowlist.
# Tools in the runner need no proxy settings, and nothing else is reachable: not other
# hosts, not other ports, not your LAN.
FROM debian:trixie-slim
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends dnsmasq-base nginx-light libnginx-mod-stream \
    && rm -rf /var/lib/apt/lists/*
COPY allowlist.txt /etc/egress/
COPY --chmod=0755 entrypoint.sh /entrypoint.sh
USER nobody
EXPOSE 53/udp 53/tcp 443
ENTRYPOINT ["/entrypoint.sh"]
