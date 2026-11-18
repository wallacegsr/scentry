# The runner's only way out. Two small standard daemons:
#   dnsmasq answers every allowlisted name with this container's own address;
#   nginx reads the server name from the TLS hello (it never decrypts anything) and
#   passes the connection on only if that name is on the allowlist.
# Tools in the runner need no proxy settings, and nothing else is reachable: not other
# hosts, not other ports, not your LAN.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends dnsmasq-base nginx-light libnginx-mod-stream \
    && rm -rf /var/lib/apt/lists/*
COPY allowlist.txt /etc/egress/
COPY --chmod=0755 entrypoint.sh healthcheck.sh /
USER nobody
EXPOSE 53/udp 53/tcp 443
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/healthcheck.sh"]
ENTRYPOINT ["/entrypoint.sh"]
