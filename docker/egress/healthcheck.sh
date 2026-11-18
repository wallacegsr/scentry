#!/bin/sh
# Healthy while both daemons run. (A dead dnsmasq stays behind as a zombie, because
# nginx doesn't reap it: so look at the state, not just whether the pid exists.)
for name in dnsmasq nginx; do
  pid=$(cat "/tmp/${name}.pid" 2>/dev/null) || exit 1
  state=$(sed -n 's/^State:[[:space:]]*\(.\).*/\1/p' "/proc/${pid}/status" 2>/dev/null)
  case "${state}" in ""|Z|X) echo "${name} isn't running"; exit 1 ;; esac
done
