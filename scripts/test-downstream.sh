#!/usr/bin/env bash
# Real downstream servers on Docker Engine (Linux) or a Docker VM (macOS).
set -euo pipefail
cd "$(dirname "$0")/.."

# A topology is data: an origin and an ordered list of proxy configurations.
# Validate selection before starting Docker or creating any resources.
registry=tests/downstream/topologies.tsv
if [ "$#" -eq 0 ]; then
  set -- $(awk '!/^#/ && NF { if (!seen[$1]++) print $1 }' "$registry")
fi
for deployment in "$@"; do
  if ! awk -v name="$deployment" '$1 == name { found=1 } END { exit !found }' "$registry"; then
    echo "Unknown deployment: $deployment (see $registry)" >&2
    exit 2
  fi
done

work=$(mktemp -d)
containers=()
container_logs=()
network=""
release_topology() {
  local i
  for ((i=${#containers[@]}-1; i>=0; i--)); do
    docker logs "${containers[$i]}" >"${container_logs[$i]}" 2>&1 || true
    docker rm -f "${containers[$i]}" >/dev/null || true
  done
  containers=()
  container_logs=()
  if [ -n "$network" ]; then docker network rm "$network" >/dev/null || true; fi
  network=""
}
cleanup() {
  status=$?
  release_topology
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

docker info >/dev/null
mkdir -p target/downstream
build_fixture() {
  local fixture=$1
  if [ ! -f "$work/$fixture-image" ]; then
    if ! docker build --progress=plain --iidfile "$work/$fixture-image" \
      "tests/downstream/$fixture" >"target/downstream/$fixture-build.log" 2>&1; then
      cat "target/downstream/$fixture-build.log" >&2
      return 1
    fi
  fi
  image=$(cat "$work/$fixture-image")
}
# Optional seeded composed-mutation search on top of the deterministic corpus.
# Pass a seed to reproduce a run, or "random" to draw a fresh one.
if [ "${ROUTE_GUARD_DOWNSTREAM_SEED:-}" = random ]; then
  ROUTE_GUARD_DOWNSTREAM_SEED=$(od -An -N8 -tu8 /dev/urandom | tr -d ' ')
fi
if [ -n "${ROUTE_GUARD_DOWNSTREAM_SEED:-}" ]; then
  export ROUTE_GUARD_DOWNSTREAM_SEED
  echo "seeded search: ROUTE_GUARD_DOWNSTREAM_SEED=$ROUTE_GUARD_DOWNSTREAM_SEED ROUTE_GUARD_DOWNSTREAM_BUDGET=${ROUTE_GUARD_DOWNSTREAM_BUDGET:-default}" \
    | tee target/downstream/search.txt
fi
# COPY keeps fixture filesystem semantics independent of the host OS.
for deployment in "$@"; do
  while read -r backend profile origin_backend origin_profile proxy_list; do
    [ "$backend" = "$deployment" ] || continue
    report_prefix="target/downstream/$backend-$profile"
    : >"$report_prefix.tsv"
    rm -f "$report_prefix-shrunk.tsv"
    # Save the complete wiring beside the observations for reproducibility.
    printf '%s %s %s %s %s\n' "$backend" "$profile" "$origin_backend" "$origin_profile" "$proxy_list" \
      >"$report_prefix-topology.txt"
    network_args=()
    publish_args=(--publish 127.0.0.1::8080)
    if [ "$proxy_list" != - ]; then
      network=$(docker network create "route-guard-$(basename "$work")")
      network_args=(--network "$network" --network-alias origin)
      publish_args=()
    fi
    build_fixture "$origin_backend"
    # The alternate-value expansion also supports empty arrays on macOS Bash 3.2.
    container=$(docker run --detach ${network_args[@]+"${network_args[@]}"} ${publish_args[@]+"${publish_args[@]}"} \
      --env "APACHE_ENCODED_SLASHES=$origin_profile" --env "ROUTING_PROFILE=$origin_profile" "$image")
    containers+=("$container")
    if [ "$proxy_list" = - ]; then
      container_logs+=("$report_prefix.log")
    else
      container_logs+=("$report_prefix-origin.log")
      IFS=, read -r -a proxies <<<"$proxy_list"
      upstream=origin
      # Start from the origin outward so every next hop exists before NGINX resolves it.
      for ((i=${#proxies[@]}-1; i>=0; i--)); do
        proxy=${proxies[$i]}
        proxy_args=(--env "UPSTREAM=$upstream")
        case "$proxy" in
          nginx-decoded) fixture=nginx; proxy_args+=(--env 'FORWARD_TARGET=$uri$is_args$args') ;;
          nginx-raw) fixture=nginx; proxy_args+=(--env 'FORWARD_TARGET=$request_uri') ;;
          apache-proxy) fixture=apache-proxy ;;
          *) echo "Unknown proxy configuration: $proxy" >&2; exit 2 ;;
        esac
        build_fixture "$fixture"
        publish_args=()
        if [ "$i" -eq 0 ]; then publish_args=(--publish 127.0.0.1::8080); fi
        container=$(docker run --detach --network "$network" --network-alias "hop-$i" \
          ${publish_args[@]+"${publish_args[@]}"} "${proxy_args[@]}" "$image")
        containers+=("$container")
        if [ "$i" -eq 0 ]; then
          container_logs+=("$report_prefix.log")
        else
          container_logs+=("$report_prefix-hop-$i-$proxy.log")
        fi
        upstream="hop-$i"
      done
    fi
    address=$(docker port "$container" 8080/tcp)
    echo "$backend/$profile ($address): $proxy_list -> $origin_backend/$origin_profile"
    ROUTE_GUARD_DOWNSTREAM_ADDR="$address" ROUTE_GUARD_DOWNSTREAM_BACKEND="$backend" \
      ROUTE_GUARD_DOWNSTREAM_PROFILE="$profile" ROUTE_GUARD_DOWNSTREAM_REPORT="$report_prefix.tsv" \
      ROUTE_GUARD_DOWNSTREAM_FAMILY_REPORT="$report_prefix-families.tsv" \
      ROUTE_GUARD_DOWNSTREAM_SHRINK_REPORT="$report_prefix-shrunk.tsv" \
      cargo test --locked --test downstream downstream_baseline -- --ignored --nocapture
    release_topology
  done <"$registry"
done
