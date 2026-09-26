#!/usr/bin/env bash
# Real downstream servers on Docker Engine (Linux) or a Docker VM (macOS).
set -euo pipefail
cd "$(dirname "$0")/.."

work=$(mktemp -d)
container=""
report_prefix=""
origin=""
network=""
cleanup() {
  status=$?
  if [ -n "$container" ]; then
    docker logs "$container" >"$report_prefix.log" 2>&1 || true
    if [ "$status" -ne 0 ]; then cat "$report_prefix.log" >&2; fi
    docker rm -f "$container" >/dev/null || true
  fi
  if [ -n "$origin" ]; then
    docker logs "$origin" >"$report_prefix-origin.log" 2>&1 || true
    docker rm -f "$origin" >/dev/null || true
  fi
  if [ -n "$network" ]; then docker network rm "$network" >/dev/null || true; fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

docker info >/dev/null
mkdir -p target/downstream
# COPY puts the fixtures on the container filesystem, including on macOS where
# a bind-mounted document root could otherwise inherit host filesystem semantics.
if [ "$#" -eq 0 ]; then set -- apache express axum sveltekit nginx-apache nginx-express tomcat-spring; fi
for backend in "$@"; do
  case "$backend" in
    apache) profiles=(Off On NoDecode) ;;
    tomcat-spring) profiles=(PathPattern) ;;
    express) profiles=(Default Sensitive Insensitive) ;;
    nginx-apache|nginx-express) profiles=(DecodedUri) ;;
    axum|sveltekit) profiles=(Sensitive) ;;
    *) echo "Unknown backend: $backend (choose apache, express, axum, sveltekit, nginx-apache, nginx-express, tomcat-spring)" >&2; exit 2 ;;
  esac
  fixture="$backend"
  if [ "$backend" = nginx-express ]; then fixture=nginx-apache; fi
  if ! docker build --progress=plain --iidfile "$work/$backend-image" \
    "tests/downstream/$fixture" >"target/downstream/$backend-build.log" 2>&1; then
    cat "target/downstream/$backend-build.log" >&2
    exit 1
  fi
  image=$(cat "$work/$backend-image")
  if [ "$backend" = apache ]; then docker run --rm "$image" httpd -v; fi

  for profile in "${profiles[@]}"; do
    report_prefix="target/downstream/$backend-$profile"
    : >"$report_prefix.tsv"
    network_args=(--env "ROUTING_PROFILE=$profile")
    if [[ "$backend" = nginx-* ]]; then
      origin_backend="${backend#nginx-}"
      docker build --progress=plain --iidfile "$work/origin-image" "tests/downstream/$origin_backend" \
        >"target/downstream/$backend-origin-build.log" 2>&1 || {
          cat "target/downstream/$backend-origin-build.log" >&2; exit 1;
        }
      network=$(docker network create "route-guard-$(basename "$work")")
      origin=$(docker run --detach --network "$network" --network-alias origin \
        --env APACHE_ENCODED_SLASHES=On --env ROUTING_PROFILE=Sensitive "$(cat "$work/origin-image")")
      network_args+=(--network "$network")
    fi
    container=$(docker run "${network_args[@]}" --detach --publish 127.0.0.1::8080 \
      --env "APACHE_ENCODED_SLASHES=$profile" "$image")
    address=$(docker port "$container" 8080/tcp)
    echo "$backend/$profile ($address)"
    ROUTE_GUARD_DOWNSTREAM_ADDR="$address" ROUTE_GUARD_DOWNSTREAM_BACKEND="$backend" \
      ROUTE_GUARD_DOWNSTREAM_PROFILE="$profile" ROUTE_GUARD_DOWNSTREAM_REPORT="$report_prefix.tsv" \
      cargo test --locked --test downstream downstream_baseline -- --ignored --nocapture
    docker logs "$container" >"$report_prefix.log" 2>&1
    docker rm -f "$container" >/dev/null
    container=""
    if [ -n "$origin" ]; then
      docker logs "$origin" >"$report_prefix-origin.log" 2>&1
      docker rm -f "$origin" >/dev/null
      origin=""
      docker network rm "$network" >/dev/null
      network=""
    fi
  done
done
