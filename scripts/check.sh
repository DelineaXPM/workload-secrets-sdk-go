#!/usr/bin/env bash
# Checks the Workload Secrets Go SDK the same way everywhere: on a developer's machine, in the Azure DevOps pipelines,
# and in the public repository's GitHub workflow. If it passes on your machine, it passes in all three.
#
#   scripts/check.sh            run every check
#
# Every check runs even when an earlier one fails, so one run reports everything that is wrong. Each failure says how
# to fix it. Exit status: 0 when every check passes, 1 otherwise. Works with the bash 3.2 that ships with macOS.
set -uo pipefail

# Pinned so a result never changes without a change here. golang.org/x/vuln holds govulncheck.
GOVULNCHECK_VERSION="v1.9.0"

cd "$(dirname "$0")/.." || exit 1

# Every check runs on the minimum Go version go.mod declares, never a newer one that happens to be installed:
# govulncheck judges the standard library by the Go it runs under, so checking on a newer Go would hide a
# vulnerability that a user building on the minimum still has. Raise the go directive to each Go security release.
go_min=$(awk '/^go /{print $2}' go.mod)
case "$go_min" in
  *.*.*) ;;
  *) go_min="$go_min.0" ;;
esac
export GOTOOLCHAIN="go$go_min"

passed=()
failed=()
hints=()

# run <name> <how to fix> <command...>: runs one check, prints its output, and records the result.
run() {
  local name="$1" fix="$2"
  shift 2
  echo
  echo "==> $name"
  local start=$SECONDS
  if "$@"; then
    passed+=("$name ($((SECONDS - start))s)")
  else
    failed+=("$name")
    hints+=("$name: $fix")
    echo "FAILED: $name"
  fi
}

# gofmt -l lists files that are not formatted and exits 0 either way, so a non-empty list is the failure.
check_gofmt() {
  local files
  files=$(gofmt -l .)
  if [ -n "$files" ]; then
    echo "Not gofmt-formatted:"
    echo "$files" | sed 's/^/  /'
    return 1
  fi
}

echo "Workload Secrets Go SDK checks in $(pwd)"
echo "Minimum Go from go.mod: $go_min; checking with: $(go version)"

# check_toolchain fails if the Go actually running is not the go.mod minimum, for example when GOTOOLCHAIN is
# overridden by a parent shell setting "local" and an older or newer Go is installed.
check_toolchain() {
  local running
  running=$(go env GOVERSION)
  if [ "$running" != "go$go_min" ]; then
    echo "Running $running, but go.mod's minimum is go$go_min."
    return 1
  fi
}

run "Go is the go.mod minimum (go$go_min)" \
  "let Go fetch the toolchain (GOTOOLCHAIN must allow downloads), or install go$go_min." \
  check_toolchain
run "gofmt" \
  "run 'gofmt -w <file>' on each file listed, then commit the result." \
  check_gofmt
run "go.mod and go.sum are tidy" \
  "run 'go mod tidy' and commit go.mod and go.sum." \
  go mod tidy -diff
run "downloaded modules match go.sum" \
  "a module in the cache does not match go.sum; run 'go clean -modcache' and try again. If it persists, do not release." \
  go mod verify
run "go build" \
  "fix the compile errors above." \
  go build ./...
run "go vet" \
  "fix each problem go vet reports above." \
  go vet ./...
run "go test" \
  "fix the failing tests above; run 'go test -run <TestName> -v .' to see one in detail." \
  go test -count=1 ./...
run "govulncheck $GOVULNCHECK_VERSION" \
  "upgrade the module or Go version govulncheck names above (go get <module>@<fixed version>, or raise the go directive), then run this script again." \
  go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...

echo
echo "==> Summary"
for item in ${passed[@]+"${passed[@]}"}; do
  echo "  PASS  $item"
done
for item in ${failed[@]+"${failed[@]}"}; do
  echo "  FAIL  $item"
done

if [ ${#failed[@]} -gt 0 ]; then
  echo
  echo "How to fix:"
  for hint in "${hints[@]}"; do
    echo "  - $hint"
  done
  exit 1
fi
echo
echo "All checks passed."
