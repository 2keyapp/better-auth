#!/usr/bin/env bash
set -euo pipefail

run() {
	echo ""
	echo "==> $1"
	shift
	"$@"
}

run "Typecheck" pnpm typecheck
run "Lint" pnpm lint
run "Format check" pnpm format:check
run "Spell check" pnpm lint:spell
run "Build" pnpm build
run "Lint types" pnpm lint:types
run "Typecheck dist" pnpm typecheck:dist
run "Lint packages" pnpm lint:packages
run "Lint dependencies" pnpm lint:dependencies

echo ""
echo "Pre-push CI checks passed."
