#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ws="$(cd "$here/../.." && pwd)"
mine="$ws/miner/Cargo.toml"

run() { echo; echo "==> $*"; "$@"; }

run cargo test  --manifest-path "$ws/Cargo.toml" -p plaine-pow
run cargo test  --manifest-path "$ws/Cargo.toml" -p plaine-pow --release
run cargo clippy --manifest-path "$ws/Cargo.toml" -p plaine-pow --all-targets -- -D warnings

if [ -f "$mine" ]; then
    run cargo test  --manifest-path "$mine"
    run cargo test  --manifest-path "$mine" --release
    run cargo clippy --manifest-path "$mine" --all-targets -- -D warnings

    echo
    echo "==> the node's dependency graph must not contain plaine-pow-mine"
    if tree_out="$(cargo tree --manifest-path "$ws/Cargo.toml" -p plaine-noded 2>&1)"; then
        if printf '%s' "$tree_out" | grep -q 'plaine-pow-mine'; then
            echo "FAIL: plaine-pow-mine is in plaine-noded's dependency tree. The JIT has re-entered the node." >&2
            exit 1
        fi
        echo "ok"

        echo
        echo "==> the linked plaine-noded binary must carry no emitter symbols"
        exe="$ws/target/debug/plaine-noded.exe"
        [ -f "$exe" ] || exe="$ws/target/debug/plaine-noded"
        [ -f "$exe" ] || exe="$ws/target/release/plaine-noded.exe"
        if [ -f "$exe" ] && command -v nm >/dev/null 2>&1; then
            if nm -C "$exe" 2>/dev/null | grep -qE 'plaine_pow_mine|emit_x86_64|emit_aarch64|page::CodeW|page::CodeX'; then
                echo "FAIL: $exe carries an emitter symbol. The JIT has re-entered the node." >&2
                exit 1
            fi
            echo "ok"
        else
            echo "not checked: build the node first with cargo build -p plaine-noded and put nm on PATH. This is not a pass." >&2
        fi
    else
        echo "WARN: cargo tree -p plaine-noded failed, so this dependency check did not run. This is not a pass. Last lines:" >&2
        printf '%s\n' "$tree_out" | tail -3 >&2
    fi
else
    echo
    echo "NOTE: $mine is not present, so the miner half of the gate did not run."
fi

echo
echo "ALL POW CHECKS PASSED"
