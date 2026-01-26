set windows-shell := ["powershell.exe"]
export RUST_LOG := "info"
export RUST_BACKTRACE := "1"

@just:
    just --list

build:
    cargo build -r

check:
    cargo check --all --tests
    cargo fmt --all -- --check

fix:
    cargo clippy --all --tests --fix

format:
    cargo fmt --all

lint:
    cargo clippy --all --tests -- -D warnings

run:
    cargo run -r

run-elevated:
    Start-Process -Verb RunAs -FilePath "cargo" -ArgumentList "run", "-r"

test:
    cargo test --all -- --nocapture

@versions:
    rustc --version
    cargo fmt -- --version
    cargo clippy -- --version
