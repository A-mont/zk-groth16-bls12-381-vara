# Convenience targets. Rust builds run in WSL per project convention.
WSL = wsl -- bash -lc
# Derive the repo's WSL path from wherever this Makefile lives (no hardcoded paths).
# Override with `make ROOT=/mnt/c/...` if you run make from inside WSL already.
ROOT ?= $(shell wsl -- wslpath -a '$(CURDIR)')

.PHONY: build test circuit setup prove verify-app gtest deploy verify report frontend clean

## off-chain: build + unit/property tests for circuit, keys, prover, telemetry
build:
	$(WSL) 'source ~/.cargo/env; cd $(ROOT) && cargo build'

test:
	$(WSL) 'source ~/.cargo/env; cd $(ROOT) && cargo test'

## Step 1: synthesise the relation and report its R1CS dimensions (no setup/proof)
circuit:
	$(WSL) 'source ~/.cargo/env; cd $(ROOT) && cargo run -p zk-circuit -- stats'

## Step 2 + 3: generate artifacts (pk/vk/prepared vk, proof, public inputs)
setup:
	$(WSL) 'source ~/.cargo/env; cd $(ROOT) && cargo run -p zk-keys -- setup --seed 42 --out-dir artifacts'

prove:
	$(WSL) 'source ~/.cargo/env; cd $(ROOT) && cargo run -p zk-prover -- prove --secret 42 --seed 7'

## Step 4: build the on-chain program to Wasm + run gtest (uses the builtin mock)
verify-app:
	$(WSL) 'source ~/.cargo/env; cd $(ROOT)/crates/verifier-app && cargo build --release'

gtest:
	$(WSL) 'source ~/.cargo/env; cd $(ROOT)/crates/verifier-app && cargo test --release'

## On-chain: deploy + verify against Vara testnet (vara-wallet, agent account)
deploy:
	$(WSL) 'bash $(ROOT)/artifacts/deploy.sh'

verify:
	$(WSL) 'bash $(ROOT)/artifacts/verify.sh'

## Read the latest run log into a summary table
report:
	$(WSL) 'cd $(ROOT) && f=$$(ls -t runs/run-*.jsonl | head -1); echo "run: $$f"; \
	  jq -r "[.step, .status, (.duration_ms|tostring)+\"ms\", (.metrics|to_entries|map(.key+\"=\"+(.value|tostring))|join(\" \"))] | @tsv" $$f'

## Frontend
frontend:
	$(WSL) 'cd $(ROOT)/frontend && npm install && npm run dev'

clean:
	$(WSL) 'source ~/.cargo/env; cd $(ROOT) && cargo clean; cd crates/verifier-app && cargo clean'
