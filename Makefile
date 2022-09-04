fmt:
	cargo fmt

bloat:
	cargo bloat -n 50 --crates

udeps:
	cargo +nightly udeps

build:
	cargo build

build_x86_64-unknown-linux-musl:
	cross build \
		--release \
		--target x86_64-unknown-linux-musl

build_aarch64-unknown-linux-musl:
	cross build \
		--release \
		--target aarch64-unknown-linux-musl