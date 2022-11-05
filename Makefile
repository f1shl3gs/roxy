fmt:
	cargo fmt

check:
	cargo check

bloat:
	cargo bloat -n 50 --crates

udeps:
	cargo +nightly udeps

build:
	cargo build --release

x86_64-unknown-linux-musl:
	cross build \
		--release \
		--target x86_64-unknown-linux-musl

aarch64-unknown-linux-musl:
	cross build \
		--release \
		--target aarch64-unknown-linux-musl

roxy-cross/aarch64-unknown-linux-musl:
	cd cross && docker build -f aarch64-unknown-linux-musl.dockerfile -t roxy-cross:aarch64-unknown-linux-musl .

container_aarch64-unknown-linux-musl: aarch64-unknown-linux-musl
	# docker run --privileged --rm tonistiigi/binfmt --install all
	cp target/aarch64-unknown-linux-musl/release/roxy roxy
	docker build -t roxy:aarch64-unknown-linux-musl --platform linux/arm64 .
