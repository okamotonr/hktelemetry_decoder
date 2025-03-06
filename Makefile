RS_BIN = rs_decoder
C_BIN  = c_decoder

.PHONY: all rust c clean

all: rust c

rust:
	cargo build --release
	cp target/release/$(RS_BIN) .

c:
	$(MAKE) -C c
	cp c/$(C_BIN) .


clean:
	@echo "Cleaning Rust project..."
	cargo clean
	@echo "Cleaning C project..."
	$(MAKE) -C c clean
	@echo "Removing binaries from repository root..."
	rm -f $(RS_BIN) $(C_BIN)
