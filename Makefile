NT61_DIR := nt61

.PHONY: build clean run run-x86_64-net-bridge

build:
	$(MAKE) -C $(NT61_DIR) build

clean:
	$(MAKE) -C $(NT61_DIR) clean

run:
	$(MAKE) -C $(NT61_DIR) run

run-x86_64-net-bridge:
	$(MAKE) -C $(NT61_DIR) run-x86_64-net-bridge
