NT61_DIR := nt61

.PHONY: build clean run

build:
	$(MAKE) -C $(NT61_DIR) build

clean:
	$(MAKE) -C $(NT61_DIR) clean

run:
	$(MAKE) -C $(NT61_DIR) run
