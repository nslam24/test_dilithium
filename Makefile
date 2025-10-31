PYTHON=/home/lamns/python/.venv/bin/python
MULTISIG=ky_doc_lap/multisig_demo.py
KEYGEN=dilithium_keygen.py
KEYS_DIR=keys

.PHONY: help run interactive gen-keys keystore-run show-bundle clean

help:
	@echo "Makefile targets for multisig demo"
	@echo "Variables you can override: LEVEL, SIG_TYPE, MODE, USERS, MESSAGE, SHUFFLE, USE_KEYSTORE, KEYS_DIR"
	@echo "Default invocation example: make run"
	@echo "Examples:"
	@echo "  make run LEVEL=Dilithium3 SIG_TYPE=dilithium MODE=both USERS=user1,user2 MESSAGE='Hello'"
	@echo "  make run SIG_TYPE=rsa LEVEL=RSA-2048"
	@echo "  make interactive  # run interactive menu"

# Run multisig non-interactively with selected variables
run:
	# Run interactive helper which will respect variables passed via make (exported below)
	PYTHON=$(PYTHON) SIG_TYPE="$(SIG_TYPE)" LEVEL="$(LEVEL)" MODE="$(MODE)" USERS="$(USERS)" MESSAGE="$(MESSAGE)" \
	SHUFFLE="$(SHUFFLE)" USE_KEYSTORE="$(USE_KEYSTORE)" KEYS_DIR="$(KEYS_DIR)" \
		bash scripts/run_multisig.sh

interactive:
	$(PYTHON) $(MULTISIG) --interactive --keys-dir $(KEYS_DIR)

gen-keys:
	# Generate default keys (user1..user5, Dilithium levels) and write keystore.json
	$(PYTHON) $(KEYGEN) --save-keys --outdir $(KEYS_DIR)

keystore-run:
	# Run multisig using keystore aliases; specify USERS as alias list or user names
	$(PYTHON) $(MULTISIG) --use-keystore --sig-type $(SIG_TYPE) --level "$(LEVEL)" --mode $(MODE) --users "$(USERS)" --message "$(MESSAGE)" --keys-dir $(KEYS_DIR) \
		$(if $(SHUFFLE),--shuffle)

show-bundle:
	@echo "Signature bundle files in current dir:"
	@ls -1 multisig_*.json 2>/dev/null || echo "(no bundles yet)"

clean:
	@rm -f multisig_*.json
	@echo "Removed multisig bundles"
