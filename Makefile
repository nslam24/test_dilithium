PYTHON=/home/lamns/python/.venv/bin/python
API_SERVER=simple_api.py
API_B64_SERVER=api_b64.py
API_PORT=9080
API_LOG=/tmp/simple_api.log
API_B64_LOG=/tmp/api_b64.log
PID_FILE=/tmp/simple_api.pid
PID_B64_FILE=/tmp/api_b64.pid
MULTISIG=ky_doc_lap/multisig_demo.py
KEYGEN=dilithium_keygen.py
KEYS_DIR=keys

.PHONY: help api-start api-stop api-restart api-status api-test api-logs api-b64-start api-b64-stop api-b64-restart api-b64-status api-b64-test run interactive gen-keys keystore-run show-bundle clean

help:
	@echo "================================================================================"
	@echo "🔐 THRESHOLD DILITHIUM - MAKEFILE COMMANDS"
	@echo "================================================================================"
	@echo ""
	@echo "📡 API Server Commands (JSON):"
	@echo "  make api-start     - Start API server (port $(API_PORT))"
	@echo "  make api-stop      - Stop API server"
	@echo "  make api-restart   - Restart API server"
	@echo "  make api-status    - Check if API server is running"
	@echo "  make api-test      - Run API test suite"
	@echo "  make api-logs      - Show API server logs"
	@echo ""
	@echo "📦 API Server Commands (Base64 - Recommended):"
	@echo "  make api-b64-start   - Start Base64 API server (port $(API_PORT))"
	@echo "  make api-b64-stop    - Stop Base64 API server"
	@echo "  make api-b64-restart - Restart Base64 API server"
	@echo "  make api-b64-status  - Check Base64 API server status"
	@echo "  make api-b64-test    - Run Base64 API test suite"
	@echo ""
	@echo "🔑 Key Generation & Multisig:"
	@echo "  make gen-keys      - Generate keys for user1..user5"
	@echo "  make run           - Run multisig demo"
	@echo "  make interactive   - Run interactive multisig menu"
	@echo ""
	@echo "🧹 Cleanup:"
	@echo "  make clean         - Remove signature bundles"
	@echo "  make clean-all     - Remove bundles + generated files"
	@echo ""
	@echo "💡 Examples:"
	@echo "  make api-b64-start             # Start Base64 API (recommended)"
	@echo "  make api-b64-test              # Test Base64 API"
	@echo "  make api-b64-stop              # Stop server"
	@echo ""

# =============================================================================
# API SERVER COMMANDS
# =============================================================================

api-start:
	@echo "🚀 Starting Threshold Dilithium API server..."
	@if [ -f $(PID_FILE) ] && kill -0 $$(cat $(PID_FILE)) 2>/dev/null; then \
		echo "⚠️  Server already running (PID: $$(cat $(PID_FILE)))"; \
		echo "   Use 'make api-restart' to restart"; \
		exit 1; \
	fi
	@$(PYTHON) $(API_SERVER) > $(API_LOG) 2>&1 & echo $$! > $(PID_FILE)
	@sleep 2
	@if kill -0 $$(cat $(PID_FILE)) 2>/dev/null; then \
		echo "✅ Server started successfully"; \
		echo "   PID: $$(cat $(PID_FILE))"; \
		echo "   URL: http://localhost:$(API_PORT)"; \
		echo "   Logs: $(API_LOG)"; \
		curl -s http://localhost:$(API_PORT)/api/health | head -1; \
	else \
		echo "❌ Server failed to start"; \
		echo "   Check logs: tail -f $(API_LOG)"; \
		rm -f $(PID_FILE); \
		exit 1; \
	fi

api-stop:
	@echo "🛑 Stopping API server..."
	@if [ ! -f $(PID_FILE) ]; then \
		echo "⚠️  PID file not found, trying pkill..."; \
		pkill -f "$(API_SERVER)" && echo "✅ Server stopped" || echo "ℹ️  No server process found"; \
	else \
		PID=$$(cat $(PID_FILE)); \
		if kill -0 $$PID 2>/dev/null; then \
			kill $$PID && echo "✅ Server stopped (PID: $$PID)"; \
			rm -f $(PID_FILE); \
		else \
			echo "⚠️  Server not running (stale PID file removed)"; \
			rm -f $(PID_FILE); \
		fi; \
	fi

api-restart:
	@echo "🔄 Restarting API server..."
	@$(MAKE) api-stop
	@sleep 1
	@$(MAKE) api-start

api-status:
	@echo "📊 API Server Status:"
	@echo "────────────────────────────────────────────────────────────────────────────────"
	@if [ -f $(PID_FILE) ] && kill -0 $$(cat $(PID_FILE)) 2>/dev/null; then \
		PID=$$(cat $(PID_FILE)); \
		echo "✅ Server is RUNNING"; \
		echo "   PID: $$PID"; \
		echo "   URL: http://localhost:$(API_PORT)"; \
		echo "   Logs: $(API_LOG)"; \
		echo ""; \
		echo "Health check:"; \
		curl -s http://localhost:$(API_PORT)/api/health 2>/dev/null || echo "   ⚠️  Server not responding"; \
	else \
		echo "❌ Server is NOT running"; \
		if [ -f $(PID_FILE) ]; then \
			echo "   (Stale PID file found - run 'make api-start')"; \
		fi; \
	fi
	@echo "────────────────────────────────────────────────────────────────────────────────"

api-test:
	@echo "🧪 Running API test suite..."
	@if ! curl -s http://localhost:$(API_PORT)/api/health > /dev/null 2>&1; then \
		echo "❌ Server not running!"; \
		echo "   Start with: make api-start"; \
		exit 1; \
	fi
	@bash test_simple_api.sh

api-logs:
	@echo "📋 API Server Logs (last 50 lines):"
	@echo "────────────────────────────────────────────────────────────────────────────────"
	@if [ -f $(API_LOG) ]; then \
		tail -50 $(API_LOG); \
	else \
		echo "ℹ️  No log file found at $(API_LOG)"; \
	fi
	@echo "────────────────────────────────────────────────────────────────────────────────"
	@echo "💡 Follow logs: tail -f $(API_LOG)"

api-logs-follow:
	@echo "📋 Following API Server Logs (Ctrl+C to stop)..."
	@tail -f $(API_LOG)

# =============================================================================
# API SERVER COMMANDS - BASE64 VERSION (RECOMMENDED)
# =============================================================================

api-b64-start:
	@echo "🚀 Starting Threshold Dilithium API server (Base64)..."
	@if [ -f $(PID_B64_FILE) ] && kill -0 $$(cat $(PID_B64_FILE)) 2>/dev/null; then \
		echo "⚠️  Base64 server already running (PID: $$(cat $(PID_B64_FILE)))"; \
		echo "   Use 'make api-b64-restart' to restart"; \
		exit 1; \
	fi
	@$(PYTHON) $(API_B64_SERVER) > $(API_B64_LOG) 2>&1 & echo $$! > $(PID_B64_FILE)
	@sleep 2
	@if kill -0 $$(cat $(PID_B64_FILE)) 2>/dev/null; then \
		echo "✅ Base64 server started successfully"; \
		echo "   PID: $$(cat $(PID_B64_FILE))"; \
		echo "   URL: http://localhost:$(API_PORT)"; \
		echo "   Logs: $(API_B64_LOG)"; \
		curl -s http://localhost:$(API_PORT)/api/health | head -1; \
	else \
		echo "❌ Server failed to start"; \
		echo "   Check logs: tail -f $(API_B64_LOG)"; \
		rm -f $(PID_B64_FILE); \
		exit 1; \
	fi

api-b64-stop:
	@echo "🛑 Stopping Base64 API server..."
	@if [ ! -f $(PID_B64_FILE) ]; then \
		echo "⚠️  PID file not found, trying pkill..."; \
		pkill -f "$(API_B64_SERVER)" && echo "✅ Server stopped" || echo "ℹ️  No server process found"; \
	else \
		PID=$$(cat $(PID_B64_FILE)); \
		if kill -0 $$PID 2>/dev/null; then \
			kill $$PID && echo "✅ Server stopped (PID: $$PID)"; \
			rm -f $(PID_B64_FILE); \
		else \
			echo "⚠️  Server not running (stale PID file removed)"; \
			rm -f $(PID_B64_FILE); \
		fi; \
	fi

api-b64-restart:
	@echo "🔄 Restarting Base64 API server..."
	@$(MAKE) api-b64-stop
	@sleep 1
	@$(MAKE) api-b64-start

api-b64-status:
	@echo "📊 Base64 API Server Status:"
	@echo "────────────────────────────────────────────────────────────────────────────────"
	@if [ -f $(PID_B64_FILE) ] && kill -0 $$(cat $(PID_B64_FILE)) 2>/dev/null; then \
		PID=$$(cat $(PID_B64_FILE)); \
		echo "✅ Server is RUNNING"; \
		echo "   PID: $$PID"; \
		echo "   URL: http://localhost:$(API_PORT)"; \
		echo "   Logs: $(API_B64_LOG)"; \
		echo ""; \
		echo "Health check:"; \
		curl -s http://localhost:$(API_PORT)/api/health 2>/dev/null || echo "   ⚠️  Server not responding"; \
	else \
		echo "❌ Server is NOT RUNNING"; \
		echo "   Start with: make api-b64-start"; \
	fi
	@echo "────────────────────────────────────────────────────────────────────────────────"

api-b64-test:
	@echo "🧪 Running Base64 API tests..."
	@echo "────────────────────────────────────────────────────────────────────────────────"
	@bash test_api_b64.sh

# =============================================================================
# MULTISIG & KEY GENERATION
# =============================================================================

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

# =============================================================================
# CLEANUP
# =============================================================================

clean:
	@rm -f multisig_*.json
	@rm -f keygen.json sign_request.json signature.json verify_request.json
	@echo "✅ Removed signature bundles and API test files"

clean-all: clean
	@rm -f $(API_LOG)
	@rm -f $(PID_FILE)
	@echo "✅ Removed all generated files"
