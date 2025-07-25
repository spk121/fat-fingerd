# Makefile for systemd-native fingerd

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99 -D_GNU_SOURCE
LDFLAGS = -lsystemd
TARGET = fingerd
SOURCE = fingerd.c

PREFIX = /usr
SBINDIR = $(PREFIX)/sbin
SYSTEMD_UNIT_DIR = /lib/systemd/system
SYSTEMD_SYSTEM_DIR = /etc/systemd/system

.PHONY: all clean install uninstall enable disable start stop status

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	# Install binary
	install -D -m 755 $(TARGET) $(DESTDIR)$(SBINDIR)/$(TARGET)
	# Install systemd units
	install -D -m 644 fingerd.service $(DESTDIR)$(SYSTEMD_UNIT_DIR)/fingerd.service
	install -D -m 644 fingerd.socket $(DESTDIR)$(SYSTEMD_UNIT_DIR)/fingerd.socket
	# Create man page directory (if you add man pages later)
	install -d $(DESTDIR)$(PREFIX)/share/man/man8

uninstall:
	# Stop and disable services first
	-systemctl stop fingerd.service fingerd.socket 2>/dev/null
	-systemctl disable fingerd.service fingerd.socket 2>/dev/null
	# Remove files
	rm -f $(DESTDIR)$(SBINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/fingerd.service
	rm -f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/fingerd.socket
	# Reload systemd
	systemctl daemon-reload 2>/dev/null || true

# Systemd management targets
enable: install
	systemctl daemon-reload
	systemctl enable fingerd.socket
	@echo "fingerd socket enabled. Start with: make start"

disable:
	systemctl disable fingerd.service fingerd.socket
	systemctl daemon-reload

start:
	systemctl start fingerd.socket
	@echo "fingerd socket started"

stop:
	systemctl stop fingerd.service fingerd.socket
	@echo "fingerd stopped"

restart:
	systemctl restart fingerd.service fingerd.socket
	@echo "fingerd restarted"

status:
	systemctl status fingerd.service fingerd.socket

# Development and testing targets
test-build: $(TARGET)
	@echo "Build successful"

check-deps:
	@echo "Checking dependencies..."
	@pkg-config --exists libsystemd || (echo "ERROR: libsystemd development package not found" && exit 1)
	@echo "Dependencies OK"

# Create a simple test to verify the daemon works
test-daemon: start
	@echo "Testing daemon..."
	@sleep 2
	@echo "" | nc localhost 79 | head -5 || echo "Test failed - daemon may not be responding"

# Development mode - run without systemd
dev-run: $(TARGET)
	@echo "Running in development mode (not as systemd service)..."
	sudo ./$(TARGET)

# Install development/debug version with extra logging
install-debug: CFLAGS += -DDEBUG -g
install-debug: install

# Package building (example for .deb)
package-prep:
	mkdir -p debian/fingerd$(SBINDIR)
	mkdir -p debian/fingerd$(SYSTEMD_UNIT_DIR)
	cp $(TARGET) debian/fingerd$(SBINDIR)/
	cp fingerd.service fingerd.socket debian/fingerd$(SYSTEMD_UNIT_DIR)/

# Installation Instructions (run 'make help' to see this)
help:
	@echo "systemd-native fingerd Makefile"
	@echo ""
	@echo "Build targets:"
	@echo "  all          - Build the fingerd binary"
	@echo "  clean        - Remove built files"
	@echo "  check-deps   - Verify required dependencies"
	@echo ""
	@echo "Installation targets:"
	@echo "  install      - Install binary and systemd units"
	@echo "  uninstall    - Remove all installed files"
	@echo "  enable       - Install and enable systemd units"
	@echo "  disable      - Disable systemd units"
	@echo ""
	@echo "Service management:"
	@echo "  start        - Start the fingerd socket"
	@echo "  stop         - Stop fingerd service and socket"
	@echo "  restart      - Restart fingerd"
	@echo "  status       - Show service status"
	@echo ""
	@echo "Development:"
	@echo "  dev-run      - Run daemon directly (not via systemd)"
	@echo "  test-daemon  - Basic functionality test"
	@echo "  install-debug- Install with debug symbols"
	@echo ""
	@echo "Installation steps:"
	@echo "  1. sudo make check-deps"
	@echo "  2. make all"
	@echo "  3. sudo make enable"
	@echo "  4. sudo make start"
	@echo "  5. make test-daemon"

# Installation verification
verify-install:
	@echo "Verifying installation..."
	@test -f $(SBINDIR)/$(TARGET) && echo "✓ Binary installed" || echo "✗ Binary missing"
	@test -f $(SYSTEMD_UNIT_DIR)/fingerd.service && echo "✓ Service unit installed" || echo "✗ Service unit missing"  
	@test -f $(SYSTEMD_UNIT_DIR)/fingerd.socket && echo "✓ Socket unit installed" || echo "✗ Socket unit missing"
	@systemctl is-enabled fingerd.socket >/dev/null 2>&1 && echo "✓ Socket enabled" || echo "✗ Socket not enabled"
	@systemctl is-active fingerd.socket >/dev/null 2>&1 && echo "✓ Socket active" || echo "✗ Socket not active"
