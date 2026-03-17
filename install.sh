#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
# DFTool Installer
# Installs the Digital Forensics Monitoring Daemon on Linux
# Must be run as root.
# ══════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

INSTALL_DIR="/opt/dftool"
CONFIG_DIR="/etc/dftool"
LOG_DIR="/var/log/dftool"
EVIDENCE_DIR="/var/lib/dftool/evidence"
PID_DIR="/var/run/dftool"
SYSTEMD_DIR="/etc/systemd/system"

banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║     DFTool — Digital Forensics Monitoring Daemon        ║"
    echo "║     Detect · Log · Alert — Never Prevent                ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

info()    { echo -e "${CYAN}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[  OK]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This installer must be run as root (sudo ./install.sh)"
    fi
}

check_python() {
    if command -v python3 &>/dev/null; then
        PY=$(command -v python3)
        PY_VER=$($PY --version 2>&1 | awk '{print $2}')
        info "Found Python: $PY ($PY_VER)"
    else
        error "Python 3.8+ is required but not found. Install it first."
    fi

    # Check version >= 3.8
    PY_MAJOR=$($PY -c "import sys; print(sys.version_info.major)")
    PY_MINOR=$($PY -c "import sys; print(sys.version_info.minor)")
    if [[ $PY_MAJOR -lt 3 ]] || [[ $PY_MINOR -lt 8 ]]; then
        error "Python 3.8+ required, found $PY_VER"
    fi
}

install_dependencies() {
    info "Installing Python dependencies …"
    $PY -m pip install --upgrade pip >/dev/null 2>&1 || true
    $PY -m pip install -r requirements.txt || error "Failed to install dependencies"
    success "Dependencies installed"
}

create_directories() {
    info "Creating directories …"
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$EVIDENCE_DIR"
    mkdir -p "$PID_DIR"

    # Restrict permissions on evidence & logs
    chmod 750 "$LOG_DIR"
    chmod 750 "$EVIDENCE_DIR"
    chmod 700 "$CONFIG_DIR"

    success "Directories created"
}

install_files() {
    info "Installing DFTool …"

    # Copy source
    cp -r src/dftool "$INSTALL_DIR/"

    # Install as Python package
    $PY -m pip install . || error "pip install failed"

    success "DFTool package installed"
}

install_config() {
    if [[ -f "$CONFIG_DIR/dftool.yaml" ]]; then
        warn "Config already exists at $CONFIG_DIR/dftool.yaml — keeping existing"
    else
        cp config/dftool.yaml "$CONFIG_DIR/dftool.yaml"
        chmod 600 "$CONFIG_DIR/dftool.yaml"
        success "Config installed to $CONFIG_DIR/dftool.yaml"
    fi
}

install_systemd() {
    info "Installing systemd service …"
    cp systemd/dftool.service "$SYSTEMD_DIR/dftool.service"
    systemctl daemon-reload
    systemctl enable dftool.service
    success "Systemd service installed and enabled"
}

print_summary() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN} Installation Complete!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Config:   ${CYAN}$CONFIG_DIR/dftool.yaml${NC}"
    echo -e "  Logs:     ${CYAN}$LOG_DIR/${NC}"
    echo -e "  Evidence: ${CYAN}$EVIDENCE_DIR/${NC}"
    echo -e "  Service:  ${CYAN}dftool.service${NC}"
    echo ""
    echo -e "  ${YELLOW}Quick Start:${NC}"
    echo -e "    sudo systemctl start dftool     # Start the daemon"
    echo -e "    sudo systemctl status dftool    # Check status"
    echo -e "    sudo dftool status              # CLI status"
    echo -e "    sudo dftool alerts --last 1h    # View recent alerts"
    echo -e "    sudo dftool timeline            # View event timeline"
    echo ""
    echo -e "  ${YELLOW}Run in foreground (debug):${NC}"
    echo -e "    sudo dftoold start --foreground"
    echo ""
    echo -e "  ${RED}Remember: DFTool DETECTS and LOGS only.${NC}"
    echo -e "  ${RED}It does NOT prevent or block any activity.${NC}"
    echo ""
}

# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────
banner
check_root
check_python
create_directories
install_dependencies
install_files
install_config
install_systemd
print_summary
