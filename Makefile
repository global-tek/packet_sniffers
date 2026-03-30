# Makefile for Network Packet Monitoring Toolkit

.PHONY: install test clean lint format setup demo help

# Default target
help:
	@echo "Network Packet Monitoring Toolkit - Makefile Commands"
	@echo "===================================================="
	@echo "setup          - Set up development environment"
	@echo "install        - Install dependencies"
	@echo "test           - Run test suite"
	@echo "lint           - Run code linting"
	@echo "format         - Format code with black"
	@echo "demo           - Run demo examples"
	@echo "clean          - Clean temporary files"
	@echo "capture        - Start packet capture (requires admin)"
	@echo "scan           - Run network scan"
	@echo "analyze        - Analyze sample data"
	@echo ""
	@echo "Examples:"
	@echo "  make setup     # Initial setup"
	@echo "  make demo      # Run demonstrations"
	@echo "  make capture   # Start packet capture"

# Setup development environment
setup:
	@echo "Setting up development environment..."
	python3 -m pip install --upgrade pip
	python3 -m pip install -r requirements.txt
	mkdir -p captures analysis visualizations exports logs
	@echo "Setup complete!"

# Install dependencies
install:
	@echo "Installing dependencies..."
	python3 -m pip install -r requirements.txt

# Run tests
test:
	@echo "Running test suite..."
	python3 tests/test_toolkit.py

# Run linting
lint:
	@echo "Running code linting..."
	flake8 src/ --max-line-length=100 --ignore=E203,W503
	@echo "Linting complete!"

# Format code
format:
	@echo "Formatting code with black..."
	black src/ examples/ tests/ --line-length=100
	@echo "Code formatting complete!"

# Clean temporary files
clean:
	@echo "Cleaning temporary files..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type f -name "*.log" -delete
	rm -rf .pytest_cache/
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	@echo "Cleanup complete!"

# Demo examples
demo:
	@echo "Running demonstration examples..."
	@echo "1. Basic configuration test..."
	python3 -c "from src.utils.common import ConfigManager; cm = ConfigManager(); print('Config loaded:', len(cm.load_config()) > 0)"
	@echo "2. Network utilities test..."
	python3 -c "from src.utils.common import NetworkUtils; print('Local IP:', NetworkUtils.get_local_ip())"
	@echo "3. Interface listing..."
	python3 -c "from src.capture.packet_sniffer import PacketSniffer; ps = PacketSniffer(); print('Interfaces:', ps.list_interfaces()[:3])"

# Packet capture (requires admin privileges)
capture:
	@echo "Starting packet capture (requires administrative privileges)..."
	sudo python3 main.py capture -c 50 -o captures/demo_capture.pcap

# Network scanning
scan:
	@echo "Running network scan..."
	python3 main.py scan 192.168.1.0/24 --ping-only

# Analyze sample data
analyze:
	@echo "Creating sample analysis..."
	python3 examples/ssl_analysis.py

# Install in development mode
dev-install:
	@echo "Installing in development mode..."
	python3 -m pip install -e .

# Create distribution package
dist:
	@echo "Creating distribution package..."
	python3 setup.py sdist bdist_wheel

# Check security vulnerabilities
security:
	@echo "Checking for security vulnerabilities..."
	python3 -m pip install safety
	safety check

# Generate documentation
docs:
	@echo "Generating documentation..."
	mkdir -p docs
	python3 -c "
import sys, os
sys.path.insert(0, 'src')
from src.capture.packet_sniffer import PacketSniffer
from src.analysis.protocol_analyzer import ProtocolAnalyzer
help(PacketSniffer)
help(ProtocolAnalyzer)
" > docs/api_reference.txt
	@echo "Documentation generated in docs/"
