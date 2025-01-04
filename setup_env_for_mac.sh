#!/bin/bash

# Color code settings
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Starting ECN test environment setup...${NC}"

# Create Python virtual environment
echo -e "${GREEN}1. Creating Python virtual environment...${NC}"
python3 -m venv ecn_env

# Activate virtual environment
echo -e "${GREEN}2. Activating virtual environment...${NC}"
source ecn_env/bin/activate

# Install required packages
echo -e "${GREEN}3. Installing required packages...${NC}"
pip install scapy
pip install requests

# Install tcpdump (for Mac)
echo -e "${GREEN}4. Installing tcpdump...${NC}"
if ! command -v tcpdump &> /dev/null; then
    if command -v brew &> /dev/null; then
        brew install tcpdump
    else
        echo "Homebrew is not installed. Please install Homebrew first."
        echo "Homebrew installation command: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        exit 1
    fi
fi

# Set execution permissions
echo -e "${GREEN}5. Setting execution permissions for Python scripts...${NC}"
chmod +x ecn.py
chmod +x ecn_www.py

# Create results directory
echo -e "${GREEN}6. Creating directory for results...${NC}"
mkdir -p ecnserver

echo -e "${BLUE}Setup completed!${NC}"
echo -e "${BLUE}How to run the program:${NC}"
echo -e "1. Activate virtual environment: ${GREEN}source ecn_env/bin/activate${NC}"
echo -e "2. Run program: ${GREEN}sudo ./ecn.py example.com${NC} or ${GREEN}sudo ./ecn_www.py example.com${NC}" 