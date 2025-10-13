#!/bin/bash
# SFUZZ - Ollama Auto-Installer
# Author: Suman Das
# License: MIT

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
echo " ███████╗███████╗██╗   ██╗███████╗███████╗"
echo " ██╔════╝██╔════╝██║   ██║╚══███╔╝╚══███╔╝"
echo " ███████╗█████╗  ██║   ██║  ███╔╝   ███╔╝ "
echo " ╚════██║██╔══╝  ██║   ██║ ███╔╝   ███╔╝  "
echo " ███████║███████╗╚██████╔╝███████╗███████╗"
echo " ╚══════╝╚══════╝ ╚═════╝ ╚══════╝╚══════╝"
echo -e "${NC}"
echo "           Ollama Auto-Installer v1.0"
echo "    ──────────────────────────────────────────────────────────"

# Function to run commands with error handling
run_command() {
    local cmd="$1"
    local description="$2"
    
    echo -e "${CYAN}[INFO]${NC} $description..."
    
    if eval "$cmd"; then
        echo -e "${GREEN}[SUCCESS]${NC} $description completed"
        return 0
    else
        echo -e "${RED}[ERROR]${NC} $description failed!"
        return 1
    fi
}

# Check if Ollama is already installed
check_ollama_installed() {
    if command -v ollama &> /dev/null; then
        echo -e "${GREEN}[INFO]${NC} Ollama is already installed!"
        return 0
    else
        return 1
    fi
}

# Install Ollama on Linux
install_linux() {
    echo -e "${CYAN}[INSTALL]${NC} Installing Ollama on Linux..."
    
    run_command "curl -fsSL https://ollama.ai/install.sh | sh" "Downloading and installing Ollama"
    
    # Start Ollama service
    if command -v systemctl &> /dev/null; then
        run_command "sudo systemctl enable ollama" "Enabling Ollama service"
        run_command "sudo systemctl start ollama" "Starting Ollama service"
    fi
}

# Install Ollama on macOS
install_macos() {
    echo -e "${CYAN}[INSTALL]${NC} Installing Ollama on macOS..."
    
    # Check if Homebrew is available
    if command -v brew &> /dev/null; then
        run_command "brew install ollama" "Installing Ollama via Homebrew"
    else
        run_command "curl -fsSL https://ollama.ai/install.sh | sh" "Downloading and installing Ollama"
    fi
}

# Install Ollama on Windows (WSL)
install_windows() {
    echo -e "${CYAN}[INSTALL]${NC} Installing Ollama on Windows (WSL)..."
    
    # Check if we're in WSL
    if grep -q Microsoft /proc/version &> /dev/null; then
        run_command "curl -fsSL https://ollama.ai/install.sh | sh" "Downloading and installing Ollama in WSL"
    else
        echo -e "${YELLOW}[INFO]${NC} Please download Ollama for Windows from: https://ollama.ai/download"
        echo -e "${YELLOW}[INFO]${NC} Run the installer manually and restart your terminal."
        return 1
    fi
}

# Download AI model
download_model() {
    echo -e "\n${CYAN}[MODEL]${NC} Downloading AI model..."
    
    local models=("llama2" "codellama")
    
    for model in "${models[@]}"; do
        echo -e "${CYAN}[MODEL]${NC} Downloading $model... (This may take several minutes)"
        if run_command "ollama pull $model" "Downloading $model"; then
            echo -e "${GREEN}[SUCCESS]${NC} Model $model downloaded successfully!"
            return 0
        fi
    done
    
    echo -e "${YELLOW}[WARNING]${NC} No models downloaded. You can manually run: ollama pull llama2"
    return 1
}

# Verify installation
verify_installation() {
    echo -e "\n${CYAN}[VERIFY]${NC} Verifying installation..."
    
    if check_ollama_installed; then
        echo -e "${GREEN}[SUCCESS]${NC} Ollama is installed and working!"
        
        # Show installed models
        echo -e "${CYAN}[MODELS]${NC} Checking installed models..."
        ollama list
        
        return 0
    else
        echo -e "${RED}[ERROR]${NC} Ollama installation verification failed!"
        return 1
    fi
}

# Main installation function
main() {
    # Check if already installed
    if check_ollama_installed; then
        download_model
        verify_installation
        return 0
    fi
    
    # Detect OS and install
    case "$(uname -s)" in
        Linux*)
            install_linux
            ;;
        Darwin*)
            install_macos
            ;;
        CYGWIN*|MINGW32*|MINGW64*|MSYS*)
            install_windows
            ;;
        *)
            echo -e "${RED}[ERROR]${NC} Unsupported operating system: $(uname -s)"
            echo -e "${YELLOW}[INFO]${NC} Please install Ollama manually from: https://ollama.ai"
            return 1
            ;;
    esac
    
    # Download model and verify if installation was successful
    if [ $? -eq 0 ]; then
        download_model
        verify_installation
        
        if [ $? -eq 0 ]; then
            echo -e "\n${GREEN}==================================================${NC}"
            echo -e "${GREEN}[COMPLETE]${NC} Ollama installation successful!"
            echo -e "${CYAN}[NEXT]${NC} Run SFUZZ with AI mode: python3 sfuzz.py -d example.com --ai-mode deep"
            echo -e "${GREEN}==================================================${NC}"
        else
            echo -e "${YELLOW}[WARNING]${NC} Installation may need a system restart."
        fi
    else
        echo -e "\n${RED}==================================================${NC}"
        echo -e "${RED}[FAILED]${NC} Ollama installation failed!"
        echo -e "${YELLOW}[TROUBLESHOOT]${NC} Please install manually from: https://ollama.ai"
        echo -e "${RED}==================================================${NC}"
        return 1
    fi
}

# Run main function
main "$@"
