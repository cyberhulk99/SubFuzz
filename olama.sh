#!/bin/bash
# SFUZZ - Ollama Auto-Installer (Fixed Version)
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
echo "           Ollama Auto-Installer v1.1"
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

# Check if Ollama is running
check_ollama_running() {
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        echo -e "${GREEN}[INFO]${NC} Ollama service is running"
        return 0
    else
        echo -e "${YELLOW}[WARNING]${NC} Ollama service is not running"
        return 1
    fi
}

# Start Ollama service
start_ollama_service() {
    echo -e "${CYAN}[SERVICE]${NC} Starting Ollama service..."
    
    # Try different methods to start Ollama
    if command -v brew &> /dev/null; then
        # macOS with Homebrew
        echo -e "${CYAN}[SERVICE]${NC} Starting via Homebrew services..."
        brew services start ollama
        sleep 5
    fi
    
    # Alternative method: direct start
    if ! check_ollama_running; then
        echo -e "${CYAN}[SERVICE]${NC} Starting Ollama directly..."
        nohup ollama serve > /tmp/ollama.log 2>&1 &
        sleep 8
    fi
    
    # Wait for service to be ready
    local max_attempts=10
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if check_ollama_running; then
            echo -e "${GREEN}[SUCCESS]${NC} Ollama service started successfully!"
            return 0
        fi
        echo -e "${YELLOW}[WAIT]${NC} Waiting for Ollama service to start... (attempt $attempt/$max_attempts)"
        sleep 3
        ((attempt++))
    done
    
    echo -e "${RED}[ERROR]${NC} Failed to start Ollama service after $max_attempts attempts"
    echo -e "${YELLOW}[TROUBLESHOOT]${NC} Try starting manually: ollama serve"
    return 1
}

# Check if Ollama is installed
check_ollama_installed() {
    if command -v ollama &> /dev/null; then
        echo -e "${GREEN}[INFO]${NC} Ollama is installed!"
        return 0
    else
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
        echo -e "${GREEN}[SUCCESS]${NC} Ollama is installed!"
        
        # Start service
        if start_ollama_service; then
            # Show installed models
            echo -e "${CYAN}[MODELS]${NC} Checking installed models..."
            ollama list
            return 0
        else
            echo -e "${YELLOW}[WARNING]${NC} Ollama installed but service not running"
            return 1
        fi
    else
        echo -e "${RED}[ERROR]${NC} Ollama installation verification failed!"
        return 1
    fi
}

# Main installation function
main() {
    # Check if already installed
    if check_ollama_installed; then
        echo -e "${GREEN}[INFO]${NC} Ollama is already installed!"
        
        # Start service and download models
        if start_ollama_service; then
            download_model
        else
            echo -e "${YELLOW}[WARNING]${NC} Could not start Ollama service. Models not downloaded."
        fi
        
        verify_installation
        return 0
    fi
    
    echo -e "${YELLOW}[INFO]${NC} Ollama not found. Please install manually from: https://ollama.ai"
    echo -e "${YELLOW}[INFO]${NC} After installation, run this script again to set up models."
    return 1
}

# Run main function
main "$@"
