#!/usr/bin/env python3
# SFUZZ - Ollama Auto-Installer
# Author: Suman Das
# License: MIT

import os
import sys
import subprocess
import platform
from colorama import init, Fore, Style

init(autoreset=True)

def run_command(cmd, description):
    """Run a shell command and handle errors"""
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {description}...")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {description} completed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {description} failed: {e}")
        print(f"{Fore.YELLOW}[DEBUG]{Style.RESET_ALL} Error output: {e.stderr}")
        return False

def check_ollama_installed():
    """Check if Ollama is already installed"""
    try:
        result = subprocess.run(["ollama", "version"], capture_output=True, text=True)
        return result.returncode == 0
    except:
        return False

def install_ollama_linux():
    """Install Ollama on Linux"""
    print(f"{Fore.CYAN}[INSTALL]{Style.RESET_ALL} Installing Ollama on Linux...")
    
    commands = [
        ("curl -fsSL https://ollama.ai/install.sh | sh", "Downloading and installing Ollama"),
        ("sudo systemctl enable ollama", "Enabling Ollama service"),
        ("sudo systemctl start ollama", "Starting Ollama service")
    ]
    
    for cmd, desc in commands:
        if not run_command(cmd, desc):
            return False
    return True

def install_ollama_macos():
    """Install Ollama on macOS"""
    print(f"{Fore.CYAN}[INSTALL]{Style.RESET_ALL} Installing Ollama on macOS...")
    
    # Check if Homebrew is available
    try:
        subprocess.run(["brew", "--version"], check=True, capture_output=True)
        use_brew = True
    except:
        use_brew = False
    
    if use_brew:
        return run_command("brew install ollama", "Installing Ollama via Homebrew")
    else:
        return run_command("curl -fsSL https://ollama.ai/install.sh | sh", "Downloading and installing Ollama")

def install_ollama_windows():
    """Install Ollama on Windows"""
    print(f"{Fore.CYAN}[INSTALL]{Style.RESET_ALL} Installing Ollama on Windows...")
    
    # Method 1: Using winget (Windows 10/11)
    try:
        result = subprocess.run(["winget", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            return run_command("winget install Ollama.Ollama", "Installing Ollama via winget")
    except:
        pass
    
    # Method 2: Download installer
    print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Please download Ollama from: https://ollama.ai/download")
    print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Run the installer manually and restart your terminal.")
    return False

def download_ai_model():
    """Download a recommended AI model"""
    print(f"\n{Fore.CYAN}[MODEL]{Style.RESET_ALL} Downloading AI model...")
    
    models = [
        "llama2",        # Good balance of size and capability
        "codellama"      # Better for code/security analysis
    ]
    
    for model in models:
        print(f"{Fore.CYAN}[MODEL]{Style.RESET_ALL} Downloading {model}... (This may take several minutes)")
        if run_command(f"ollama pull {model}", f"Downloading {model}"):
            print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Model {model} downloaded successfully!")
            return True
    
    print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} No models downloaded. You can manually run: ollama pull llama2")
    return False

def verify_installation():
    """Verify Ollama installation"""
    print(f"\n{Fore.CYAN}[VERIFY]{Style.RESET_ALL} Verifying installation...")
    
    if check_ollama_installed():
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Ollama is installed and working!")
        
        # Check running models
        try:
            result = subprocess.run(["ollama", "list"], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"{Fore.CYAN}[MODELS]{Style.RESET_ALL} Installed models:")
                print(result.stdout)
        except:
            pass
            
        return True
    else:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Ollama installation verification failed!")
        return False

def main():
    """Main installation function"""
    print(f"""
{Fore.CYAN}
 ███████╗███████╗██╗   ██╗███████╗███████╗
 ██╔════╝██╔════╝██║   ██║╚══███╔╝╚══███╔╝
 ███████╗█████╗  ██║   ██║  ███╔╝   ███╔╝ 
 ╚════██║██╔══╝  ██║   ██║ ███╔╝   ███╔╝  
 ███████║███████╗╚██████╔╝███████╗███████╗
 ╚══════╝╚══════╝ ╚═════╝ ╚══════╝╚══════╝
{Style.RESET_ALL}
           Ollama Auto-Installer v1.0
    ──────────────────────────────────────────────────────────
    This script will install Ollama for enhanced AI capabilities
    in SFUZZ Security Scanning Platform.
    ──────────────────────────────────────────────────────────
    """)
    
    # Check if already installed
    if check_ollama_installed():
        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Ollama is already installed!")
        download_ai_model()
        verify_installation()
        return
    
    # Detect operating system
    system = platform.system().lower()
    print(f"{Fore.CYAN}[SYSTEM]{Style.RESET_ALL} Detected OS: {system}")
    
    # Install based on OS
    success = False
    if system == "linux":
        success = install_ollama_linux()
    elif system == "darwin":  # macOS
        success = install_ollama_macos()
    elif system == "windows":
        success = install_ollama_windows()
    else:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Unsupported operating system: {system}")
        return
    
    if success:
        # Download a model
        download_ai_model()
        
        # Verify installation
        if verify_installation():
            print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[COMPLETE]{Style.RESET_ALL} Ollama installation successful!")
            print(f"{Fore.CYAN}[NEXT]{Style.RESET_ALL} Run SFUZZ with AI mode: python3 sfuzz.py -d example.com --ai-mode deep")
            print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Installation may need a system restart.")
    else:
        print(f"\n{Fore.RED}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.RED}[FAILED]{Style.RESET_ALL} Ollama installation failed!")
        print(f"{Fore.YELLOW}[TROUBLESHOOT]{Style.RESET_ALL} Please install manually from: https://ollama.ai")
        print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
