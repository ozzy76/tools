#!/bin/zsh # Explicit Zsh shebang

# Install Homebrew
echo "Installing Homebrew..."
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Check if Homebrew installed successfully
if ! command -v brew &>/dev/null; then
  echo "Error: Homebrew installation failed."
  exit 1
fi

# Add Homebrew to PATH (using Zsh's preferred method)
if [[ ! "$PATH" == *"/opt/homebrew/bin"* ]]; then
  echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
  source ~/.zprofile # Source the file immediately
fi

# Install Python 3.9 (or latest if you prefer)
echo "Installing Python 3.9..."

if ! command -v python3.9 &>/dev/null; then
    brew install python@3.9
else
    echo "Python 3.9 already installed."
fi

# Set python3.9 as default python3
if ! command -v python3 &>/dev/null || [[ "$(python3 --version 2>&1 | awk '{print $2}')" != "3.9"* ]]; then
  echo "Setting python3.9 as default python3..."
  brew unlink python
  brew link --overwrite python@3.9
fi

# Install pip if it's not present
if ! command -v pip3 &>/dev/null; then
    echo "Installing pip..."
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
    python3 get-pip.py
    rm get-pip.py
fi

# Upgrade pip (Best Practice)
echo "Upgrading pip..."
python3 -m pip install --upgrade pip

# Install required Python packages
echo "Installing required Python packages..."
python3 -m pip install requests beautifulsoup4 urllib3 colorama certifi

# Install ScoutSuite
echo "Installing ScoutSuite..."
if [ ! -d "ScoutSuite" ]; then
  git clone https://github.com/nccgroup/ScoutSuite.git
fi

cd ScoutSuite

echo "Installing ScoutSuite in editable mode..."
python3 -m pip install -e .

echo "ScoutSuite installation complete!"
echo "You can now run ScoutSuite by navigating to the ScoutSuite directory and using 'python3 scout.py'"
exit 0