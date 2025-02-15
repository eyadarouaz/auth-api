#!/bin/bash

# Update package list and install Python and virtual environment tools
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv

# Create a virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install FastAPI and other required packages
pip install fastapi uvicorn[standard] passlib[bcrypt] python-jose

# Echo Python and FastAPI versions
echo "Python version: $(python3 --version)"
echo "FastAPI version: $(pip show fastapi | grep Version)"

# Install required packages from requirements.txt if it exists
if [ -f requirements.txt ]; then
    pip install -r requirements.txt
else
    echo "No requirements.txt file found."
fi

# Check if FastAPI is installed
if pip show fastapi > /dev/null 2>&1; then
    echo "FastAPI is installed."
else
    echo "FastAPI is not installed."
    exit 1
fi

# Check if Uvicorn is installed
if pip show uvicorn > /dev/null 2>&1; then
    echo "Uvicorn is installed."
else
    echo "Uvicorn is not installed."
    exit 1
fi

# Print success message
echo "Setup completed successfully."
echo "To activate the virtual environment, run: source venv/bin/activate"