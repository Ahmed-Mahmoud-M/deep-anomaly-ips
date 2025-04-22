# Install venv 
sudo apt install python3-venv

# Create a virtual environment && Lists the venv in your home directory
python3 -m venv ~/my_venv

# Activate it
source ~/my_venv/bin/activate

# Now install
pip install -r requirements.txt
