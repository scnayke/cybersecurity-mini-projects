# 🔑 Keylogger (Educational)

This Python-based keylogger captures keystrokes using the `pynput` library and logs them to a file.

## Features

- Records all key presses
- Logs special keys like Shift, Enter
- Basic file-based logging


### How to Run

```bash
# Set up virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install evdev

# Run the keylogger (requires sudo)
sudo ./venv/bin/python keylogger_evdev.py
