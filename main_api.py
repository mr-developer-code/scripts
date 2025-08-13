from utils_node import run_command
import multiprocessing
import sys
import signal
import time

def cleanup(signum, frame):
    print("Shutting down cleanly...")
    sys.exit(0)

signal.signal(signal.SIGTERM, cleanup)
signal.signal(signal.SIGINT, cleanup)

commands = [
    "sudo python3 update_alert_benign_file_cont.py",
    "sudo python3 post_alert_data_snids_packet_api.py",
    "sudo python3 post_load_conn_api.py",
    "sudo python3 extract_feature_nprobe.py",
    "sudo python3 adnids.py",
    "sudo python3 post_data_adnids_packet_api.py"
]

for cmd in commands:
    p = multiprocessing.Process(target=run_command, args=(cmd,))
    p.start()
    time.sleep(10)

#---------------------------------------------------------------------------------------