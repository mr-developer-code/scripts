from utils_node import *
import time

file_to_read = "/sgi/var/log/suricata/eve.json"
alert_file_to_write = "/sgi/var/log/suricata/alert.json"
benign_file_to_write = "/sgi/var/log/suricata/benign.json"

i = 0
while True:
    update_alert_list(file_to_read, alert_file_to_write)
    update_benign_list(file_to_read, benign_file_to_write)
    i=i+1
    print(f"[Update files] Updated {i} times")
    time.sleep(5)

#---------------------------------------------------------------------------------------