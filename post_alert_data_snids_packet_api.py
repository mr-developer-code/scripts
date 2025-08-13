import requests
import time
from utils_node import *
from datetime import datetime

file_to_read = "/sgi/var/log/suricata/alert.json"
alert_data = []
last_postion_get = 0

def main():
    global last_postion_get

    try :
        with open(file_to_read, "r") as f:
            f.seek(last_postion_get)
            lines = f.readlines()
            last_postion_get = f.tell()

            for line in lines:
                try:
                    entry = json.loads(line)
                    if isinstance(entry, dict):
                        flow_byte = entry.get("flow",{})

                        ## time
                        alert_time = datetime.strptime(str(entry.get("timestamp")), "%Y-%m-%dT%H:%M:%S.%f%z").strftime("%H:%M:%S")
                        status = "dangerous" if entry.get("event_type") == "alert" else "safe"

                        alert = {
                            "time": alert_time,
                            "source": entry.get("src_ip","N/A"),
                            "destination": entry.get("dest_ip","N/A"),
                            "protocol": entry.get("proto", "N/A"),
                            "size": str(int(flow_byte.get("bytes_toserver",0)) + int(flow_byte.get("bytes_toclient",0))) + "B",
                            "status": status
                        }
                        alert_data.append(alert)
                    else:
                        continue
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        message = "Alert file not found"
    
    if len(alert_data) == 0:
        message = "No new alerts yet"
    
    with open("/sgi/sur_files/address.txt", "r") as f:
        address = f.readline()

    data  = {
        "alert_list" : alert_data,
        'message' : message,
        'address' : address
    }

    return data

while True:
    try:
        data = main()
        while True:
            response = requests.post("https://apipost.huzaifa.cloud/api/dashboard-packet-data", json=data)
            reply = response.json()
            if "received" in reply['message']:
                print("[snids] data send")
                break
            if "waiting" in reply['message']:
                print("[snids] waiting")
                break
            time.sleep(2)
    except Exception:
        continue
    time.sleep(3)

#---------------------------------------------------------------------------------------