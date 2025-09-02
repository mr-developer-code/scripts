import requests
import json
from datetime import datetime
import time

file_to_read = "/sgi/var/log/suricata/adnids_alert.json"

last_postion_get = 0

PROTO_MAP = {6: 'TCP', 17: 'UDP', 1: 'ICMP', 0: "N/A"}

def main():
    global last_postion_get
    message = ""
    alert_data = []

    try :
        with open(file_to_read, "r") as f:
            f.seek(last_postion_get)
            lines = f.readlines()
            last_postion_get = f.tell()

            for line in lines:
                try:
                    entry = json.loads(line)
                    if isinstance(entry, dict):

                        ## customized
                        alert_time = datetime.utcfromtimestamp(entry.get("FIRST_SWITCHED")).strftime("%H:%M:%S")
                        protocol = PROTO_MAP.get(entry.get("PROTOCOL", 0))
                        status = "safe" if entry.get("prediction") == "2" else "dangerous"

                        alert = {
                            "time": alert_time,
                            "source": entry.get("IPV4_SRC_ADDR","N/A"),
                            "destination": entry.get("IPV4_DST_ADDR","N/A"),
                            "protocol": protocol,
                            "size": str(int(entry.get("IN_BYTES",0)) + int(entry.get("OUT_BYTES",0))) + "B",
                            "status": status
                        }
                        alert_data.append(alert)

                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        message = "Alert file not found"

    if len(alert_data) == 0:
        message = "No new alert yet"

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
            response = requests.post("https://apipost.huzaifa.cloud/api/adnids-dashboard-packet-data", json=data)
            reply = response.json()
            if "received" in reply['message']:
                print("[adnids] data send")
                break
            if "waiting" in reply['message']:
                print("[adnids] waiting")
                break
            time.sleep(2)
    except Exception:
        continue
    time.sleep(3)

#---------------------------------------------------------------------------------------
