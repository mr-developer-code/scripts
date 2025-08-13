import requests
import time
from datetime import datetime
from utils_node import *
import psutil

total_bytes = 0
now =  datetime.now().astimezone()
flow_count = 0
network_load = []
network_load_data = []
loadconn_data = []
connection_list = []
connection_data = []

def main():
    global network_load, network_load_data, loadconn_data, connection_list, connection_data

    ## netwrok laod
    bandwidth = run_command_simple("lshw -class network | grep -i capacity | awk '{print $2}'")

    if "Gb" in bandwidth:
        max_bandwidth = int(bandwidth.split("G")[0]) * 1000000000
    elif "Mb" in bandwidth:
        max_bandwidth = int(bandwidth.split("M")[0]) * 1000000
    elif "Kb" in bandwidth:
        max_bandwidth = int(bandwidth.split("M")[0]) * 1000
    else:
        max_bandwidth = int(bandwidth.split("M")[0])

    old = psutil.net_io_counters()
    time.sleep(60)
    new = psutil.net_io_counters()

    total_bytes = (new.bytes_sent - old.bytes_sent) + (new.bytes_recv - old.bytes_recv)

    total_bits = total_bytes * 8
    max_bits_in_interval = max_bandwidth * 60  
    load_percent = (total_bits / max_bits_in_interval) * 100
    load_percent = min(load_percent, 100.0)

    network_load.append(load_percent)
    if len(network_load)+1 > 240:
        avg = round(sum(network_load)/len(network_load),2)
        network_load_data.append(avg)
        network_load = []

    if len(network_load_data)+1 > 8:
        network_load_data.pop(0)

    ## connection rate
    cur_conn = psutil.net_connections(kind='all')
    # conn_list = [conn for conn in cur_conn if conn.status != "NONE"]
    # connections = len(conn_list)
    connections = len(cur_conn)

    connection_list.append(connections)
    if len(connection_list)+1 > 240:
        total = sum(connection_list)
        connection_data.append(total)
        connection_list = []

    if len(connection_data)+1 > 8:
        connection_data.pop(0)

    with open("/sgi/sur_files/address.txt", "r") as f:
        address = f.readline()

    data = {
        "network_load": f"{load_percent:.2f}%",
        "network_traffic_data": network_load_data,
        "connections" : connections,
        "connections_data" : connection_data,
        'address' : address
    }

    return data

while True:
    try:
        data = main()
        while True:
            response = requests.post("https://apipost.huzaifa.cloud/api/dashboard-loadconn-data", json=data)
            reply = response.json()
            if "received" in reply['message']:
                print("[load-conn] data sent")
                break
            time.sleep(2)
    except Exception:
        continue
    time.sleep(3)

#---------------------------------------------------------------------------------------