import requests
import time

while True:
    try:
        with open ("/sgi/sur_files/progress.txt", "r") as f:
                line = f.readline()
    except:
        line =  0 

    with open("/sgi/sur_files/address.txt", "r") as f:
         address = f.readline()

    data = {
        'line':line,
        'address': address
    }

    while True:
        try:
            response = requests.post("https://apipost.huzaifa.cloud/api/progress", json=data)
            reply = response.json()
            if "received" in reply['message']:
                print("[progress] data send")
                break
        except Exception:
            continue           
    time.sleep(3)

#---------------------------------------------------------------------------------------
