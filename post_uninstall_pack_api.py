import requests
import time

with open('/sgi/sur_files/uninstall_package.txt', 'r') as f:
    lines = f.readlines()
    task = "no need"
    
    with open ("/sgi/sur_files/address.txt", "r") as f:
        address = f.readline()

    for line in lines:
        if "packages are not installed" in line:
            with open('/sgi/uninstall_package.txt', 'w') as f:
                f.write("clear")
            task = "install"
            break

data = {
    'lines':lines,
    'address':address,
    'task' :task
}

while True:
    try:
        response = requests.post("https://apipost.huzaifa.cloud/api/check-uninstalled-packages", json=data)
        reply = response.json()
        if "received" in reply['message']:
            print("[uninstall package] data send")
            break
    except Exception:
        continue
    time.sleep(3)

#---------------------------------------------------------------------------------------