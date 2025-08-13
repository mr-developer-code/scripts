from utils_node import *
import shutil
from ruamel.yaml import YAML
import os
import re
import pwd

## initialization
yaml = YAML()
yaml.preserve_quotes = True
yaml.indent(mapping=2, sequence=4, offset=2)

## creating directries
os.makedirs("/sgi/etc/suricata", exist_ok=True)
os.makedirs("/sgi/log", exist_ok=True)
os.makedirs("/sgi/var/lib/suricata", exist_ok=True)
os.makedirs("/sgi/var/log/suricata", exist_ok=True)
os.makedirs("/sgi/var/lib/suricata/cache/sgh", exist_ok=True)
os.makedirs("/sgi/var/lib/suricata/rules", exist_ok=True)
os.makedirs("/sgi/var/run/suricata/", exist_ok=True)
os.makedirs("/usr/local/var/run/suricata/", exist_ok=True)
os.makedirs("/sgi/etc/share/file/magic", exist_ok=True)

## assigning rights
run_command("useradd --no-create-home --system --shell /sbin/nologin suricata")

run_command("sudo chown -R suricata:suricata /sgi/etc/suricata")
run_command("sudo chmod -R g+r /sgi/etc/suricata")

run_command("sudo chown -R suricata:suricata /sgi/var/log/suricata")
run_command("sudo chmod -R g+rw /sgi/var/log/suricata")

run_command("sudo chown -R suricata:suricata /sgi/var/lib/suricata")
run_command("sudo chmod -R g+srw /sgi/var/lib/suricata")

run_command("sudo chown -R suricata:suricata /sgi/var/run/suricata")
run_command("sudo chmod -R g+srw /sgi/var/run/suricata")

run_command("sudo chown -R suricata:suricata /sgi/log")
run_command("sudo chmod -R g+srw /sgi/log")

run_command("sudo chown -R suricata:suricata /sys/devices/system/node/")
run_command("sudo chmod -R u+rwX /sys/devices/system/node/")

# run_command("sudo chmod 755 /usr/local/var/run/suricata/")
# run_command("sudo chmod 777 /sgi/var/log/suricata")

## initialization
interface_name = (run_command_simple("ip route get 1 | awk '{print $5; exit}'")).strip()
inet_add = (run_command_simple(f"ip -4 addr show dev {interface_name.strip()} | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){{3}}+/\\d+'")).strip().split("\n")[0]
pci_add = (run_command_simple("sudo ethtool -i ens33 | grep bus-info")).split(":", 1)[1].strip()
host_os = (run_command_simple("cat /etc/os-release |grep -i ^name")).split("=",1)[1].lower()

if "ubuntu" in host_os:
    host_os = "linux"
landlocl_line = ' lsm=landlock"'
immou_line = ' intel_iommu=on"'
start_cmd = f"ExecStart=/sgi/bin/suricata -c /sgi/etc/suricata/suricata.yaml --pfring-int={interface_name}\n"

# os.chdir("/sgi")
# env = os.environ.copy()
# env = "/sgi"

def main_config():

    ## installation and configuration
    run_command("sudo apt-get update")
    run_command("sudo apt-get -y install libpcre3 libpcre3-dbg libpcre3-dev build-essential autoconf automake libtool libpcap-dev libnet1-dev libyaml-0-2 libyaml-dev zlib1g zlib1g-dev libcap-ng-dev libcap-ng0 make libmagic-dev libnuma-dev python3-pip git flex bison linux-headers-$(uname -r) cmake gcc g++ libssl-dev python3-dev swig tshark tcpdump")
    run_command("sudo apt install libnl-genl-3-dev")

    check_packages()
    run_command("sudo python3 scripts/post_uninstall_pack_api.py")

    os.chdir(f'/sgi/modules/nDPI')
    run_command("./autogen.sh")
    run_command("./configure")
    run_command("make && sudo make install")

    os.chdir(f'/sgi/modules/PF_RING/kernel')
    run_command("make && sudo make install")
    os.chdir(f'/sgi/modules/PF_RING/userland/lib')
    run_command("./configure && make && sudo make install")

    os.chdir(f'/sgi')
    run_command("sudo modprobe pf_ring")

    os.chdir(f'/sgi/modules/nprobe')
    run_command("sudo dpkg -i apt-ntop.deb")
    run_command("sudo apt install nprobe")

    run_command("cargo install --force cbindgen")
    run_command("echo \'export PATH=\"${PATH}:~/.cargo/bin\"\' >> ~/.bashrc")
    run_command("source ~/.bashrc")

    os.chdir(f'/sgi/modules/suricata-8.0.0')
    run_command("LIBS='-lrt -lnuma' ./configure --prefix=/sgi --enable-pfring --with-libpfring-includes=/usr/local/include --with-libpfring-libraries=/usr/local/lib")
    run_command("make -j $(nproc)")
    run_command("sudo make install")
    
    os.chdir(f'/sgi')
    
    ## landlock sandbox policy
    with open("/etc/default/grub", "r") as f:
        new_text= []
        lines = f.readlines()

        for line in lines:
            if "GRUB_CMDLINE_LINUX_DEFAULT" in line and "landlock" not in line:
                x = re.sub("\"$",landlocl_line, line)
                new_text.append(x)
            else:
                new_text.append(line)

    with open("/etc/default/grub", "w") as f:
        f.writelines(new_text)
    run_command("sudo update-grub")

    ## immou
    with open("/etc/default/grub", "r") as f:
        new_text=[]
        lines = f.readlines()

        for line in lines:
            if "GRUB_CMDLINE_LINUX_DEFAULT" in line and "intel_iommu" not in line:
                x = re.sub("\"$",immou_line, line)
                new_text.append(x)
            else:
                new_text.append(line)

    with open("/etc/default/grub", "w") as f:
        f.writelines(new_text)
    run_command("sudo update-grub")

    ## manipulation of suricata.yaml
    with open ("/sgi/sur_files/suricata.yaml", "r") as f:
        lines = yaml.load(f)

    lines["vars"]["address-groups"]["HOME_NET"] = f"[{inet_add}]"

    for item in lines.get("af-packet", []):
        if "interface" in item:
            item['interface'] = interface_name
            break

    for item in lines.get("pfring", []):
        if "interface" in item:
            item['interface'] = interface_name
            break
    
    if "dpdk" in lines and "interfaces" in lines["dpdk"]:
        for item in lines["dpdk"]["interfaces"]:
            if "interface" in item:
                item["interface"] = pci_add
                break
    
    if "host-os-policy" in lines and "linux" in host_os:
        lines["host-os-policy"]["linux"] = f"[{inet_add}]"

    cpu_affinity = lines.get("threading", {}).get("cpu-affinity", {})
    worker_cpu_set = cpu_affinity.get("worker-cpu-set", {})
    if "interface-specific-cpu-set" in worker_cpu_set:
        for iface in worker_cpu_set["interface-specific-cpu-set"]:
            iface["interface"] = interface_name

    http_config = (
    lines.get("app-layer", {})
          .get("protocols", {})
          .get("http", {})
          .get("libhtp", {})
    )
    if "server-config" in http_config:
        for server in http_config["server-config"]:
            for server_name, server_settings in server.items():
                server_settings["address"] = f"[{inet_add}]"

    with open ("/sgi/sur_files/suricata.yaml", "w") as f:
        yaml.dump(lines, f) 

    ## manipulating service file
    with open("/sgi/sur_files/suricata.service","r") as f:
        new_lines= []
        lines = f.readlines()   

        for line in lines:
            if "ExecStart" in line:
                new_lines.append(start_cmd)
            else:
                new_lines.append(line)

    with open("/sgi/sur_files/suricata-pfring.service","w") as f:
        f.writelines(new_lines)

    ## replace the config file
    shutil.copy("/sgi/sur_files/suricata.yaml", "/sgi/etc/suricata/suricata.yaml")
    shutil.copy("/sgi/sur_files/suricata-afpacket.service", "/etc/systemd/system/suricata-afpacket.service")
    shutil.copy("/sgi/sur_files/suricata-pfring.service", "/etc/systemd/system/suricata-pfring.service")
    shutil.copy("/sgi/sur_files/main-api.service", "/etc/systemd/system/main-api.service")
    shutil.copy("/sgi/sur_files/local.rules", "/sgi/var/lib/suricata/rules/local.rules")
    shutil.copy("/sgi/sur_files/classification.config", "/sgi/etc/suricata/classification.config")
    shutil.copy("/sgi/sur_files/reference.config", "/sgi/etc/suricata/reference.config")
    shutil.copy("/sgi/sur_files/threshold.config", "/sgi/etc/suricata/threshold.config")
    shutil.copy("/sgi/sur_files/main_api_service.log", "/sgi/log/main_api_service.log")

    print("[INFO] Files Uploaded")

    run_command(f"sudo ip link set {interface_name} promisc on")

    ## reloading serivce directory
    run_command("sudo /bin/systemctl --system daemon-reload")
    run_command("sudo /bin/systemctl --system daemon-reexec")

    ## start pfring
    run_command("sudo /bin/systemctl --system enable suricata-pfring")
    run_command("sudo /bin/systemctl --system start suricata-pfring")

    with open("/sgi/sur_files/progress.txt","w") as f:
        f.write(str(98.84))

    res_pfring_status = run_command_simple("sudo /bin/systemctl --system status suricata-pfring | grep -i active")

    ## start af-packet if pfring fails
    if "failed" in res_pfring_status:
        run_command("sudo /bin/systemctl --system stop suricata-pfring")
        run_command("sudo /bin/systemctl --system enable suricata-afpacket")

        with open("/sgi/sur_files/progress.txt","w") as f:
            f.write(str(98.84))

        run_command("sudo /bin/systemctl --system start suricata-afpacket")
        print("[INFO] AF-PACKET Configuration Completed!")
    else:
        print("[INFO] PFRING Configuration Completed!")
    
    ## runs all api's
    run_command("sudo /bin/systemctl --system enable main-api")
    run_command("sudo /bin/systemctl --system start main-api")

    with open("/sgi/sur_files/progress.txt","w") as f:
        f.write(str(100))

main_config()

#---------------------------------------------------------------------------------------
