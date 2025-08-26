import subprocess
import json
import pexpect
import sys
import pandas as pd
import tenseal as ts
import re
import hashlib
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from keras.utils import to_categorical


## initialization
last_postion_update_alert = 0
last_postion_update_benign = 0
last_postion_extract_feature = 0
last_postion_get = 0
count = 0
package_list = ["libpcre3","libpcre3-dbg", "libpcre3-dev", "build-essential", "autoconf", "automake",
                "libtool", "libpcap-dev", "libnet1-dev", "libyaml-0-2", "libyaml-dev", "zlib1g", "zlib1g-dev",
                "libcap-ng-dev", "libcap-ng0", "make", "libmagic-dev", "libnuma-dev", 'python3-pip', "git",
                "flex", "bison", "linux-headers-$(uname -r)", "cmake", "gcc", "g++", "libssl-dev", "python3-dev", "swig",
                "tshark", "tcpdump", "liblz4-dev", "libpcre2-dev", "libjansson-dev", "libunwind-dev", "rustc", "cargo"]
uninstalled_packages = []
extracted_features = []
sid = 1000000

## Mapping from protocol number to name
protocol_map = {
    1: "icmp",
    6: "tcp",
    17: "udp",
}

## Mapping for L7_PROTO to application protocol
l7_proto_map = {
    80: "http",
    53: "dns",
    443: "tls",
    21: "ftp",
    502: "modbus",
    67: "dhcp",
    68: "dhcp",
    0: "arp",  # ARP uses protocol number 0 in some contexts
    110: "pop3",
    443: "quic",  # QUIC often uses UDP/443
}

## execute terminal command that need input
def run_command(command):
    with open("/sgi/sur_files/progress.txt", "r")as f:
        count = float(f.read().strip())

    print(f"[Running] \"{command}\"")

    full_command = f"bash -lc \"{command}\""
    print(full_command)
    child = pexpect.spawn(full_command, encoding="utf-8")
    child.logfile = sys.stdout  # Shows in terminal

    try:
        while True:
            i = child.expect([                   
                'Press.*Enter.*',                   # Press Enter
                '[Yy]/[Nn]',                        # y/n confirmation
                pexpect.EOF,
                pexpect.TIMEOUT                     # Timeout
            ], timeout=10)

            if i == 0:
                print("Pressing Enter")
                child.sendline('')
            elif i == 1:
                print("Sending 'y'")
                child.sendline('y')
            elif i == 2:
                print("Command finished.")
                break

        count = round(count + 1.01,1)
        
        with open("/sgi/sur_files/progress.txt", "w") as f:
            f.write(str(count))
    except Exception as e:
        print(f"Unexpected error: {e}")

    child.close()

## execute terminal command
def run_command_simple(command):
    with open("/sgi/sur_files/progress.txt", "r")as f:
        count = float(f.read().strip())
    try:
        print(f"[Running] \"{command}\"")
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        count = round(count + 1.01,1)
        
        with open("/sgi/sur_files/progress.txt", "w") as f:
            f.write(str(count))
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")

## save snids based alert data
def update_alert_list(file_read, file_write):
    global last_postion_update_alert
    with open(file_read,"r") as f:
        f.seek(last_postion_update_alert)
        lines = f.readlines()
        last_postion_update_alert = f.tell()

        for line in lines:
            try:
                entry = json.loads(line)
                if entry.get("event_type") == "alert":
                    with open(file_write, "a") as a:
                        a.write(json.dumps(entry) + "\n")
            
            except json.JSONDecodeError:
                continue

## save snids based benign data
def update_benign_list(file_read, file_write):
    global last_postion_update_benign
    with open(file_read,"r") as f:
        f.seek(last_postion_update_benign)
        lines = f.readlines()
        last_postion_update_benign = f.tell()

        for line in lines:
            try:
                entry = json.loads(line)
                if entry.get("event_type") != "alert":
                    with open(file_write, "a") as a:
                        a.write(json.dumps(entry) + "\n")
            
            except json.JSONDecodeError:
                continue

## save uninstall packages name
def check_packages():
    with open("sur_files/uninstall_package.txt", "w") as f:
        f.write("")
    for i in range(len(package_list)):
        res = run_command_simple(f'dpkg -l | grep "ii  {package_list[i]}"')
        if res:
            continue
        else:
            uninstalled_packages.append(package_list[i])
            with open("sur_files/uninstall_package.txt", "a") as f:
                f.write(package_list[i])

    if len(uninstalled_packages) > 0:
        with open("sur_files/uninstall_package.txt", "a") as f:
            f.write("the above packages are not installed.")
            sys.exit()

## regularized weights for aggregation
def apply_regularization(local_model, global_model, mu):
    print("[INFO] Applying Regularization!")

    for i, (lw, gw) in enumerate(zip(local_model.variables, global_model.variables)):
        updated_weight = (1 - mu) * lw + mu * gw
        local_model.variables[i].assign(updated_weight)
    
    return local_model

## scaled up the weights
def scaling_weight(weight, scalar):
    print("[INFO] scaling weight")

    weight_list=[]
    for i in range(len(weight)):
        # print(weight[i].scale())
        weight_list.append(scalar * weight[i])
    return weight_list

## encrypt thr model weights
def encrypt_parameter(model, context):
    print("[INFO] Encrypting!")
    encrypted_parameters = []
    parameters_shapes = []
    l = 0

    for layer in model.layers:
        if len(layer.get_weights()) > 0:
            weights = layer.get_weights()

            if len(weights) == 2:
                print(f"layer {l} have 2 parameters")
                w, b = weights
                print("[] Encrypting Start..!")
                w_e = ts.ckks_vector(context, w.flatten())
                b_e = ts.ckks_vector(context, b.flatten())
                print("[] Encrypting Done..!")
                encrypted_parameters.extend([w_e, b_e])
                parameters_shapes.extend([w.shape, b.shape])
                l = l+1

            elif len(weights) == 4:
                print(f"layer {l} have 4 parameters")
                g, b, mm, mv = weights
                print("[] Encrypting Start..!")
                g_e = ts.ckks_vector(context, g.flatten())
                b_e = ts.ckks_vector(context, b.flatten())
                mm_e = ts.ckks_vector(context, mm.flatten())
                mv_e = ts.ckks_vector(context, mv.flatten())
                print("[] Encrypting Done..!")
                encrypted_parameters.extend([g_e, b_e, mm_e, mv_e])
                parameters_shapes.extend([g.shape, b.shape, mm.shape, mv.shape])
                l = l+1
            else:
                print("layer have different parameters")
                print("[] Encrypting Start..!")
                we = ts.ckks_vector(context, weights.flatten())
                print("[] Encrypting Done..!")
                encrypted_parameters.extend([we])
                parameters_shapes.extend([weights.shape])

    return encrypted_parameters, parameters_shapes

## load extracted features
def extract_feature_from_log(file_path):
    global last_postion_extract_feature
    with open(file_path, 'r') as f:
        f.seek(last_postion_extract_feature)
        lines = f.readlines()
        last_postion_extract_feature = f.tell()

        if lines:
            for line in lines:
                try:
                    extracted_features.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue  # Ignore malformed JSON lines
    df = pd.DataFrame(extracted_features)
    return df

## convert TCP flags to Suricata flag string
def flags_to_string(flags):
    flag_map = {
        0x01: 'F',  # FIN
        0x02: 'S',  # SYN
        0x04: 'R',  # RST
        0x08: 'P',  # PSH
        0x10: 'A',  # ACK
        0x20: 'U',  # URG
        0x40: 'E',  # ECE
        0x80: 'C'   # CWR
    }
    result = ''
    for bit in sorted(flag_map.keys()):
        if flags & bit:
            result += flag_map[bit]
    return result if result else '0'

## Validate hostname
def is_valid_hostname(hostname):
    return bool(hostname and re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\.\-]*[a-zA-Z0-9]$', hostname))

## Validate MAC address
def is_valid_mac(mac):
    return bool(mac and re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac))

## generate suricata rules
def rule_generator(file_to_read, file_to_write):
    global sid
    with open(file_to_read, 'r') as f:
        lines = f.readlines()

    rules = []
    for line in lines:
        try: 
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue
        
        ## Extract header fields
        protocol_num = alert.get('PROTOCOL')
        protocol = protocol_map.get(protocol_num, "ip")
        src_ip = alert.get('IPV4_SRC_ADDR', 'any')
        src_port = str(alert.get('L4_SRC_PORT', 'any'))
        dst_ip = alert.get('IPV4_DST_ADDR', 'any')
        dst_port = str(alert.get('L4_DST_PORT', 'any'))

        ## Separate packet-layer and app-layer options
        packet_options = []
        app_options = []
        packet_msg = []
        app_msg = []

        ## Packet-layer options
        if protocol == "tcp":
            tcp_flags = alert.get('TCP_FLAGS', 0)
            flag_str = flags_to_string(tcp_flags)
            if flag_str:
                packet_options.append(f"tcp.flags:{flag_str};")

        ## TTL options
        min_ttl = alert.get('MIN_TTL')
        max_ttl = alert.get('MAX_TTL')
        if min_ttl is not None and max_ttl is not None:
            if min_ttl == max_ttl:
                packet_options.append(f"ttl:{min_ttl};")
            else:
                packet_options.append(f"ttl:>{min_ttl - 1};")
                packet_options.append(f"ttl:<{max_ttl + 1};")

        ## ICMP-specific options
        if protocol == "icmp":
            icmp_type = alert.get('ICMP_TYPE')
            if icmp_type is not None:
                packet_options.append(f"itype:{icmp_type};")

        ## Netflow-specific options
        in_bytes = alert.get('IN_BYTES')
        in_pkts = alert.get('IN_PKTS')
        out_bytes = alert.get('OUT_BYTES')
        out_pkts = alert.get('OUT_PKTS')
        if any([in_bytes, in_pkts, out_bytes, out_pkts]):
            msg_parts = []
            if in_bytes is not None:
                msg_parts.append(f"in_bytes {in_bytes}")
            if in_pkts is not None:
                msg_parts.append(f"in_packets {in_pkts}")
            if out_bytes is not None:
                msg_parts.append(f"out_bytes {out_bytes}")
            if out_pkts is not None:
                msg_parts.append(f"out_packets {out_pkts}")
            packet_msg.append(f'Intrusive packet with netflow {", ".join(msg_parts)}')

        ## Flow duration
        flow_duration = alert.get('FLOW_DURATION_MILLISECONDS')
        if flow_duration is not None:
            packet_msg.append(f'Flow duration {flow_duration} ms"')

        ## Application-layer options
        app_proto = alert.get('L7_PROTO')
        if not app_proto:
            app_proto = l7_proto_map.get(int(dst_port) if dst_port.isdigit() else 0, None)

        ## HTTP-specific options
        if app_proto == "http" or dst_port == "80":
            hostname = alert.get('hostname')
            httpstatus = alert.get('httpstatus')
            url = alert.get('url')
            http_content_type = alert.get('http_content_type')
            http_method = alert.get('http_method')
            http_protocol = alert.get('http_protocol')
            request_headers = alert.get('request_headers', [])
            response_headers = alert.get('response_headers', [])
            if hostname and is_valid_hostname(hostname):
                app_options.append(f"http.host; content:\"{hostname}\"; nocase;")
            if httpstatus is not None:
                app_options.append(f"http.stat_code; content:\"{httpstatus}\";")
            if url:
                app_options.append(f"http.uri; content:\"{url}\"; nocase;")
            if http_content_type:
                app_options.append(f"http.content_type; content:\"{http_content_type}\"; nocase;")
            if http_method:
                app_options.append(f"http.method; content:\"{http_method}\"; nocase;")
            if http_protocol:
                app_options.append(f"http.protocol; content:\"{http_protocol}\"; nocase;")
            for header in request_headers:
                app_options.append(f"http.request_header; content:\"{header}\"; nocase;")
            for header in response_headers:
                app_options.append(f"http.response_header; content:\"{header}\"; nocase;")
            if any([hostname, httpstatus, url, http_content_type, http_method, http_protocol, request_headers, response_headers]):
                app_msg.append(f'Intrusive HTTP packet')

        ## TLS-specific options
        if app_proto == "tls" or dst_port == "443":
            tls_sni = alert.get('tls_sni')
            tls_version = alert.get('tls_version')
            tls_ja3_hash = alert.get('tls_ja3_hash')
            tls_ja3_string = alert.get('tls_ja3_string')
            tls_ja3s_hash = alert.get('tls_ja3s_hash')
            tls_ja3s_string = alert.get('tls_ja3s_string')
            if tls_sni and is_valid_hostname(tls_sni):
                app_options.append(f"tls.sni; content:\"{tls_sni}\"; nocase;")
            if tls_version in ["TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3", "SSLv3"]:
                app_options.append(f"tls.version:{tls_version};")
            if tls_ja3_hash:
                app_options.append(f"ja3.hash; content:\"{tls_ja3_hash}\";")
            if tls_ja3_string:
                app_options.append(f"ja3.string; content:\"{tls_ja3_string}\";")
            if tls_ja3s_hash:
                app_options.append(f"ja3s.hash; content:\"{tls_ja3s_hash}\";")
            if tls_ja3s_string:
                app_options.append(f"ja3s.string; content:\"{tls_ja3s_string}\";")
            if any([tls_sni, tls_version, tls_ja3_hash, tls_ja3_string, tls_ja3s_hash, tls_ja3s_string]):
                app_msg.append(f'Intrusive TLS packet')

        ## FTP-specific options
        if app_proto == "ftp" or dst_port == "21":
            ftp_ret_code = alert.get('FTP_COMMAND_RET_CODE')
            if ftp_ret_code is not None:
                app_options.append(f"ftp.completion_code; content:\"{ftp_ret_code}\";")
                app_msg.append(f'Intrusive FTP packet with return code {ftp_ret_code}')

        ## File-specific options
        file_name = alert.get('file_name')
        file_size = alert.get('file_size')
        if file_name:
            app_options.append(f"file.name; content:\"{file_name}\"; nocase;")
        if file_size is not None:
            app_options.append(f"filesize:{file_size};")
        if file_name or file_size is not None:
            app_msg.append(f'Intrusive file transfer')

        ## QUIC-specific options
        if app_proto == "quic" or dst_port == "443":
            quic_version = alert.get('quic_version')
            quic_cyu_hash = alert.get('quic_cyu_hash')
            quic_cyu_string = alert.get('quic_cyu_string')
            if quic_version:
                app_options.append(f"quic.version:{quic_version};")
            if quic_cyu_hash:
                app_options.append(f"quic.cyu.hash; content:\"{quic_cyu_hash}\";")
            if quic_cyu_string:
                app_options.append(f"quic.cyu.string; content:\"{quic_cyu_string}\";")
            
        ## Generate separate rules
        ## Packet-layer rule
        if packet_options or packet_msg:
            rule = f"alert {protocol} {src_ip} {src_port} -> {dst_ip} {dst_port} ("
            rule += f'msg:"{", ".join(packet_msg) if packet_msg else "Intrusive packet"}";'
            rule += " ".join(packet_options) if packet_options else ""
            rule += f" sid:{sid}; rev:1;)"
            rules.append(rule)
            sid += 1

        ## Application-layer rule
        if app_options or app_msg:
            rule = f"alert {protocol} {src_ip} {src_port} -> {dst_ip} {dst_port} ("
            rule += f'msg:"{", ".join(app_msg) if app_msg else "Intrusive application packet"}";'
            rule += " ".join(app_options) if app_options else ""
            rule += f" sid:{sid}; rev:1;)"
            rules.append(rule)
            sid += 1

    ## rules to a file
    length_rules = len(rules)
    try:
        with open(file_to_write, 'w') as f:
            for rule in rules:
                f.write(rule + '\n')
        print(f"Generated {len(rules)} Suricata rules in {file_to_write}")
    except IOError:
        print(f"Error: Could not write to {file_to_write}")

    return length_rules

## calculate hash for model weights
def get_model_weights_hash(model, hash_alg="sha256"):
    hasher = hashlib.new(hash_alg)
    for w in model.get_weights():
        hasher.update(w.tobytes())
    return hasher.hexdigest()

## -----------------------------------debug----------------------------
def dataset_analysis(data):
    print("[INFO] columns")
    print("\t",data.shape)

    print("[INFO] Extraction")
    # data = data.drop(["Label","Dataset"], axis=1)
    data = data.drop(["Label"], axis=1)
    data = data.drop(["IPV4_SRC_ADDR","L4_SRC_PORT", "IPV4_DST_ADDR", "L4_DST_PORT"], axis=1)

    x = data.drop("Attack", axis = 1)
    y = data["Attack"]
    print("\t[] After Extraction", "\n\t", data.shape)

    print("[INFO] Normailzation")

    scaler = MinMaxScaler()
    x_scaled = scaler.fit_transform(x)

    label_scaler = LabelEncoder()
    y_encode = label_scaler.fit_transform(y)

    num_classes = len(label_scaler.classes_)
    print("\tclasses",num_classes)
    y_one_hot = to_categorical(y_encode, 21)

    print("\t[] After Normailzation")
    print("\tx: ",x_scaled.shape)
    print("\ty: ",y_one_hot.shape)

    return x_scaled, y_one_hot
