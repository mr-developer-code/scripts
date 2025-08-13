import json
import os
import subprocess
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime

temp = 0

## Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('watchdog').setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

## Define nProbe template
NPROBE_TEMPLATE = (
    "%IPV4_SRC_ADDR %IPV4_DST_ADDR "
    "%L4_SRC_PORT %L4_DST_PORT %PROTOCOL %L7_PROTO "
    "%IN_BYTES %OUT_BYTES %IN_PKTS %OUT_PKTS %FIRST_SWITCHED %LAST_SWITCHED "
    "%TCP_FLAGS %CLIENT_TCP_FLAGS %SERVER_TCP_FLAGS %DURATION_IN %DURATION_OUT "
    "%MIN_TTL %MAX_TTL %LONGEST_FLOW_PKT %SHORTEST_FLOW_PKT %MIN_IP_PKT_LEN "
    "%MAX_IP_PKT_LEN %SRC_TO_DST_SECOND_BYTES %DST_TO_SRC_SECOND_BYTES "
    "%RETRANSMITTED_IN_BYTES %RETRANSMITTED_IN_PKTS %RETRANSMITTED_OUT_BYTES "
    "%RETRANSMITTED_OUT_PKTS %SRC_TO_DST_AVG_THROUGHPUT %DST_TO_SRC_AVG_THROUGHPUT "
    "%NUM_PKTS_UP_TO_128_BYTES %NUM_PKTS_128_TO_256_BYTES %NUM_PKTS_256_TO_512_BYTES "
    "%NUM_PKTS_512_TO_1024_BYTES %NUM_PKTS_1024_TO_1514_BYTES %TCP_WIN_MAX_IN "
    "%TCP_WIN_MAX_OUT %ICMP_TYPE %DNS_QUERY_ID %DNS_QUERY_TYPE %DNS_TTL_ANSWER "
    "%FTP_RAW_CODE"
)

## Protocol mapping
PROTO_MAP = {'6': 'TCP', '17': 'UDP', '1': 'ICMP'}

class PcapHandler(FileSystemEventHandler):
    def __init__(self, output_dir, eve_file, feature_output):
        self.output_dir = output_dir
        self.eve_file = eve_file
        self.feature_output = feature_output

    def on_any_event(self, event):
        logger.debug(f"File system event: {event.event_type} at {event.src_path}")

    def on_created(self, event):
        self.process_event(event)

    def on_modified(self, event):
        self.process_event(event)

    def process_event(self, event):
        """Handle created or modified .pcap files."""
        if event.src_path.endswith('.pcap'):
            logger.info(f"Processing {event.event_type} .pcap file: {event.src_path}")
            self.process_pcap(event.src_path)

    def process_pcap(self, pcap_file):
        """Process a single .pcap file."""
        try:
            flow_count = estimate_flow_count(pcap_file)
            split_files = []
            if flow_count > 512 or flow_count == 0:
                logger.warning(f"Flow count {flow_count} exceeds safe limit or is unknown, splitting .pcap")
                split_files = split_pcap(pcap_file, self.output_dir)
            else:
                split_files = [pcap_file]
            for split_file in split_files:
                logger.info(f"Processing split file: {split_file}")
                run_nprobe(split_file, self.output_dir)
            benign_flows, protocol_features = parse_eve_json(self.eve_file)
            features = extract_features(self.output_dir, benign_flows, protocol_features)
            with open(self.feature_output, 'a') as f:
                for feature_set in features:
                    json.dump(feature_set, f)
                    f.write('\n')
            logger.info(f"Extracted {len(features)} feature sets to {self.feature_output}")
        except Exception as e:
            logger.error(f"Error processing {pcap_file}: {e}")

## Estimate the number of flows in a .pcap file using tshark.
def estimate_flow_count(pcap_file):
    try:
        cmd = [
            "tshark", "-r", pcap_file, "-T", "fields",
            "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport",
            "-e", "udp.srcport", "-e", "udp.dstport", "-e", "ip.proto"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        flows = set()
        for line in result.stdout.splitlines():
            fields = line.split('\t')
            if len(fields) >= 7:
                src_ip, dst_ip, tcp_sport, tcp_dport, udp_sport, udp_dport, proto = fields[:7]
                sport = tcp_sport or udp_sport
                dport = tcp_dport or udp_dport
                if src_ip and dst_ip and sport and dport and proto and ':' not in src_ip and ':' not in dst_ip:
                    flows.add((src_ip, dst_ip, sport, dport, proto))
        flow_count = len(flows)
        logger.info(f"Estimated flow count for {pcap_file}: {flow_count}")
        return flow_count
    except subprocess.SubprocessError as e:
        logger.error(f"Error estimating flow count for {pcap_file}: {e}")
        return 0

## Split a .pcap file into smaller chunks.
def split_pcap(pcap_file, output_dir):
    global temp
    try:
        prefix = os.path.join(output_dir, f"split_{os.path.basename(pcap_file).replace('.pcap', '')}_{temp}.pcap")
        temp += 1
        cmd = [
            "tcpdump", "-r", pcap_file, "-w", prefix, "-C", "5"
        ]
        subprocess.run(cmd, check=True)
        split_files = [
            os.path.join(output_dir, f) for f in os.listdir(output_dir)
            if f.startswith(f"split_{os.path.basename(pcap_file).replace('.pcap', '')}_") and (f.endswith('.pcap') or ".pcap" in f)
        ]
        logger.info(f"Generated split files: {split_files}")
        return split_files
    except subprocess.SubprocessError as e:
        logger.error(f"Error splitting .pcap file {pcap_file}: {e}")
        return []

## Run nProbe to process a .pcap file and output flow data in JSON.
def run_nprobe(pcap_file, output_dir):
    cmd = [
        "nprobe", "-i", pcap_file, "-n", "none", "-T", NPROBE_TEMPLATE,
        "--dump-format", "json", "--json-labels", "-P", output_dir
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        logger.info(f"nProbe processed {pcap_file}, output saved to {output_dir}")
        if "Maximum number of flows reached (25000)" in result.stderr:
            logger.warning(f"nProbe demo limit reached for {pcap_file}")
    except subprocess.SubprocessError as e:
        logger.error(f"Error running nProbe on {pcap_file}: {e}")

## Convert Suricata ISO timestamp to epoch milliseconds.
def parse_suricata_time(timestr):
    try:
        dt = datetime.strptime(timestr, "%Y-%m-%dT%H:%M:%S.%f%z")
        return int(dt.timestamp() * 1000)  # milliseconds
    except Exception:
        return 0
    
## Parse eve.json for benign flows (5-tuple) and protocol-specific features.
def parse_eve_json(eve_file):
    benign_flows = []
    protocol_features = {}
    total_flows = 0
    try:
        with open(eve_file, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                    event_type = event.get('event_type')
                    flow_id = event.get('flow_id')

                    if event_type in ['flow', 'netflow']:
                        total_flows += 1
                        flow_tuple = {
                            'src_ip': str(event.get('src_ip', '')),
                            'dst_ip': str(event.get('dest_ip', '')),
                            'src_port': str(event.get('src_port', '')),
                            'dst_port': str(event.get('dest_port', '')),
                            'proto': str(event.get('proto', '')).upper(),
                            'FIRST_SWITCHED': parse_suricata_time(event.get('start', '')),
                            'LAST_SWITCHED': parse_suricata_time(event.get('end', ''))
                        }
                        if (not flow_tuple['src_ip'] or not flow_tuple['dst_ip'] or
                            not flow_tuple['src_port'] or not flow_tuple['dst_port'] or
                            not flow_tuple['proto']):
                            continue
                        benign_flows.append(flow_tuple)
                        protocol_features[flow_id] = protocol_features.get(flow_id, {})
                        protocol_features[flow_id]['flow'] = flow_tuple
                        protocol_features[flow_id]['TIMESTAMP'] = str(event.get('timestamp', ''))

                        # logger.debug(f"Suricata benign flow: {flow_tuple}")

                    if event_type in ['http', 'tls', 'ftp', 'files', 'netflow', 'quic']:
                        protocol_features[flow_id] = protocol_features.get(flow_id, {})
                        if event_type == 'http':
                            http_data = event.get('http', {})
                            protocol_features[flow_id]['http'] = {
                                'L7_PROTO': 'http',
                                'hostname': http_data.get('hostname'),
                                'httpstatus': http_data.get('status'),
                                'url': http_data.get('url'),
                                'http_content_type': http_data.get('http_content_type'),
                                'http_method': http_data.get('http_method'),
                                'http_protocol': http_data.get('protocol'),
                                'request_headers': [h.get('name') + ': ' + h.get('value') for h in http_data.get('request_headers', [])],
                                'response_headers': [h.get('name') + ': ' + h.get('value') for h in http_data.get('response_headers', [])]
                            }
                        elif event_type == 'tls':
                            tls_data = event.get('tls', {})
                            protocol_features[flow_id]['tls'] = {
                                'L7_PROTO': 'tls',
                                'tls_sni': tls_data.get('sni'),
                                'tls_version': tls_data.get('version'),
                                'tls_ja3_hash': tls_data.get('ja3', {}).get('hash'),
                                'tls_ja3_string': tls_data.get('ja3', {}).get('string'),
                                'tls_ja3s_hash': tls_data.get('ja3s', {}).get('hash'),
                                'tls_ja3s_string': tls_data.get('ja3s', {}).get('string')
                            }
                        elif event_type == 'ftp':
                            ftp_data = event.get('ftp', {})
                            ftp_reply_code = None
                            if isinstance(ftp_data.get('reply'), list):
                                for reply in ftp_data.get('reply', []):
                                    if isinstance(reply, dict) and 'code' in reply:
                                        ftp_reply_code = reply['code']
                                        break
                            else:
                                ftp_reply_code = ftp_data.get('reply', {}).get('code')
                            protocol_features[flow_id]['ftp'] = {
                                'L7_PROTO': 'ftp',
                                'FTP_COMMAND_RET_CODE': ftp_reply_code
                            }
                        elif event_type == 'files':
                            protocol_features[flow_id]['files'] = {
                                'file_name': event.get('files', {}).get('filename'),
                                'file_size': event.get('files', {}).get('size')
                            }
                        elif event_type == 'netflow':
                            protocol_features[flow_id]['netflow'] = {
                                'IN_BYTES': event.get('netflow', {}).get('bytes'),
                                'IN_PKTS': event.get('netflow', {}).get('pkts'),
                                'MIN_TTL': event.get('netflow', {}).get('min_ttl'),
                                'MAX_TTL': event.get('netflow', {}).get('max_ttl')
                            }
                        elif event_type == 'quic':
                            quic_data = event.get('quic', {})
                            protocol_features[flow_id]['quic'] = {
                                'L7_PROTO': 'quic',
                                'quic_version': quic_data.get('version'),
                                'quic_cyu_hash': quic_data.get('cyu', {}).get('hash'),
                                'quic_cyu_string': quic_data.get('cyu', {}).get('string')
                            }

                except json.JSONDecodeError:
                    logger.warning(f"Skipping invalid JSON line in {eve_file}")
                    continue

        logger.info(f"Parsed {total_flows} total flows, {len(benign_flows)} benign flows from {eve_file}")
        return benign_flows, protocol_features
    except FileNotFoundError:
        logger.error(f"File {eve_file} not found.")
        return [], {}

##Check if two flows match (forward or reverse) with timing tolerance.
def flows_match(f1, f2, time_window=5000):
    proto1 = str(f1.get('proto', '')).upper()
    proto2 = str(f2.get('proto', '')).upper()

    forward_match = (
        f1['src_ip'] == f2['src_ip'] and
        f1['dst_ip'] == f2['dst_ip'] and
        f1['src_port'] == f2['src_port'] and
        f1['dst_port'] == f2['dst_port'] and
        proto1 == proto2
    )

    reverse_match = (
        f1['src_ip'] == f2['dst_ip'] and
        f1['dst_ip'] == f2['src_ip'] and
        f1['src_port'] == f2['dst_port'] and
        f1['dst_port'] == f2['src_port'] and
        proto1 == proto2
    )

    if not (forward_match or reverse_match):
        return False

    ## Timestamp check
    t1_start = int(f1.get('FIRST_SWITCHED', 0))
    t1_end = int(f1.get('LAST_SWITCHED', 0))
    t2_start = int(f2.get('FIRST_SWITCHED', 0))
    t2_end = int(f2.get('LAST_SWITCHED', 0))

    if t1_start and t2_start:
        start_diff = abs(t1_start - t2_start)
        end_diff = abs(t1_end - t2_end)
        if start_diff > time_window and end_diff > time_window:
            return False

    return True

## Extract features from nProbe .flows files, matching with benign flows.
def extract_features(nprobe_output_dir, benign_flows, protocol_features):
    features = []
    unmatched_nprobe_flows = []

    for root, _, files in os.walk(nprobe_output_dir):
        for filename in files:
            if filename.endswith('.flows'):
                file_path = os.path.join(root, filename)
                logger.info(f"Processing nProbe output: {file_path}")
                try:
                    with open(file_path, 'rb') as f:
                        for line in f:
                            try:
                                flow = json.loads(line.decode('utf-8', errors='ignore').strip())
                                flow_tuple = {
                                    'src_ip': str(flow.get('IPV4_SRC_ADDR')),
                                    'dst_ip': str(flow.get('IPV4_DST_ADDR')),
                                    'src_port': str(flow.get('L4_SRC_PORT', '')),
                                    'dst_port': str(flow.get('L4_DST_PORT', '')),
                                    'proto': PROTO_MAP.get(str(flow.get('PROTOCOL', '')), str(flow.get('PROTOCOL', ''))).upper(),
                                    'FIRST_SWITCHED': flow.get('FIRST_SWITCHED', 0),
                                    'LAST_SWITCHED': flow.get('LAST_SWITCHED', 0)
                                }

                                # logger.debug(f"nProbe flow: {flow_tuple}")

                                matched = False
                                for suri_flow in benign_flows:
                                    if flows_match(flow_tuple, suri_flow):
                                        matched = True
                                        feature_set = {
                                        'IPV4_SRC_ADDR': flow.get('IPV4_SRC_ADDR', '0.0.0.0'),
                                        'IPV4_DST_ADDR': flow.get('IPV4_DST_ADDR', '0.0.0.0'),
                                        'L4_SRC_PORT': flow.get('L4_SRC_PORT', 0),
                                        'L4_DST_PORT': flow.get('L4_DST_PORT', 0),
                                        'PROTOCOL': flow.get('PROTOCOL', 0),
                                        'L7_PROTO': flow.get('L7_PROTO', 0),
                                        'IN_BYTES': flow.get('IN_BYTES', 0),
                                        'OUT_BYTES': flow.get('OUT_BYTES', 0),
                                        'IN_PKTS': flow.get('IN_PKTS', 0),
                                        'OUT_PKTS': flow.get('OUT_PKTS', 0),
                                        'FIRST_SWITCHED': flow.get('FIRST_SWITCHED', 0),
                                        'LAST_SWITCHED': flow.get('LAST_SWITCHED', 0),
                                        'TCP_FLAGS': flow.get('TCP_FLAGS', 0),
                                        'CLIENT_TCP_FLAGS': flow.get('CLIENT_TCP_FLAGS', 0),
                                        'SERVER_TCP_FLAGS': flow.get('SERVER_TCP_FLAGS', 0),
                                        'DURATION_IN': flow.get('DURATION_IN', 0),
                                        'DURATION_OUT': flow.get('DURATION_OUT', 0),
                                        'MIN_TTL': flow.get('MIN_TTL', 0),
                                        'MAX_TTL': flow.get('MAX_TTL', 0),
                                        'LONGEST_FLOW_PKT': flow.get('LONGEST_FLOW_PKT', 0),
                                        'SHORTEST_FLOW_PKT': flow.get('SHORTEST_FLOW_PKT', 0),
                                        'MIN_IP_PKT_LEN': flow.get('MIN_IP_PKT_LEN', 0),
                                        'MAX_IP_PKT_LEN': flow.get('MAX_IP_PKT_LEN', 0),
                                        'SRC_TO_DST_SECOND_BYTES': flow.get('SRC_TO_DST_SECOND_BYTES', 0),
                                        'DST_TO_SRC_SECOND_BYTES': flow.get('DST_TO_SRC_SECOND_BYTES', 0),
                                        'RETRANSMITTED_IN_BYTES': flow.get('RETRANSMITTED_IN_BYTES', 0),
                                        'RETRANSMITTED_IN_PKTS': flow.get('RETRANSMITTED_IN_PKTS', 0),
                                        'RETRANSMITTED_OUT_BYTES': flow.get('RETRANSMITTED_OUT_BYTES', 0),
                                        'RETRANSMITTED_OUT_PKTS': flow.get('RETRANSMITTED_OUT_PKTS', 0),
                                        'SRC_TO_DST_AVG_THROUGHPUT': flow.get('SRC_TO_DST_AVG_THROUGHPUT', 0),
                                        'DST_TO_SRC_AVG_THROUGHPUT': flow.get('DST_TO_SRC_AVG_THROUGHPUT', 0),
                                        'NUM_PKTS_UP_TO_128_BYTES': flow.get('NUM_PKTS_UP_TO_128_BYTES', 0),
                                        'NUM_PKTS_128_TO_256_BYTES': flow.get('NUM_PKTS_128_TO_256_BYTES', 0),
                                        'NUM_PKTS_256_TO_512_BYTES': flow.get('NUM_PKTS_256_TO_512_BYTES', 0),
                                        'NUM_PKTS_512_TO_1024_BYTES': flow.get('NUM_PKTS_512_TO_1024_BYTES', 0),
                                        'NUM_PKTS_1024_TO_1514_BYTES': flow.get('NUM_PKTS_1024_TO_1514_BYTES', 0),
                                        'TCP_WIN_MAX_IN': flow.get('TCP_WIN_MAX_IN', 0),
                                        'TCP_WIN_MAX_OUT': flow.get('TCP_WIN_MAX_OUT', 0),
                                        'ICMP_TYPE': flow.get('ICMP_TYPE', 0),
                                        'ICMP_IPV4_TYPE': flow.get('ICMP_TYPE', 0),
                                        'DNS_QUERY_ID': flow.get('DNS_QUERY_ID', 0),
                                        'DNS_QUERY_TYPE': flow.get('DNS_QUERY_TYPE', 0),
                                        'DNS_TTL_ANSWER': flow.get('DNS_TTL_ANSWER', 0),
                                        'FTP_COMMAND_RET_CODE': flow.get('FTP_RAW_CODE', 0)
                                        }
                                        duration_ms = (flow.get('LAST_SWITCHED', 0) - flow.get('FIRST_SWITCHED', 0))
                                        feature_set['FLOW_DURATION_MILLISECONDS'] = duration_ms
                                        feature_set['SRC_TO_DST_AVG_THROUGHPUT'] = (
                                            int(flow.get('IN_BYTES', 0)) * 8 / (duration_ms / 1000) if duration_ms > 0 else 0
                                        )
                                        feature_set['DST_TO_SRC_AVG_THROUGHPUT'] = (
                                            int(flow.get('OUT_BYTES', 0)) * 8 / (duration_ms / 1000) if duration_ms > 0 else 0
                                        )
                                        flow_id = None
                                        for fid, data in protocol_features.items():
                                            if (
                                            data.get('flow', {}).get('src_ip') == flow_tuple['src_ip'] and
                                            data.get('flow', {}).get('dst_ip') == flow_tuple['dst_ip'] and
                                            data.get('flow', {}).get('src_port') == flow_tuple['src_port'] and
                                            data.get('flow', {}).get('dst_port') == flow_tuple['dst_port'] and
                                            data.get('flow', {}).get('proto') == flow_tuple['proto']):
                                                flow_id = fid
                                                break
                                        if flow_id in protocol_features:
                                            for event_type in ['http', 'tls', 'ftp', 'files', 'netflow', 'quic']:
                                                if event_type in protocol_features[flow_id]:
                                                    feature_set.update(protocol_features[flow_id][event_type])
                                        if flow.get('ICMP_TYPE') is not None:
                                            feature_set['ICMP_TYPE'] = flow.get('ICMP_TYPE')
                                        features.append(feature_set)
                                        # logger.debug(f"Matched benign flow: {flow_tuple}")
                                        break

                                if not matched:
                                    unmatched_nprobe_flows.append(flow_tuple)

                            except json.JSONDecodeError:
                                logger.warning(f"Skipping invalid JSON line in {file_path}")
                                continue
                except Exception as e:
                    logger.error(f"Error reading nProbe output {file_path}: {e}")
                    continue

    # unmatched flows
    if unmatched_nprobe_flows:
        logger.warning(f"Unmatched nProbe flows: {len(unmatched_nprobe_flows)}")

    logger.info(f"Extracted {len(features)} feature sets")
    return features

def main():
    pcap_dir = "/sgi/var/log/suricata"
    eve_file = "/sgi/var/log/suricata/benign.json"
    output_dir = "/sgi/var/log/suricata/nprobe_output"
    feature_output = "/sgi/var/log/suricata/features.json"

    if not os.path.exists(pcap_dir):
        logger.error(f"Directory {pcap_dir} does not exist")
        return
    if not os.access(pcap_dir, os.R_OK):
        logger.error(f"No read permission for {pcap_dir}")
        return

    os.makedirs(output_dir, exist_ok=True)

    event_handler = PcapHandler(output_dir, eve_file, feature_output)

    pcap_files = [os.path.join(pcap_dir, f) for f in os.listdir(pcap_dir) if f.endswith('.pcap')]
    if pcap_files:
        logger.info(f"Found {len(pcap_files)} existing .pcap files in {pcap_dir}")
        for pcap_file in pcap_files:
            try:
                event_handler.process_pcap(pcap_file)
            except Exception as e:
                logger.error(f"Error processing {pcap_file}: {e}")
                continue
    else:
        logger.info(f"No existing .pcap files found in {pcap_dir}, starting monitoring...")

    observer = Observer()
    observer.schedule(event_handler, pcap_dir, recursive=True)
    observer.start()
    logger.info(f"Started monitoring {pcap_dir} for new or modified .pcap files")

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        logger.info("Stopping observer...")
        observer.stop()
    observer.join()

while True:
    main()
    time.sleep(15)

#---------------------------------------------------------------------------------------