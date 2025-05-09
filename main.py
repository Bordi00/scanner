import argparse
import codecs
import ipaddress
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
import re
import json
from loguru import logger
from datetime import datetime
import sys
from tqdm import tqdm

SCAN_TYPES = ["tcp", "udp", "syn", "xmas", "null", "fin"]
FILTERED_CODES = [1, 2, 3, 9, 10, 13]
MOST_SCANNED_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 110,
    111, 123, 135, 137, 138, 139, 143, 161, 162, 179,
    389, 443, 445, 465, 514, 515, 520, 554, 587, 593,
    631, 636, 873, 902, 993, 995, 1025, 1080, 1194, 1234,
    1433, 1434, 1521, 1723, 1900, 2049, 2082, 2083, 2100, 2222,
    2375, 2376, 2483, 2484, 25565, 2601, 3128, 3268, 3306, 3389,
    3478, 3632, 4000, 4444, 4500, 4672, 5000, 5001, 5060, 5061,
    5432, 5631, 5632, 5900, 5985, 5986, 6000, 6379, 6666, 6667,
    7001, 7002, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090,
    9200, 9300, 9999, 10000, 11211, 27017
] + list(range(49152, 49162))

MOST_SCANNED_WELL_KNOWN_PORTS = [
    1, 7, 9, 13, 17, 19, 20, 21, 22, 23,
    25, 37, 42, 43, 49, 53, 67, 68, 69, 70,
    79, 80, 88, 109, 110, 111, 113, 119, 123, 135,
    137, 138, 139, 143, 161, 162, 179, 194, 389, 427,
    443, 445, 464, 465, 512, 513, 514, 515, 520, 524,
    540, 548, 554, 587, 593, 631, 636, 873, 990, 992,
    993, 995, 102, 108, 135, 144, 179, 254, 255, 260,
    264, 318, 383, 512, 513, 514, 515, 520, 524, 530,
    543, 544, 548, 554, 587, 593, 631, 636, 749, 765,
    873, 992, 993, 995, 999, 1010, 1023
]
def get_windows_ip():
    try:
        result = subprocess.check_output([
            "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
            "-Command",
            "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -match 'Wi-Fi|Ethernet'}).IPAddress"
        ])
        return result.decode("utf-8").strip()
    except Exception as e:
        print("Failed to retrieve Windows IP via PowerShell:", e)
        return None

def get_payloads():
    entries = []
    current_entry = None

    udp_line_pattern = re.compile(r'^udp\s+([\d,-]+)\s*(?:"([^"]*)")?')
    payload_line_pattern = re.compile(r'^\s*"([^"]+)"')
    source_line_pattern = re.compile(r'^\s*source\s+(\d+)')

    def decode_payload(s):
        # Decode \xNN sequences into actual bytes
        return codecs.decode(s, 'unicode_escape').encode('latin1')

    with open("utilities/payloads", 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()

            # Skip comments and blank lines
            if not line or line.startswith('#'):
                continue

            # New UDP entry
            m = udp_line_pattern.match(line)
            if m:
                if current_entry:
                    entries.append(current_entry)
                ports, first_payload = m.groups()
                current_entry = {
                    'protocol': 'udp',
                    'ports': ports,
                    'payloads': []
                }
                if first_payload:
                    current_entry['payloads'].append(decode_payload(first_payload))
                continue

            # Additional payload lines
            m = payload_line_pattern.match(line)
            if m and current_entry:
                current_entry['payloads'].append(decode_payload(m.group(1)))
                continue

            # Source port line
            m = source_line_pattern.match(line)
            if m and current_entry:
                current_entry['source'] = int(m.group(1))
                continue

    # Append the last entry if there is one
    if current_entry:
        entries.append(current_entry)

    return entries

def host_discovery(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> list | None:
    pings = [IP(dst=str(ip)) / ICMP() for ip in network.hosts()]
    answered, _ = sr(pings, timeout=1, verbose=False)
    return [sent.dst for sent, recv in answered] if answered else None


class Scanner:
    def __init__(self, params):
        self.verbose = params.verbose
        conf.iface = params.interface
        ips = get_windows_ip().split("\r\n")
        self.duration = 0
        self.ip = ""
        for ip in ips:
            self.ip = ip if self.ip == "" and ip.startswith("172.25.") else self.ip
        self.start = datetime.now()
        self.end = 0
        targets = params.target.split(",")
        self.targets = set()
        for target in targets:
            if "/" in target:  # 172.10.2.0/24
                try:
                    self.targets.add(ipaddress.ip_network(target, strict=False))
                except ValueError:
                    print(f"Invalid network address: {params.target}")
                    exit(1)
            else:
                try:
                    self.targets.add(ipaddress.ip_address(target))
                except ValueError:
                    print(f"Invalid IP address: {params.target}")
                    exit(1)

        if "MSWKP" in params.port:
            self.ports = MOST_SCANNED_WELL_KNOWN_PORTS
        else:
            self.ports = set()
            for port in params.port.split(","):
                if "-" in port:
                    start_port, end_port = port.split("-")
                    self.ports.update(range(int(start_port), int(end_port) + 1))
                else:
                    self.ports.add(int(port))


        self.verbose = params.verbose
        self.randomize = params.randomize
        self.delay = params.delay
        self.open_ports = {}
        self.mode = params.mode
        match self.mode:
            case "noisy":
                self.inter = None
            case "sneaky":
                self.inter = (0.1, 0.16) # 420 packets per minute -> 25200 packets per hour
            case "stealth":
                self.inter = (0.5, 1.5) # 60 packets per minute -> 3600 packets per hour

        if not self.randomize:
            self.scan_type = params.scan_type

    def _scan_port(self, target: str | list, port: int | list):
        scan_type = random.choice(SCAN_TYPES) if self.randomize else self.scan_type
        if self.inter and self.randomize:
            self.delay = random.uniform(self.inter[0], self.inter[1])

        match scan_type:
            case "tcp":
                self.tcp_scan(target, [port] if isinstance(port, int) else port)
            case "udp":
                self.udp_scan(target, [port] if isinstance(port, int) else port)
            case "syn":
                self.syn_scan(target, [port] if isinstance(port, int) else port)
            case "xmas":
                self.exotic_scan(target, [port] if isinstance(port, int) else port, mode="x")
            case "null":
                self.exotic_scan(target, [port] if isinstance(port, int) else port, mode="n")
            case "fin":
                self.exotic_scan(target, [port] if isinstance(port, int) else port, mode="f")
            case _:
                print(f"Invalid scan type: {scan_type}")
                exit(1)

    def tcp_scan(self, target: str | list, ports_range: range | list):
        logger.info(f"TCP scan on {target}")
        ans, _ = sr(
            IP(dst=target) / TCP(sport=RandShort(), dport=ports_range, flags="S"),
            timeout=1,
            verbose=False,
            inter=self.delay,
        )
        for sent, received in ans:
            port = sent.dport
            if received.haslayer(TCP) and received[TCP].flags == 0x12: # SYN-ACK
                logger.success(f"{port} is open")
                self.open_ports[sent.dst] = self.open_ports[sent.dst].append(port) if self.open_ports.get(sent.dst) else [port]

                sr1(IP(dst=sent.dst) / TCP(sport=sent.sport, dport=port, flags="A"), timeout=0.5, verbose=False)
                sr1(IP(dst=sent.dst) / TCP(sport=sent.sport, dport=port, flags="R"), timeout=0.5, verbose=False)


    def syn_scan(self, target: str | list, ports_range: range | list):
        logger.info(f"SYN scan on {target}")
        ans, unans = sr(
            IP(dst=target) / TCP(sport=RandShort(), dport=ports_range, flags="S"),
            timeout=1,
            verbose=False,
            inter=self.delay
        )
        for sent, recv in ans:
            if recv.haslayer("TCP") and recv["TCP"].flags == 0x12: # SYN-ACK
                self.open_ports[sent.dst] = self.open_ports[sent.dst].append(sent.dport) if self.open_ports.get(sent.dst) else [sent.dport]
                logger.success(f"{sent.dst}:{sent.dport} is open")
        for u in unans:
            logger.info(f"{u.dst}:{u.dport} is closed")



    def udp_scan(self, target: str | list, ports_range: range | list):
        pkts = []
        payloads = []
        logger.info(f"UDP scan on {target}")
        for port in ports_range:
            for pl in get_payloads():
                if pl["ports"] == port:
                    payloads = pl["payloads"] if port in pl.get(port, []) else []

            pkts.append(IP(dst=target) / UDP(sport=RandShort(), dport=port) / Raw(load=payloads.pop(0)) if payloads else \
                        IP(dst=target) / UDP(sport=RandShort(), dport=port))
        ans, unans = sr(pkts, timeout=1, verbose=False, retry=2, inter=self.delay)
        for sent, recv in ans:
            if recv.haslayer("UDP"):
                self.open_ports[sent.dst] = self.open_ports[sent.dst].append(sent.dport) if self.open_ports.get(sent.dst) else [sent.dport]
                logger.success(f"{sent.dst}:{sent.dport} is open")
            elif recv.haslayer("ICMP"):
                if recv["ICMP"].type == 3 and recv["ICMP"].code == 3:
                    logger.info(f"{sent.dst}:{sent.dport} is closed")
                elif recv["ICMP"].type == 3 and recv["ICMP"].code in FILTERED_CODES:
                    logger.warning(f"{sent.dst}:{sent.dport} is filtered")

        for u in unans:
            self.open_ports[u.dst] = self.open_ports[u.dst].append(u.dport) if self.open_ports.get(u.dst) else [u.dport]
            logger.warning(f"{u.dst}:{u.dport} is open or filtered")

    def exotic_scan(self, target: str | list, ports_range: range | list , mode: str ="x"):
        if mode not in ["x", "f", "n"]:
            return
        f = ""
        match mode:
            case "x":
                logger.info(f"XMAS scan on {target}")
                f = "FPU"
            case "f":
                logger.info(f"FIN scan on {target}")
                f = "F"
            case "n":
                logger.info(f"NULL scan on {target}")
                f = ""

        ans, unans = sr(
            IP(dst=target) / TCP(sport=RandShort(), dport=ports_range, flags=f),
            timeout=1,
            verbose=False,
            retry=2,
            inter=self.delay,
        )
        for sent, received in ans:
            port = sent.dport
            if received.haslayer(TCP):
                tcp_layer = received.getlayer(TCP)
                if tcp_layer.flags == 0x14:  # RST
                    logger.info(f"{sent.dst}:{port} is closed")
            elif received.haslayer(ICMP):
                icmp = received.getlayer(ICMP)
                if icmp.type == 3 and icmp.code in FILTERED_CODES:
                    logger.info(f"{sent.dst}:{port} is filtered")
            else:
                logger.info(f"{sent.dst}:{port} status unknown")

        # Ports that didn’t respond are potentially open|filtered
        for pkt in unans:
            self.open_ports[pkt.dst] = self.open_ports[pkt.dst].append(pkt.dport) if self.open_ports.get(pkt.dst) else [pkt.dport]
            logger.warning(f"{pkt.dst}:{pkt.dport} is open or filtered")


    def scan(self):
        if self.randomize:
            self.ports = random.sample(list(self.ports), len(self.ports))
            self.scan_type = random.choice(SCAN_TYPES)

        for target in self.targets:
            if isinstance(target, ipaddress.IPv4Network) or isinstance(target, ipaddress.IPv6Network):
                alive_hosts = host_discovery(target)
                logger.info(f"{len(alive_hosts)} hosts found alive")
                if self.mode == "noisy":
                    match self.scan_type:
                        case "syn":
                            self.syn_scan(target=[str(host) for host in alive_hosts], ports_range=list(self.ports))
                        case "tcp":
                            self.tcp_scan([str(host) for host in alive_hosts], list(self.ports))
                        case "udp":
                            self.udp_scan([str(host) for host in alive_hosts], list(self.ports))
                        case "xmas":
                            self.exotic_scan([str(host) for host in alive_hosts], list(self.ports), mode="x")
                        case "fin":
                            self.exotic_scan([str(host) for host in alive_hosts], list(self.ports), mode="f")
                        case "null":
                            self.exotic_scan([str(host) for host in alive_hosts], list(self.ports), mode="n")
                else:
                    for host in alive_hosts if self.verbose else tqdm(alive_hosts):
                        logger.info(f"{host} is alive")
                        logger.info("Starting port scan...")
                        ports = self.ports if isinstance(self.ports, list) else list(self.ports)
                        ports = [ports[i:i + 10] for i in range(0, len(self.ports), 10)]
                        for port in ports:
                            self._scan_port(str(host), port)
            else:
                answered, _ = sr(IP(dst=str(target)) / ICMP(), timeout=1, verbose=False)
                if answered:
                    logger.info(f"{target} is alive")
                    logger.info("Starting port scan...")
                    if self.mode == "noisy":
                        match self.scan_type:
                            case "syn":
                                self.syn_scan(str(target), list(self.ports))
                            case "tcp":
                                self.tcp_scan(str(target), list(self.ports))
                            case "udp":
                                self.udp_scan(str(target), list(self.ports))
                            case "xmas":
                                self.exotic_scan(str(target), list(self.ports), mode="x")
                            case "fin":
                                self.exotic_scan(str(target), list(self.ports), mode="f")
                            case "null":
                                self.exotic_scan(str(target), list(self.ports), mode="n")
                    else:
                        ports = self.ports if isinstance(self.ports, list) else list(self.ports)
                        ports = [ports[i:i+10] for i in range(0, len(self.ports), 10)]
                        for port in ports if self.verbose else tqdm(ports):
                            self._scan_port(str(target), port)
        if not self.open_ports:
            logger.info("No open ports found")
        try:
            self.end = datetime.now()
            self.duration = self.end - self.start
        except:
            self.end = datetime.now()
            self.duration = self.end - datetime.strptime(self.start, "%Y-%m-%d %H:%M:%S.%f")

    def save_scan_params(self, filename: str, update: bool = False):
        filename += ".json" if not filename.endswith(".json") else ""

        # Load existing data if valid
        if os.path.exists(filename) and os.path.getsize(filename) > 0:
            try:
                with open(filename, "r") as f:
                    file_data = json.load(f)
                    file_data = list(file_data) if not isinstance(file_data, list) else file_data

            except (json.JSONDecodeError, FileNotFoundError):
                file_data = []
        else:
            file_data = []

        if not update:
            data = {}
            data["ip"] = self.ip
            data["start"] = str(self.start)
            data["random"] = self.randomize
            data["mode"] = self.mode
            file_data.append(data)
        else:
            file_data[-1]["end"] = str(self.end)
            file_data[-1]["duration"] = str(self.duration)

        # Overwrite with the updated list
        with open(filename, "w") as f:
            json.dump(file_data, f, indent=4)


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-t",
        "--target",
        type=str,
        required=True,
        help="Target ip/network to scan")
    parser.add_argument(
        "-p",
        "--port",
        type=str,
        help="List of ports to scan (e.g., 22,80-100), default scans first 1000 ports",
        default="1-1000",
    )
    parser.add_argument("-r", "--randomize", action="store_true", help="Randomize the scans")
    parser.add_argument(
        "-s",
        "--scan-type",
        type=str,
        choices=SCAN_TYPES,
        default="tcp",
        help="Type of scan to perform (tcp/udp), default is tcp",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-d", "--delay", type=float, help="Delay between each scan", default=0.0)
    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        choices=get_if_list(),
        help="Interface to use",
        default=conf.iface,
    )

    parser.add_argument(
        "-m",
        "--mode",
        choices=["noisy", "sneaky", "stealth"],
        type=str,
        default="noisy",
        help="Mode to use",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Output json file",
    )

    parser.add_argument(
        "-I",
        "--iterations",
        type=int,
        help="Number of iterations to perform",
        default=1,
    )

    return parser.parse_args()


def main():
    args = parse_arguments()
    logger.remove(0)
    if args.verbose:
        logger.add(lambda msg: print(msg, end=""), level="DEBUG", format="<lvl>{message}</lvl>", colorize=True)

    mode = args.mode
    for i in range(args.iterations):

        if i != 0:
            logger.info("Waiting for 1h..." % args.delay)
            time.sleep(3600)
            args.mode = "sneaky" if mode == "stealth" else "sneaky"
            mode = args.mode

        logger.info("Starting scan...")
        scanner = Scanner(args)
        if args.output:
            scanner.save_scan_params(args.output, update=False)
        scanner.scan()
        if args.output:
            scanner.save_scan_params(args.output, update=True)
        logger.info("Scan completed")


if __name__ == "__main__":
    main()
