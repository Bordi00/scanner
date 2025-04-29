import argparse
import codecs
import ipaddress
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
import re
import json
from loguru import logger

SCAN_TYPES = ["tcp", "udp", "syn", "xmas", "ack", "null", "fin"]

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
    def __init__(self, args):
        conf.iface = args.interface
        targets = args.target.split(",")
        self.targets = set()
        for target in targets:
            if "/" in target:  # 172.10.2.0/24
                try:
                    self.targets.add(ipaddress.ip_network(target, strict=False))
                except ValueError:
                    print(f"Invalid network address: {args.target}")
                    exit(1)
            else:
                try:
                    self.targets.add(ipaddress.ip_address(target))
                except ValueError:
                    print(f"Invalid IP address: {args.target}")
                    exit(1)

        self.ports = set()
        for port in args.port.split(","):
            if "-" in port:
                start_port, end_port = port.split("-")
                self.ports.update(range(int(start_port), int(end_port) + 1))
            else:
                self.ports.add(int(port))

        self.verbose = args.verbose
        self.randomize = args.randomize
        self.delay = args.delay
        self.open_ports = dict()
        self.payloads = get_payloads()

        if not self.randomize:
            self.scan_type = args.scan_type

    def _scan_port(self, target: str, port: int):
        scan_type = random.choice(SCAN_TYPES) if self.randomize else self.scan_type
        delay = random.uniform(0.0, 1.0) if self.randomize else self.delay
        if delay is not None:
            time.sleep(delay)

        match scan_type:
            case "tcp":
                p = IP(dst=target) / TCP(dport=port, flags="S")
                request, responses = sr(p, timeout=1, verbose=False)
                for response in responses:
                    if response and response.haslayer(TCP) and response[TCP].flags == 0x12:  # SYN-ACK
                        _, response = sr(IP(dst=target) / TCP(dport=port, flags="A"), timeout=1, verbose=False)
                        if response and response.haslayer(TCP) and response[TCP].flags == 0x10:  # ACK
                            sr(IP(dst=target) / TCP(dport=port, flags="R"), timeout=1, verbose=False)
                            self.open_ports[target] = self.open_ports.get(target, []).append(port)
                            logger.info(f"{target}:{port} is open")

            case "udp":
                payloads = []
                for bs in self.payloads:
                    payloads = bs["payloads"] if port in bs.get("ports", []) else []
                    break
                p = [IP(dst=target) / UDP(dport=port) / Raw(load=pl) for pl in payloads] if payloads else IP(dst=target) / UDP(dport=port)
                for _ in range(2):
                    _, responses = sr(p, timeout=1, verbose=False)
                    for _ in responses if responses else []:
                        self.open_ports[target] = self.open_ports.get(target, []).append(port)
                        break
            case "syn":
                _, responses = sr(IP(dst=target) / TCP(dport=port, flags="S"), timeout=1, verbose=False)
                for response in responses:
                    if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
                        sr(IP(dst=target) / TCP(dport=port, flags="R"), timeout=1, verbose=False)
                        self.open_ports[target] = self.open_ports.get(target, []).append(port)
                        logger.info(f"{target}:{port} is open")
            case "xmas":
                for i in range(2):
                    _, responses = sr(IP(dst=target) / TCP(dport=port, flags="FPU"), timeout=1, verbose=False)
                    for response in responses if responses else []:
                        if i == 1:
                            self.open_ports[target] = self.open_ports.get(target, []).append(port)
                            logger.info(f"{target}:{port} is open")

                    if i != 1 and responses:
                        break
            case "ack":
                # TODO: implement the logic for ACK scan
                # response = sr(IP(dst=target) / TCP(dport=port, flags="A"), timeout=1, verbose=False)
                pass
            case "null":
                for i in range(2):
                    _, responses = sr(IP(dst=target) / TCP(dport=port, flags=""), timeout=1, verbose=False)
                    for response in responses:
                        if i == 1:
                            self.open_ports[target] = self.open_ports.get(target, []).append(port)
                            logger.info(f"{target}:{port} is open")
                    if i != 1 and responses:
                        break
            case "fin":
                for i in range(2):
                    _, responses = sr(IP(dst=target) / TCP(dport=port, flags="F"), timeout=1, verbose=False)
                    for response in responses:
                        if i == 1:
                            self.open_ports[target] = self.open_ports.get(target, []).append(port)
                            logger.info(f"{target}:{port} is open")
                    if i != 1 and responses:
                        break
            case _:
                print(f"Invalid scan type: {scan_type}")
                exit(1)

    def scan(self):
        if self.randomize:
            self.ports = random.sample(list(self.ports), len(self.ports))
        for target in self.targets:
            if isinstance(target, ipaddress.IPv4Network) or isinstance(target, ipaddress.IPv6Network):
                alive_hosts = host_discovery(target)

                for host in alive_hosts:
                    logger.info(f"{host} is alive")
                    logger.info("Starting port scan...")
                    for port in self.ports:
                        self._scan_port(str(host), port)
            else:
                answered, _ = sr(IP(dst=str(target)) / ICMP(), timeout=1, verbose=False)
                if answered:
                    logger.info(f"{target} is alive")
                    logger.info("Starting port scan...")
                    for port in self.ports:
                        self._scan_port(str(target), port)
        if not self.open_ports:
            logger.info("No open ports found")

    def save_scan_params(self, filename: str):
        if not filename.endswith(".json"):
            filename += ".json"
        with open(filename, "w") as f:
            json.dump(self.__dict__, f, indent=4, default=str)


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

    return parser.parse_args()


def main():
    args = parse_arguments()
    logger.remove(0)
    if args.verbose:
        logger.add(lambda msg: print(msg, end=""), level="DEBUG", format="<lvl>{message}</lvl>", colorize=True)
    logger.info("Starting scan...")
    scanner = Scanner(args)
    scanner.scan()

if __name__ == "__main__":
    main()
