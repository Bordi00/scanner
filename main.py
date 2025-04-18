import argparse
import ipaddress
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP

SCAN_TYPES = ["tcp", "udp", "syn", "xmas", "ack", "null", "fin"]


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
                self.ports.update(range(start_port, end_port + 1))
            else:
                self.ports.add(int(port))

        self.verbose = args.verbose
        self.randomize = args.randomize
        self.delay = args.delay
        self.open_ports = dict()
        if not self.randomize:
            self.scan_type = args.scan_type

    def _scan_port(self, target: str, port: int):
        scan_type = random.choice(SCAN_TYPES) if self.randomize else self.scan_type
        delay = random.uniform(0.0, 1.0) if self.randomize else self.delay
        if delay is not None:
            time.sleep(delay)
        match scan_type:
            case "tcp":
                request, response = sr(IP(dst=target) / TCP(dport=port, flags="S"), timeout=1, verbose=False)
                if response and response.haslayer(TCP) and response[TCP].flags == 0x12:  # SYN-ACK
                    _, response = sr(IP(dst=target) / TCP(dport=port, flags="A"), timeout=1, verbose=False)
                    if response and response.haslayer(TCP) and response[TCP].flags == 0x10:  # ACK
                        sr(IP(dst=target) / TCP(dport=port, flags="R"), timeout=1, verbose=False)
                        self.open_ports[target] = self.open_ports.get(target, []).append(port)
            case "udp":
                for _ in range(2):
                    _, response = sr(IP(dst=target) / UDP(dport=port), timeout=1, verbose=False)
                    if response:
                        self.open_ports[target] = self.open_ports.get(target, []).append(port)
                        break
            case "syn":
                _, response = sr(IP(dst=target) / TCP(dport=port, flags="S"), timeout=1, verbose=False)
                if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
                    sr(IP(dst=target) / TCP(dport=port, flags="R"), timeout=1, verbose=False)
                    self.open_ports[target] = self.open_ports.get(target, []).append(port)
            case "xmas":
                for i in range(2):
                    _, response = sr(IP(dst=target) / TCP(dport=port, flags="FPU"), timeout=1, verbose=False)
                    if not response and i == 1:
                        self.open_ports[target] = self.open_ports.get(target, []).append(port)
                    elif response:
                        break
            case "ack":
                # TODO: implement the logic for ACK scan
                # response = sr(IP(dst=target) / TCP(dport=port, flags="A"), timeout=1, verbose=False)
                pass
            case "null":
                for i in range(2):
                    _, response = sr(IP(dst=target) / TCP(dport=port, flags=""), timeout=1, verbose=False)
                    if not response and i == 1:
                        self.open_ports[target] = self.open_ports.get(target, []).append(port)
                    elif response:
                        break
            case "fin":
                for i in range(2):
                    _, response = sr(IP(dst=target) / TCP(dport=port, flags="F"), timeout=1, verbose=False)
                    if not response and i == 1:
                        self.open_ports[target] = self.open_ports.get(target, []).append(port)
                    elif response:
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
                    for port in self.ports:
                        self._scan_port(str(host), port)
            else:
                for port in self.ports:
                    self._scan_port(str(target), port)


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
        required=True,
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
    scanner = Scanner(args)
    scanner.scan()


if __name__ == "__main__":
    main()
