"""PCAP traffic parser using tshark fields mode (efficient streaming)."""

import csv
import logging
import subprocess
import time
from dataclasses import dataclass
from typing import Iterator, List, Optional


@dataclass
class PacketInfo:
    """Information about a single network packet."""
    timestamp: float          # Unix timestamp from tshark
    src_ip: str
    src_port: str
    dst_ip: str
    dst_port: str
    protocol: str          # e.g., TCP, UDP, HTTP, DNS
    domain: Optional[str] = None    # Extracted domain
    url: Optional[str] = None       # Full URL if HTTP
    dns_ip: Optional[str] = None    # DNS resolved IP

    @property
    def timestamp_str(self) -> str:
        """Get timestamp as formatted string."""
        return self.timestamp

    def get_unique_key(self) -> str:
        """Get unique key for deduplication."""
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}:{self.protocol}:{self.url}:{self.domain}:{self.dns_ip}"

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "url": self.url,
            "domain": self.domain,
            "dns_ip": self.dns_ip
        }

    def __str__(self) -> str:
        """String representation."""
        return (f"[{self.protocol}] {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} | "
                f"Domain: {self.domain or 'N/A'} | URL: {self.url or 'N/A'} | DNS: {self.dns_ip or 'N/A'}")


class TrafficParser:
    """
    Efficient PCAP traffic parser using tshark fields mode.

    This parser uses tshark's -T fields option for streaming output,
    which is much more efficient than JSON mode for large files.
    """

    # Fields to extract from tshark
    FIELDS = [
        'frame.time_epoch',             # Unix timestamp (float)
        'ip.src',                        # Source IP
        'tcp.srcport',                   # TCP source port
        'udp.srcport',                   # UDP source port
        'ip.dst',                        # Destination IP
        'tcp.dstport',                   # TCP destination port
        'udp.dstport',                   # UDP destination port
        '_ws.col.Protocol',              # Protocol column
        'frame.protocols',               # Protocol stack
        'http.host',                     # HTTP Host header
        'tls.handshake.extensions_server_name',  # TLS SNI
        'http.request.full_uri',        # Full HTTP URI
        'dns.qry.name',                  # DNS query name
        'dns.a',                         # DNS A record (IPv4)
        'dns.aaaa',                      # DNS AAAA record (IPv6)
    ]

    def __init__(self, tshark_path: str = 'tshark'):
        """
        Initialize the traffic parser.

        Args:
            tshark_path: Path to tshark executable (default: 'tshark')
        """
        self.tshark_path = tshark_path

    def _check_tshark(self) -> bool:
        """Check if tshark is available."""
        timeout_seconds = 15
        max_attempts = 2
        for attempt in range(1, max_attempts + 1):
            try:
                subprocess.run(
                    [self.tshark_path, '-v'],
                    capture_output=True,
                    timeout=timeout_seconds,
                    check=True,
                )
                return True
            except FileNotFoundError as exc:
                logger.warning(
                    "tshark check failed attempt=%s/%s type=FileNotFoundError path=%s err=%s",
                    attempt,
                    max_attempts,
                    self.tshark_path,
                    exc,
                )
            except subprocess.TimeoutExpired as exc:
                logger.warning(
                    "tshark check failed attempt=%s/%s type=TimeoutExpired timeout=%ss err=%s",
                    attempt,
                    max_attempts,
                    timeout_seconds,
                    exc,
                )
            except subprocess.CalledProcessError as exc:
                logger.warning(
                    "tshark check failed attempt=%s/%s type=CalledProcessError returncode=%s err=%s",
                    attempt,
                    max_attempts,
                    exc.returncode,
                    exc,
                )
        return False

    def parse_pcap(self, pcap_path: str, filter_expr: Optional[str] = None) -> List[PacketInfo]:
        """
        Parse a PCAP file and return all packets.

        Args:
            pcap_path: Path to the PCAP file
            filter_expr: Optional tshark display filter (e.g., 'http or dns')

        Returns:
            List of PacketInfo objects
        """
        return list(self.parse_pcap_stream(pcap_path, filter_expr))

    def parse_pcap_stream(self, pcap_path: str, filter_expr: Optional[str] = None) -> Iterator[PacketInfo]:
        """
        Parse a PCAP file and yield packets as they are parsed.

        This is memory-efficient for large files.

        Args:
            pcap_path: Path to the PCAP file
            filter_expr: Optional tshark display filter (e.g., 'http or dns')

        Yields:
            PacketInfo objects
        """
        if not self._check_tshark():
            raise RuntimeError(
                "tshark is not available. Please install Wireshark from "
                "https://www.wireshark.org/download.html"
            )

        # Build tshark command
        cmd = self._build_command(pcap_path, filter_expr)

        # Run tshark
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1  # Line buffered
        )

        try:
            # Use csv.DictReader to parse tab-separated output
            reader = csv.DictReader(process.stdout, delimiter='\t')

            for row in reader:
                packet = self._parse_row(row)
                if packet:
                    yield packet

        except KeyboardInterrupt:
            process.terminate()
            process.wait()
            raise
        except Exception as e:
            process.terminate()
            process.wait()
            raise RuntimeError(f"Error parsing PCAP: {e}")
        finally:
            process.terminate()
            process.wait()

    def _build_command(self, pcap_path: str, filter_expr: Optional[str]) -> List[str]:
        """Build the tshark command."""
        cmd = [
            self.tshark_path,
            '-n',                          # No name resolution
            '-r', pcap_path,               # Read from file
            '-T', 'fields',                # Fields output mode
        ]

        # Add display filter 
        if filter_expr:
            cmd.extend(['-Y', filter_expr])

        # Add fields to extract
        for field in self.FIELDS:
            cmd.extend(['-e', field])

        # Output formatting
        cmd.extend([
            '-E', 'header=y',              # Include header
            '-E', 'separator=\t',          # Tab separator
            '-E', 'occurrence=f',          # Use first occurrence
        ])

        return cmd

    def _parse_row(self, row: dict) -> Optional[PacketInfo]:
        """
        Parse a single row from tshark output.

        Args:
            row: Dictionary with field names as keys

        Returns:
            PacketInfo object or None if row is invalid
        """
        # Basic fields
        timestamp_str = row.get('frame.time_epoch', '0')
        src_ip = row.get('ip.src')
        dst_ip = row.get('ip.dst')
        protocol = (row.get('_ws.col.Protocol') or row.get('_ws.col.protocol') or '').strip()
        if not protocol:
            protocol_stack = (row.get('frame.protocols') or '').strip()
            if protocol_stack:
                protocol = protocol_stack.split(':')[-1].upper()

        # Skip rows without basic info
        if not src_ip or not dst_ip:
            return None

        # Parse timestamp to float (time_epoch is already a number)
        try:
            timestamp = float(timestamp_str)
        except (ValueError, TypeError):
            timestamp = 0.0

        # Merge TCP/UDP ports
        src_port = row.get('tcp.srcport') or row.get('udp.srcport')
        dst_port = row.get('tcp.dstport') or row.get('udp.dstport')

        # Domain extraction (priority: HTTP Host > TLS SNI > DNS Query)
        domain = (
            row.get('http.host') or
            row.get('tls.handshake.extensions_server_name') or
            row.get('dns.qry.name')
        )

        # URL
        url = row.get('http.request.full_uri')

        # DNS resolved IPs
        dns_ip = row.get('dns.a') or row.get('dns.aaaa')

        return PacketInfo(
            timestamp=timestamp,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            domain=domain,
            url=url,
            dns_ip=dns_ip
        )

    def print_packets(self, pcap_path: str, filter_expr: Optional[str] = None) -> int:
        """
        Parse and print packets to stdout.

        Args:
            pcap_path: Path to the PCAP file
            filter_expr: Optional tshark display filter

        Returns:
            Number of packets processed
        """
        count = 0
        for packet in self.parse_pcap_stream(pcap_path, filter_expr):
            print(packet)
            count += 1
        return count


def main():
    """Simple command-line interface."""
    import argparse

    parser = argparse.ArgumentParser(description='Parse PCAP files using tshark')
    parser.add_argument('--pcap_file', type=str,default="data/ugl.igoeabeefeybdjmbyid.xqrtpkcr/capture.pcap",help='Path to PCAP file')
    parser.add_argument('-f', '--filter', default="", help='Tshark display filter (e.g., "http or dns")')
    parser.add_argument('-c', '--count', type=int,default=20, help='Limit number of packets to display')
    args = parser.parse_args()

    traffic_parser = TrafficParser()

    print(f"Parsing {args.pcap_file}...")
    if args.filter:
        print(f"Filter: {args.filter}")
    print("-" * 80)

    count = 0
    for packet in traffic_parser.parse_pcap_stream(args.pcap_file, args.filter):
        print(packet)
        count += 1
        if args.count and count >= args.count:
            break

    print("-" * 80)
    print(f"Total packets: {count}")


if __name__ == '__main__':
    main()
logger = logging.getLogger(__name__)
