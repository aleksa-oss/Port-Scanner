#!/usr/bin/env python3
"""
Network Scanner Main Module
Multi-threaded network service scanner using banner grabbers.
"""

import threading
import sys
import socket
from grabbers import *
from utils import list_builder

# Port to handler function mapping
PORT_HANDLERS = {
	21: simple_protocol_grabber,
	22: simple_protocol_grabber,
	23: telnet_grabber,
	25: simple_protocol_grabber,
	53: detect_dns_service,
	69: tftp_grabber,
	80: http_grabber,
	88: kerberos_grabber,
	110: simple_protocol_grabber,
	123: ntp_grabber,
	137: netbios_grabber,
	143: simple_protocol_grabber,
	161: snmp_getnext_grabber,
	389: ldap_grabber,
	443: https_grabber,
	445: smb_grabber,
	587: simple_protocol_grabber,
	636: ldaps_grabber,
	993: imaps_grabber,
	995: pop3s_grabber,
	1433: mssql_grabber,
	3306: simple_protocol_grabber,
	3389: rdp_grabber,
	5432: postgresql_grabber,
	8080: http_8080_grabber
}


def is_valid_host(host):
	"""Check if the host is resolvable."""
	try:
		socket.gethostbyname(host)
		return True
	except socket.error:
		return False


def scanner(host, port_list):
	"""Scanner worker thread function."""
	while not port_list.empty():
		try:
			port = port_list.get()
			handler = PORT_HANDLERS.get(port)

			if handler:
				if handler == simple_protocol_grabber:
					handler(host, port)
				else:
					handler(host)
			else:
				tcp_check(host, port)
		except Exception:
			continue


def create_custom_port_list(ports_str):
	"""Convert string to a port queue. Supports comma-separated ranges."""
	import queue
	port_queue = queue.Queue()

	if not ports_str:
		return port_queue

	for part in ports_str.split(','):
		part = part.strip()
		if '-' in part:
			try:
				start, end = map(int, part.split('-', 1))
				for port in range(start, end + 1):
					if 1 <= port <= 65535:
						port_queue.put(port)
			except ValueError:
				print(f"[!] Invalid port range: {part}")
		else:
			try:
				port = int(part)
				if 1 <= port <= 65535:
					port_queue.put(port)
				else:
					print(f"[!] Invalid port number: {port}")
			except ValueError:
				print(f"[!] Invalid port: {part}")

	return port_queue


def print_usage():
	"""Print usage information."""
	print("Network Scanner - Multi-threaded service banner grabber\n")
	print("Usage:")
	print(f"  {sys.argv[0]} <host> [options]\n")
	print("Options:")
	print("  -t, --threads <num>     Number of threads (default: 100)")
	print("  -p, --ports <ports>     Custom ports (e.g., 80,443,8080-8090)")
	print("  -r, --range <num>       Scan ports 1-<num> (default: 6000)")
	print("  -h, --help              Show this help message\n")
	print("Examples:")
	print(f"  {sys.argv[0]} example.com")
	print(f"  {sys.argv[0]} 192.168.1.1 -t 50 -r 1000")
	print(f"  {sys.argv[0]} example.com -p 22,80,443,8000-8100")


def main():
	"""Main function with argument parsing and execution."""
	if len(sys.argv) < 2 or sys.argv[1] in ['-h', '--help']:
		print_usage()
		sys.exit(0)

	host = sys.argv[1]
	threads_number = 100
	port_range = 6000
	custom_ports = None

	# Parse flags
	i = 2
	while i < len(sys.argv):
		arg = sys.argv[i]
		if arg in ['-t', '--threads']:
			if i + 1 < len(sys.argv):
				try:
					threads_number = int(sys.argv[i + 1])
					if threads_number < 1:
						print("[!] Number of threads must be positive")
						sys.exit(1)
					i += 2
				except ValueError:
					print("[!] Invalid number of threads")
					sys.exit(1)
			else:
				print("[!] Missing value for threads option")
				sys.exit(1)

		elif arg in ['-p', '--ports']:
			if i + 1 < len(sys.argv):
				custom_ports = sys.argv[i + 1]
				i += 2
			else:
				print("[!] Missing value for ports option")
				sys.exit(1)

		elif arg in ['-r', '--range']:
			if i + 1 < len(sys.argv):
				try:
					port_range = int(sys.argv[i + 1])
					if not (1 <= port_range <= 65535):
						print("[!] Port range must be between 1 and 65535")
						sys.exit(1)
					i += 2
				except ValueError:
					print("[!] Invalid port range")
					sys.exit(1)
			else:
				print("[!] Missing value for range option")
				sys.exit(1)

		else:
			print(f"[!] Unknown option: {arg}")
			print_usage()
			sys.exit(1)

	# Validate host
	if not is_valid_host(host):
		print(f"[!] Invalid or unreachable host: {host}")
		sys.exit(1)

	# Build port list
	if custom_ports:
		port_list = create_custom_port_list(custom_ports)
		print(f"[*] Scanning {host} with custom ports: {custom_ports}")
	else:
		port_list = list_builder(port_range)
		print(f"[*] Scanning {host} on ports 1-{port_range}")

	print(f"[*] Using {threads_number} threads")
	print(f"[*] Total ports to scan: {port_list.qsize()}")
	print("-" * 60)

	# Start scanning
	threads = []
	for _ in range(threads_number):
		t = threading.Thread(target=scanner, args=(host, port_list), daemon=True)
		t.start()
		threads.append(t)

	try:
		for t in threads:
			t.join()
	except KeyboardInterrupt:
		print("\n[!] Scan interrupted by user")
		sys.exit(1)

	print("\n[*] Scan completed!")


if __name__ == "__main__":
	main()

