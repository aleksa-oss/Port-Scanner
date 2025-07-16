#!/usr/bin/env python3
"""
Network Service Banner Grabber
A tool for identifying and gathering information from various network services.
"""

import socket
import re
import time
import struct
import random
import ssl


# Telnet negotiation constants
IAC = 255
DO = 253
DONT = 254
WILL = 251
WONT = 252
SB = 250
SE = 240

# Minimal Kerberos AS-REQ packet (DER-encoded, crafted)
# This is a generic unauthenticated AS-REQ that some KDCs will respond to
RAW_AS_REQ = bytes.fromhex(
	"6a81a73081a4a003020105a10302010ea207030500"
	"20200ea30aa10830061b046b726274a40ba409a207"
	"03050020200ea511180f3230323530373130313730"
	"3534355aa711180f32303235303731303138303535"
	"5aa8193017a003020101a110300e1b0c6578616d70"
	"6c652e636f6d"
)


def print_banner(title):
	"""Print a formatted banner for service information."""
	print("=" * 60)
	print(f"[+] {title}")
	print("=" * 60)


def print_footer():
	"""Print a footer separator."""
	print("-" * 60 + "\n")


def tcp_check(host, port):
	"""Basic TCP port connectivity check."""
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(2)
		s.connect((host, port))
		print_banner(f"Port {port} is open")
		print_footer()
		s.close()
	except Exception:
		pass


def http_grabber(host):
	"""Grab HTTP banner and response from port 80."""
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(3)
		s.connect((host, 80))
		s.send(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
		response = s.recv(4096).decode(errors="ignore")
		print_banner("Port 80 (HTTP) is open")
		print(response)
		print_footer()
		s.close()
	except Exception:
		pass


def simple_protocol_grabber(host, port):
	"""Grab banners from simple protocols that send immediate responses."""
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(3)
		s.connect((host, port))
		response = s.recv(1024).decode(errors="ignore")
		
		service_map = {
			21: "FTP",
			22: "SSH",
			23: "TELNET",
			25: "SMTP",
			110: "POP3",
			143: "IMAP",
			587: "SMTP",
			3306: "MySQL"
		}
		
		service_name = service_map.get(port, "Unknown")
		print_banner(f"Port {port} ({service_name}) is open")
		print(response)
		print_footer()
		s.close()
	except Exception:
		pass


def telnet_negotiate(sock, cmd, option):
	"""Handle Telnet protocol negotiation."""
	if cmd == DO:
		sock.sendall(bytes([IAC, WONT, option]))
	elif cmd == WILL:
		sock.sendall(bytes([IAC, DONT, option]))


def telnet_grabber(host):
	"""Enhanced Telnet banner grabber with protocol negotiation."""
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(5)
		s.connect((host, 23))
		s.sendall(b"\r\n")

		buffer = bytearray()
		in_sb = False

		while True:
			try:
				chunk = s.recv(1024)
				if not chunk:
					break
			except socket.timeout:
				break
				
			i = 0
			while i < len(chunk):
				byte = chunk[i]
				if byte == IAC:
					i += 1
					if i >= len(chunk):
						break
					cmd = chunk[i]
					if cmd in (DO, DONT, WILL, WONT):
						i += 1
						if i >= len(chunk):
							break
						option = chunk[i]
						telnet_negotiate(s, cmd, option)
					elif cmd == SB:
						in_sb = True
					elif cmd == SE:
						in_sb = False
					i += 1
					continue
				if in_sb:
					i += 1
					continue
				buffer.append(byte)
				i += 1

			if b"login" in buffer.lower() or b"password" in buffer.lower():
				break
				
		print_banner("Port 23 (Telnet) is open")
		print(buffer.decode(errors="ignore"))
		print_footer()
		s.close()
	except Exception:
		pass


def encode_domain(domain):
	"""Encode domain name for DNS query."""
	parts = domain.split(".")
	return b"".join(bytes([len(part)]) + part.encode() for part in parts) + b"\x00"


def build_dns_query(domain, qtype=1, qclass=1):
	"""Build DNS query packet."""
	tid = random.randint(0, 0xFFFF)
	flags = 0x0100
	header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
	qname = encode_domain(domain)
	question = qname + struct.pack(">HH", qtype, qclass)
	return header + question, tid


def send_dns_query(ip, domain="example.com"):
	"""Send DNS query and return response."""
	packet, tid = build_dns_query(domain)
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.settimeout(3)
	try:
		s.sendto(packet, (ip, 53))
		data, _ = s.recvfrom(512)
	except (socket.timeout, OSError):
		return False, None
	finally:
		s.close()

	if data[:2] == struct.pack(">H", tid) and (data[2] & 0x80):
		return True, data
	else:
		return False, None


def extract_first_txt(data, question_len):
	"""Extract first TXT record from DNS response."""
	ans_start = 12 + question_len
	if ans_start + 12 > len(data):
		return None
	rdata_len = struct.unpack(">H", data[ans_start + 10: ans_start + 12])[0]
	rdata_off = ans_start + 12
	if rdata_off + rdata_len > len(data) or rdata_len == 0:
		return None
	txt_len = data[rdata_off]
	return data[rdata_off + 1: rdata_off + 1 + txt_len].decode(errors="ignore")


def detect_dns_service(ip):
	"""Detect DNS service and try to get version information."""
	ok, _ = send_dns_query(ip)
	if not ok:
		return

	version_packet, tid = build_dns_query("version.bind", qtype=16, qclass=3)
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.settimeout(3)
	try:
		s.sendto(version_packet, (ip, 53))
		data, _ = s.recvfrom(512)
	except Exception:
		print_banner("Port 53 (DNS) is open")
		print("DNS version not disclosed")
		print_footer()
		return
	finally:
		s.close()

	if not (data[:2] == struct.pack(">H", tid) and (data[2] & 0x80)):
		return

	qlen = len(encode_domain("version.bind")) + 4
	banner = extract_first_txt(data, qlen)
	print_banner("Port 53 (DNS) is open")
	if banner:
		print(f"DNS software banner: {banner}")
	else:
		print("DNS service detected but version not disclosed")
	print_footer()


def https_grabber(host):
	"""Grab HTTPS certificate and response information."""
	context = ssl.create_default_context()
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(5)
		s.connect((host, 443))
		ss = context.wrap_socket(s, server_hostname=host)
		cert = ss.getpeercert()
		
		print_banner("Port 443 (HTTPS) is open")
		print("TLS version:", ss.version())
		print("Certificate Subject:", cert.get('subject'))
		print("Certificate Issuer:", cert.get('issuer'))
		print("Valid From:", cert.get('notBefore'))
		print("Valid To:", cert.get('notAfter'))
		print()

		request = (
			f"GET / HTTP/1.1\r\n"
			f"Host: {host}\r\n"
			f"User-Agent: Mozilla/5.0 (NetworkGrabber/1.0)\r\n"
			f"Connection: close\r\n"
			f"\r\n"
		)
		ss.send(request.encode())
		response = b""
		while True:
			try:
				chunk = ss.recv(1024)
				if not chunk:
					break
				response += chunk
			except Exception:
				break
		print("HTTP response over TLS:")
		print(response.decode(errors="ignore"))
		print_footer()
		ss.close()
		s.close()
	except Exception:
		pass


def imaps_grabber(host):
	"""Grab IMAPS banner information."""
	try:
		context = ssl.create_default_context()
		context.check_hostname = False
		context.verify_mode = ssl.CERT_NONE
		
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(5)
		s.connect((host, 993))
		ss = context.wrap_socket(s, server_hostname=host)
		
		response = b""
		ss.settimeout(5)
		for _ in range(3):
			try:
				data = ss.recv(1024)
				if not data:
					break
				response += data
			except socket.timeout:
				break
				
		if response:
			print_banner("Port 993 (IMAPS) is open")
			print(response.decode(errors="ignore"))
			print_footer()
			
		ss.close()
		s.close()
	except Exception:
		pass


def pop3s_grabber(host):
	"""Grab POP3S banner information."""
	try:
		context = ssl.create_default_context()
		context.check_hostname = False
		context.verify_mode = ssl.CERT_NONE
		
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(5)
		s.connect((host, 995))
		ss = context.wrap_socket(s, server_hostname=host)
		
		response = b""
		ss.settimeout(5)
		
		for _ in range(3):
			try:
				data = ss.recv(1024)
				if not data:
					break
				response += data
			except socket.timeout:
				break
					
		if response:
			print_banner("Port 995 (POP3S) is open")
			print(response.decode(errors="ignore"))
			print_footer()
			
		ss.close()
		s.close()
	except Exception:
		pass


def tftp_grabber(host, filename="test.txt", mode="octet"):
	"""Grab TFTP service information."""
	packet = b"\x00\x01"
	packet += filename.encode() + b"\x00"
	packet += mode.encode() + b"\x00"
	
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.settimeout(3)
	
	try:
		s.sendto(packet, (host, 69))
		data, addr = s.recvfrom(516)
		print_banner("Port 69 (TFTP) is open")
		print(data[:100].decode(errors="ignore"))
		print_footer()
		s.close()
	except socket.timeout:
		pass


def kerberos_grabber(host):
	"""Grab Kerberos service information."""
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(3)
		s.connect((host, 88))
		
		pkt_len = len(RAW_AS_REQ)
		s.sendall(pkt_len.to_bytes(4, "big") + RAW_AS_REQ)
		
		response = s.recv(1024)
		print_banner("Port 88 (Kerberos) is open")
		print(response.hex())
		print_footer()
		s.close()
	except Exception:
		pass


def ntp_grabber(host):
	"""Grab NTP service information."""
	ntp_packet = b"\x1b" + 47 * b"\0"
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.settimeout(3)
	
	try:
		s.sendto(ntp_packet, (host, 123))
		data, _ = s.recvfrom(1024)
		if data:
			print_banner("Port 123 (NTP) is open")
			print(data.hex())
			print_footer()
	except Exception:
		pass


def build_netbios_name(name="*"):
	"""Build NetBIOS name for query."""
	name = name.ljust(15) + "\x00"
	encoded = b""
	
	for c in name:
		b = ord(c)
		high_nibble = (b >> 4) & 0x0F
		low_nibble = b & 0x0F
		encoded += bytes([high_nibble + ord("A"), low_nibble + ord("A")])
	return encoded


def build_netbios_name_query_packet(name="*"):
	"""Build NetBIOS name query packet."""
	tid = random.randint(0, 0xFFFF)
	flags = 0x0010
	qdcount = 1
	ancount = 0
	nscount = 0
	arcount = 0
	
	header = struct.pack(">HHHHHH", tid, flags, qdcount, ancount, nscount, arcount)
	qname = b"\x20" + build_netbios_name(name) + b"\x00"
	question = struct.pack(">HH", 0x0020, 0x0001)
	
	return header + qname + question


def netbios_grabber(host, name="*"):
	"""Grab NetBIOS service information."""
	packet = build_netbios_name_query_packet(name)
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.settimeout(3)
	
	try:
		s.sendto(packet, (host, 137))
		data, addr = s.recvfrom(1024)
		print_banner("Port 137 (NetBIOS) is open")
		print(data.hex())
		print(data.decode(errors="ignore"))
		print_footer()
		s.close()
	except Exception:
		pass


def build_ldap_bind_request():
	"""Build LDAP bind request packet."""
	message_id = b"\x02\x01\x01"
	version = b"\x02\x01\x03"

	dn = b"cn=read-only-admin,dc=example,dc=com"
	dn_field = b"\x04" + bytes([len(dn)]) + dn

	password = b"password"
	pw_field = b"\x80" + bytes([len(password)]) + password

	bind_request = b"\x60" + bytes([len(version + dn_field + pw_field)]) + version + dn_field + pw_field
	ldap_message = b"\x30" + bytes([len(message_id + bind_request)]) + message_id + bind_request
	return ldap_message


def ldap_grabber(host):
	"""Grab LDAP service information."""
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(3)
		s.connect((host, 389))
		s.send(build_ldap_bind_request())
		data = s.recv(1024)
		if data:
			print_banner("Port 389 (LDAP) is open")
			print(data.hex())
			print(data.decode(errors="ignore"))
			print_footer()
		s.close()
	except Exception:
		pass


def ldaps_grabber(host):
	"""Grab LDAPS service information."""
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(5)
		s.connect((host, 636))
		
		context = ssl.create_default_context()
		context.check_hostname = False
		context.verify_mode = ssl.CERT_NONE
		ss = context.wrap_socket(s, server_hostname=host)

		print_banner("Port 636 (LDAPS) is open")
		print("TLS version:", ss.version())
		print("Cipher:", ss.cipher())
		print("Certificate:", ss.getpeercert())

		ss.send(build_ldap_bind_request())
		data = ss.recv(1024)
		if data:
			print("[+] Got response from LDAPS")
			print(data.hex())
			print(data.decode(errors="ignore"))
		print_footer()
		ss.close()
	except Exception:
		pass


def snmp_getnext_grabber(host, community='public', oid='1.3.6.1.2.1.1.1.0'):
	"""Grab SNMP service information using GET request."""
	def encode_length(length):
		if length < 0x80:
			return bytes([length])
		result = []
		while length > 0:
			result.insert(0, length & 0xFF)
			length >>= 8
		return bytes([0x80 | len(result)]) + bytes(result)

	def encode_oid(oid):
		parts = [int(x) for x in oid.split('.')]
		result = bytes([40 * parts[0] + parts[1]])
		for part in parts[2:]:
			if part < 128:
				result += bytes([part])
			else:
				temp = []
				while part:
					temp.insert(0, (part & 0x7F) | 0x80)
					part >>= 7
				temp[-1] &= 0x7F
				result += bytes(temp)
		return b'\x06' + encode_length(len(result)) + result

	def encode_string(s):
		b = s.encode()
		return b'\x04' + encode_length(len(b)) + b

	def encode_null():
		return b'\x05\x00'

	def encode_integer(i):
		b = []
		while i:
			b.insert(0, i & 0xFF)
			i >>= 8
		if not b:
			b = [0]
		if b[0] & 0x80:
			b.insert(0, 0x00)
		return b'\x02' + encode_length(len(b)) + bytes(b)

	def build_get_packet(community, request_id, oid):
		encoded_oid = encode_oid(oid)
		varbind = b'\x30' + encode_length(len(encoded_oid + encode_null())) + encoded_oid + encode_null()
		varbind_list = b'\x30' + encode_length(len(varbind)) + varbind
		pdu = b'\xa0' + encode_length(len(encode_integer(request_id) + encode_integer(0) + encode_integer(0) + varbind_list)) \
			  + encode_integer(request_id) + encode_integer(0) + encode_integer(0) + varbind_list
		snmp = b'\x30' + encode_length(len(encode_integer(0) + encode_string(community) + pdu)) \
			   + encode_integer(0) + encode_string(community) + pdu
		return snmp

	request_id = random.randint(0, 0x7FFFFFFF)
	packet = build_get_packet(community, request_id, oid)

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.settimeout(3)
		s.sendto(packet, (host, 161))
		data, _ = s.recvfrom(4096)

		print_banner("Port 161 (SNMP) is open")
		print("[*] Raw Response (hex):")
		print(data.hex())
		print("\n[*] ASCII Response (best-effort):")
		try:
			print(data.decode(errors="ignore"))
		except Exception:
			print("[!] Failed to decode ASCII.")
		print_footer()
		s.close()
	except socket.timeout:
		pass
	except Exception as e:
		print(f"[!] Error: {e}")


def build_startup_packet(user="postgres"):
	"""Build PostgreSQL startup packet."""
	protocol_version = 0x00030000
	params = f"user\0{user}\0".encode("utf-8") + b"\0"
	length = 4 + 4 + len(params)
	packet = struct.pack("!I", length) + struct.pack("!I", protocol_version) + params
	return packet


def postgresql_grabber(host):
	"""Grab PostgreSQL service information."""
	packet = build_startup_packet()

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(3)
		s.connect((host, 5432))
		s.sendall(packet)
		response = s.recv(4096)
		if response:
			print_banner("Port 5432 (PostgreSQL) is open")
			print(response.hex())
			print()
			print(response.decode(errors="ignore"))
			print_footer()
		s.close()
	except Exception:
		pass


def hexdump(src, length=16):
	"""Create a hexdump representation of binary data."""
	result = []
	for i in range(0, len(src), length):
		s = src[i:i+length]
		hexa = ' '.join(f"{b:02x}" for b in s)
		text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in s)
		result.append(f"{i:04x}  {hexa:<48}  {text}")
	return '\n'.join(result)


def smb_grabber(host):
	"""Grab SMB service information."""
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(3)
		s.connect((host, 445))
		s.send(b"\x81\x00\x00\x44" + b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + b"\x00" * 60)
		data = s.recv(1024)
		print_banner("Port 445 (SMB) is open")
		print(data.hex())
		print(data.decode(errors="ignore"))
		print(hexdump(data))
		print_footer()
		s.close()
	except Exception:
		pass


def rdp_grabber(host):
	"""Grab RDP service information."""
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(3)
		s.connect((host, 3389))
		packet = bytes.fromhex("030000130ee000000000000100080003000000")
		s.send(packet)
		data = s.recv(1024)
		print_banner("Port 3389 (RDP) is open")
		print(data.hex())
		print(data.decode(errors="ignore"))
		print_footer()
		s.close()
	except Exception:
		pass


def mssql_grabber(host):
	"""Grab MSSQL service information."""
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(3)
		s.connect((host, 1433))

		packet = bytes.fromhex(
			"12 01 00 34 00 00 00 00"
			"00 00 1a 00 06 01 00 20 01 02 00 01 02"
			"03 00 01 03 04 00 01 04 ff 08 00 00 00"
			"00 00 00 00 00 00 00 00"
		)

		s.send(packet)
		data = s.recv(1024)

		print_banner("Port 1433 (MSSQL) is open")
		print("[*] Raw Response (hex):")
		print(data.hex())
		print("\n[*] ASCII Response (best-effort):")
		print(data.decode(errors="ignore"))
		print_footer()
		s.close()
	except Exception:
		pass


def http_8080_grabber(host):
	"""Grab HTTP banner from alternate port 8080."""
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(3)
		s.connect((host, 8080))
		s.send(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
		response = b""
		while True:
			chunk = s.recv(1024)
			if not chunk:
				break
			response += chunk
		print_banner("Port 8080 (HTTP-alt) is open")
		print(response.decode(errors="ignore"))
		print_footer()
		s.close()
	except Exception:
		pass

