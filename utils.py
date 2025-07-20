import queue
import socket

def list_builder(max_num):
	"""Build a queue containing numbers from 1 up to max_num inclusive."""
	q = queue.Queue()
	for i in range(1, max_num + 1):
		q.put(i)
	return q
	
def is_valid_host(host):
	"""Check if the host is a valid IP address or resolvable domain name."""
	try:
		socket.gethostbyname(host)
		return True
	except socket.error:
		return False
