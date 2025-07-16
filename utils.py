import queue

def list_builder(max_num):
	"""Build a queue containing numbers from 1 up to max_num inclusive."""
	q = queue.Queue()
	for i in range(1, max_num + 1):
		q.put(i)
	return q
