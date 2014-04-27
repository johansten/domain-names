
import sys

import random
import string

import hashlib
import os.path
import cPickle as pickle

import socket
import select

#------------------------------------------------------------------------------
#
#   http://www.stephanboyer.com/post/65/generating-domain-names-with-markov-chains
#
#------------------------------------------------------------------------------

# sample a probability mass function
#   pmf: dict mapping elements to probabilities
def sample(pmf):
	sample = random.random()
	cdf = 0.0
	for e in pmf:
		cdf += pmf[e]
		if cdf >= sample:
			return e
	return random.choice(pmf.keys())

#------------------------------------------------------------------------------

# compute a conditional probability mass function
#   pmf:       dict mapping elements to probabilities
#   condition: boolean-valued function to condition on
def conditional(pmf, condition):
	total_mass = 0.0
	cond = {}
	for e in pmf:
		if condition(e):
			cond[e] = pmf[e]
			total_mass += pmf[e]
	for e in cond:
		cond[e] /= total_mass
	return cond

#------------------------------------------------------------------------------

class Markov:

	# 	n = 5 # this is the "n" in n-grams, try adjusting this for different results
	#	transitions = {} # keys are n-grams, values are dicts mapping subsequent n-grams to probabilities
	#	prefix_frequencies = {} # prefixes are n-grams that appear at the beginning of words

	@classmethod
	def unpickle(cls, filename):
		f = open(filename, 'rb')
		cls.n = pickle.load(f)
		cls.transitions = pickle.load(f)
		cls.prefix_frequencies = pickle.load(f)
		f.close()

	@classmethod
	def pickle(cls, filename):
		f = open(filename, 'wb')
		pickle.dump(cls.n, f, -1)
		pickle.dump(cls.transitions, f, -1)
		pickle.dump(cls.prefix_frequencies, f, -1)
		f.close()

	@classmethod
	def create(cls, dictionary, n):

		transitions = {}
		frequencies = {} # keys are n-grams, values are normalized frequencies [0, 1] of occurrence in the wordlist

		# get a list of words with only ASCII characters, and surround them with ^ and $ to demarcate the word boundaries
		words = [w.strip().lower() for w in dictionary]
		words = ["^" + w + "$" for w in words if w != "" and all([c in string.ascii_lowercase for c in w])]

		# construct a discrete-time markov chain of n-grams
		for word in words:
			for i in range(len(word) + 1 - n):
				gram = word[i : i + n]
				if gram in frequencies:
					frequencies[gram] += 1
				else:
					frequencies[gram] = 1

			for i in range(len(word) - n):
				gram = word[i : i + n]
				next = word[i + 1 : i + n + 1]
				if gram not in transitions:
					transitions[gram] = {}
				if next in transitions[gram]:
					transitions[gram][next] += 1
				else:
					transitions[gram][next] = 1

		for gram in frequencies:
			frequencies[gram] /= float(len(frequencies))

		for gram in transitions:
			total = 0
			for next in transitions[gram]:
				total += transitions[gram][next]
			for next in transitions[gram]:
				transitions[gram][next] /= float(total)

		cls.n = n
		cls.transitions = transitions
		cls.prefix_frequencies = conditional(frequencies, lambda x: x[0] == "^")

	# generate a new letter according to the markov chain (make sure len(word) >= n)
	@classmethod
	def evolve(cls, word):
		# grab the last n characters and make sure the n-gram is in our model
		gram = word[-cls.n:]
		if gram not in cls.transitions:
			# uh oh, just return a random letter to keep things moving
			return random.choice(string.ascii_lowercase + "$")

		# sample the n-grams that we can transition to
		return sample(cls.transitions[gram])[-1:]

	# generate a word according to the markov chain
	@classmethod
	def gen_word(cls):
		# start with a prefix
		word = sample(cls.prefix_frequencies)

		# wait until the markov chain adds a terminator to the word
		while word[-1] != "$":
			# generate a new letter and append it to the word
			word += cls.evolve(word)

			# optional: sometimes domains are multiple word-like lexemes concatenated together
			if word[-1] == "$" and random.random() > 0.7 and len(word) < 8:
				word += sample(cls.prefix_frequencies)

		# remove the boundary markers and return the word
		return word.replace("^", "").replace("$", "")

	@staticmethod
	def initialize(dictionary_name, n = 5):

		m = hashlib.md5()
		dictionary = open(dictionary_name).readlines()
		for line in dictionary:
			m.update(line)
		filename = "%s-%d.dat" % (m.hexdigest(), n)

		if os.path.exists(filename):
			Markov.unpickle(filename)
		else:
			Markov.create(dictionary, n)
			Markov.pickle(filename)


def get_domain_candidate():
	# generate a few domains and pick the smallest
	return sorted([Markov.gen_word() for i in range(3)], key=lambda x: len(x))[0] + '.com'


class ConnHandler:

	def __init__(self, num_connections):

		self.read_list  = []
		self.write_list = []

		for n in xrange(num_connections):
			c = Connection(self)
			self.write_list.append(c)

	def run(self):

		while True:

			ready = select.select(self.read_list, self.write_list, [])
			for c in ready[0]:
				c.read(self)

			for c in ready[1]:
				c.write(self)


class Connection:

	# whois.verisign-grs.com: '199.7.x.74'

	ips = [
		48, 49,
		50, 51, 52, 53, 55, 56, 57, 58, 59,
		61,
		71, 73, 74,
	]

	def __init__(self, handler):
		self.init(handler)

	def init(self, handler):

		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		ip = '199.7.%d.74' % random.choice(Connection.ips)
		s.setblocking(0)

		try:
			s.connect((ip, 43))
		except socket.error:
			pass

		self.domain = get_domain_candidate()
		self.socket = s

	def fileno(self):
		return self.socket.fileno()

	def write(self, handler):
		self.socket.send(self.domain + "\r\n")
		self.read1 = True

		handler.write_list.remove(self)
		handler.read_list.append(self)

	def read(self, handler):

		if self.read1:
			self.socket.recv(189)
			self.read1 = False

		else:
			data = self.socket.recv(16)
			if data.startswith('\nNo match for "'):
				print self.domain

			self.socket.close()
			self.init(handler)

			handler.read_list.remove(self)
			handler.write_list.append(self)

def main():

	Markov.initialize("/usr/share/dict/words", 5)

	num_connections = 5
	handler = ConnHandler(num_connections)

	try:
		handler.run()
	except (KeyboardInterrupt, select.error):
		sys.stdout.write("\b\b")

#------------------------------------------------------------------------------

if __name__ == '__main__':
	main()
