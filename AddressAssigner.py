import ipaddress

class AssignmentException(Exception): pass

class AddressAssigner():
	def __init__(self, root_network):
		self._root_network = root_network
		self._assignable = [ self._root_network ]
		self.exclude_address(self._root_network.network_address)
		self.exclude_address(self._root_network.broadcast_address)
		self._net_index = 0
		self._addr_index = 0

	def assign(self):
		try:
			address = self._assignable[self._net_index][self._addr_index]
		except IndexError:
			self._addr_index = 0
			self._net_index += 1
			try:
				address = self._assignable[self._net_index][self._addr_index]
			except IndexError:
				raise AssignmentException("Ran out of IP addresses for network %s" % (self._root_network))
		self._addr_index += 1
		return address

	def exclude_address(self, address):
		return self.exclude_net(ipaddress.ip_network(address))

	def exclude_net(self, network):
		still_assignable = [ ]
		for assignable in self._assignable:
			try:
				still_assignable += assignable.address_exclude(network)
			except ValueError:
				# Non overlap
				still_assignable.append(assignable)
		self._assignable = still_assignable
		self._assignable.sort()

	@classmethod
	def parse(cls, definition):
		print(definition)
		root_network = ipaddress.ip_network(definition["network"])
		assigner = cls(root_network)
		if "exclude" in definition:
			for exclude_def in definition["exclude"]:
				if isinstance(exclude_def, list):
					# start, end
					exclude_start = ipaddress.ip_address(exclude_def[0])
					exclude_end = ipaddress.ip_address(exclude_def[1])
					exclude_nets = ipaddress.summarize_address_range(exclude_start, exclude_end)
				else:
					exclude_nets = [ ipaddress.ip_network(exclude_def) ]
				for exclude_net in exclude_nets:
					assigner.exclude_net(exclude_net)

		for i in range(100000):
			print(assigner.assign())

		return assigner
