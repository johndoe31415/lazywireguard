#	lazywireguard - Quick setup of Wireguard keys and routing table
#	Copyright (C) 2021-2021 Johannes Bauer
#
#	This file is part of lazywireguard.
#
#	lazywireguard is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	lazywireguard is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with lazywireguard; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>

import re

class CIDR():
	_IPv4_RE = re.compile(r"(?P<no0>\d{1,3})\.(?P<no1>\d{1,3})\.(?P<no2>\d{1,3})\.(?P<no3>\d{1,3})")
	_CIDR_RE = re.compile(r"(?P<no0>\d{1,3})\.(?P<no1>\d{1,3})\.(?P<no2>\d{1,3})\.(?P<no3>\d{1,3})\s*/\s*(?P<subnet>\d{1,2})")

	def __init__(self, network_str):
		match = self._CIDR_RE.fullmatch(network_str)
		if match is None:
			raise Exception("Invalid CIDR: %s" % (network_str))
		match = match.groupdict()

		self._taken = set()
		self._subnet = int(match["subnet"])
		self._net = sum(value << (8 * index) for (index, value) in enumerate(reversed(list(int(match["no" + str(i)]) for i in range(4)))))
		self._last_ip = self._net + (1 << self._subnet) - 2
		self._mask = ((1 << self._subnet) - 1) << (32 - self._subnet)
		if (self._net & ~self._mask) != 0:
			net = self._net & self._mask
			raise Exception("Invalid network: %s / %s -- did you mean %s/%d" % (self._int2ipv4(self._net), self._int2ipv4(self._mask), self._int2ipv4(net), self._subnet))
		self._index = 0

	@property
	def net(self):
		return self._int2ipv4(self._net)

	@property
	def subnet(self):
		return self._subnet

	@staticmethod
	def _int2ipv4(intval):
		return "%d.%d.%d.%d" % ((intval >> 24) & 0xff, (intval >> 16) & 0xff, (intval >> 8) & 0xff, (intval >> 0) & 0xff)

	def claim(self, address):
		self._taken.add(self.plausibilize(address))

	def plausibilize(self, address):
		match = self._IPv4_RE.fullmatch(address)
		if match is None:
			raise Exception("Invalid IPv4 address: %s" % (address))
		match = match.groupdict()
		int_address = sum(value << (8 * index) for (index, value) in enumerate(reversed(list(int(match["no" + str(i)]) for i in range(4)))))
		if (int_address & self._mask) != self._net:
			raise Exception("IPv4 address %s does not fall in the %s/%d subnet." % (address, self.net, self.subnet))
		return int_address

	def next_addr(self):
		while True:
			self._index += 1
			int_ip = self._net + self._index
			if int_ip > self._last_ip:
				raise Exception("Out of IPv4 addresses. Increase subnet size or reduce number of hosts.")
			if int_ip not in self._taken:
				return self._int2ipv4(int_ip)
