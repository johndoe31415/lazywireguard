#	lazywireguard - Quick setup of Wireguard keys and routing table
#	Copyright (C) 2021-2022 Johannes Bauer
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

import json
import itertools
import ipaddress
from AddressAssigner import AddressAssigner
from ConfigGenerator import ConfigGenerator
from Exceptions import NetworkOverlapException, DuplicateNameException, InvalidFixedAddressException

class WireguardGenerator():
	def __init__(self, args):
		self._args = args
		with open(self._args.config_file) as f:
			self._config = json.load(f)
		self._networks = [ AddressAssigner.parse(network) for network in self._config["topology"]["networks"] ]
		self._routed = [ ipaddress.ip_network(network) for network in self._config["topology"].get("routed", [ ]) ]
		self._check_networks_have_no_overlap()
		self._check_no_duplicate_name()
		self._assign_server_client_fields()
		self._reserve_fixed_addresses()
		self._check_duplicate_fixed_addresses()
		self._assign_addresses()

	@property
	def config(self):
		return self._config

	@property
	def networks(self):
		return self._networks

	@property
	def routed(self):
		return self._routed

	def _get_network_index(self, address):
		for (index, net) in enumerate(self._networks):
			if address in net.root_network:
				return index
		return None

	def _check_networks_have_no_overlap(self):
		checked_networks = [ ("network", assigner.root_network) for assigner in self._networks ]
		checked_networks += [ ("routed network", network) for network in self._routed ]

		for ((text1, net1), (text2, net2)) in itertools.combinations(checked_networks, 2):
			if net1.overlaps(net2):
				raise NetworkOverlapException("Networks may not overlap, but %s %s overlaps %s %s." % (net1, text1, net2, text2))

	def _check_no_duplicate_name(self):
		seen_names = set()
		for host in self.hosts:
			if host["name"] in seen_names:
				raise DuplicateNameException("Hostname '%s' used twice. Must be unique." % (host["name"]))

	def _assign_server_client_fields(self):
		self.concentrator["server"] = True
		for client in self.clients:
			client["server"] = False

	def _reserve_fixed_address(self, address):
		address = ipaddress.ip_address(address)
		for network in self._networks:
			network.exclude_address(address)
		return address

	def _reserve_fixed_addresses(self):
		for host in self.hosts:
			addresses = [ ]
			if "address" in host:
				if isinstance(host["address"], str):
					addresses.append(self._reserve_fixed_address(host["address"]))
				else:
					for address in host["address"]:
						addresses.append(self._reserve_fixed_address(address))
				del host["address"]
			host["fixed_address"] = addresses

	def _check_duplicate_fixed_addresses(self):
		seen = set()
		for host in self.hosts:
			for address in host["fixed_address"]:
				if address in seen:
					raise InvalidFixedAddressException("Host '%s' has invalid address %s which has been assigned to another host already." % (host["name"], address))
				seen.add(address)

	def _assign_host_address(self, host):
		assigned = [ None ] * len(self._networks)
		for address in host["fixed_address"]:
			index = self._get_network_index(address)
			if index is None:
				raise InvalidFixedAddressException("Host '%s' has invalid address %s which falls into none of the networks." % (host["name"], address))
			if assigned[index] is not None:
				raise InvalidFixedAddressException("Host '%s' has already duplicate assignment with address %s; the same network has already been specified." % (host["name"], address))
			assigned[index] = address

		for (index, assigned_address) in enumerate(assigned):
			if assigned_address is None:
				assigned[index] = self._networks[index].assign()
		host["assigned"] = assigned

	def _assign_addresses(self):
		for host in self.hosts:
			self._assign_host_address(host)

	@property
	def concentrator(self):
		return self._config["concentrator"]

	@property
	def clients(self):
		yield from self._config["clients"]

	@property
	def hosts(self):
		yield self.concentrator
		yield from self.clients

	def _get_output_directory(self, host):
		if self._args.output_dir is None:
			return self._config["topology"]["domainname"] + "/" + host["name"]
		else:
			return self._args.output_dir + "/" + host["name"]

	def run(self):
		# First create all keys (so the public keys for all configs are known)
		generators = [ ConfigGenerator(self, host, self._get_output_directory(host)) for host in self.hosts ]
		for generator in generators:
			generator.generate_keys()

		# Then, create all configuration files
		for generator in generators:
			generator.generate()
