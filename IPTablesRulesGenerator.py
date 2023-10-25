#	lazywireguard - Quick setup of Wireguard keys and routing table
#	Copyright (C) 2021-2023 Johannes Bauer
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
import ipaddress
import itertools
import collections
from CmdlineEscape import CmdlineEscape
from Exceptions import RuleParseException, NoSuchGroupException

class IPTablesRule():
	_RULE_SYNTAX = re.compile(r"(?P<lhs>[^\s]+)\s+(?P<arrow>(<-|->|<->|<=|=>|<=>))\s+(?P<rhs>[^\s]+)")
	_ParsedSide = collections.namedtuple("ParsedSide", [ "bind_interface", "networks" ])

	def __init__(self, wggen, rule_str):
		self._wggen = wggen
		self._rule_str = rule_str
		self._lhs = None
		self._rhs = None
		self._arrow = None
		self._parse_rule()

	@property
	def bidirectional(self):
		return self._arrow in ("<->", "<=>")

	@property
	def only_wg_interface(self):
		return self._arrow in ("<->", "->", "<-")

	def _parse_rule(self):
		match = self._RULE_SYNTAX.fullmatch(self._rule_str)
		if match is None:
			raise RuleParseException(f"Unable to parse routing rule: {self._rule_str}")
		match = match.groupdict()

		if match["arrow"] == "<-":
			(match["lhs"], match["arrow"], match["rhs"]) = (match["rhs"], "->", match["lhs"])
		elif match["arrow"] == "<=":
			(match["lhs"], match["arrow"], match["rhs"]) = (match["rhs"], "=>", match["lhs"])

		self._lhs = self._resolve(match["lhs"])
		self._arrow = match["arrow"]
		self._rhs = self._resolve(match["rhs"])

	def _resolve(self, symbol):
		if symbol == "*":
			return self._ParsedSide(bind_interface = False, networks = [ None ])
		elif symbol.startswith("!"):
			# Explicit address or network, take as-is
			network = ipaddress.ip_network(symbol[1:])
			return self._ParsedSide(bind_interface = False, networks = [ network ])
		elif symbol.startswith("@"):
			# Whole group
			networks = [ ]
			group_name = symbol[1:]
			for member in self._wggen.get_group_members(group_name):
				networks += member["assigned"]
			return self._ParsedSide(bind_interface = True, networks = networks)
		else:
			return self._ParsedSide(bind_interface = True, networks = self._wggen.get_host(symbol)["assigned"])

	def _iptables_rule(self, src, dst, is_ipv4 = False, in_ifname = None, out_ifname = None, only_established = False):
		if is_ipv4:
			cmd = [ "iptables" ]
		else:
			cmd = [ "ip6tables" ]

		cmd += [ "-A", "FORWARD" ]
		if only_established:
			cmd += [ "-m", "state", "--state", "ESTABLISHED,RELATED" ]
		if in_ifname is not None:
			cmd += [ "-i", in_ifname ]
		if out_ifname is not None:
			cmd += [ "-o", out_ifname ]
		if src is not None:
			cmd += [ "-s", str(src) ]
		if dst is not None:
			cmd += [ "-d", str(dst) ]
		cmd += [ "-j", "ACCEPT" ]
		rule_text = self._rule_str if (not only_established) else f"only established: {self._rule_str}"
		cmd += [ "-m", "comment", "--comment", rule_text ]
		return cmd

	def _iptables_rules(self, ifname, src, dst, only_established = False):
		srcs = self._resolve_routing_target(src)
		dsts = self._resolve_routing_target(dst)
		for (ipsrc, ipdst) in itertools.product(srcs, dsts):
			yield self._iptables_rule(ifname, ipsrc, ipdst, only_established)

	def _generate_routing_table(self):
		host = self._config["concentrator"]
		ifname = host.get("ifname", "wg0")
		dirname = self.output_dir + "/" + host["name"]
		filename = f"{dirname}/iptables.sh"
		with open(filename, "w") as f:
			cle = CmdlineEscape()
			print("#!/bin/bash", file = f)
			for rule in self._config.get("route", [ ]):
				match = self._RULE_SYNTAX.fullmatch(rule)
				if match is None:
					raise Exception(f"Unable to parse routing rule: {rule}")
				match = match.groupdict()

				if match["arrow"] == "<-":
					(match["lhs"], match["arrow"], match["rhs"]) = (match["rhs"], "->", match["lhs"])

				uni_directional = (match["arrow"] == "->")
				if uni_directional:
					# Initial packets are okay, but we only route back estalibshed/related connections
					for rule in self._iptables_rules(ifname, match["lhs"], match["rhs"]):
						print(cle.cmdline(rule), file = f)
					for rule in self._iptables_rules(ifname, match["rhs"], match["lhs"], only_established = True):
						print(cle.cmdline(rule), file = f)
				else:
					print(cle.cmdline(self._iptables_rule(ifname, match["lhs"], match["rhs"])), file = f)
					print(cle.cmdline(self._iptables_rule(ifname, match["rhs"], match["lhs"])), file = f)

	def _iterate_ipversion_commands(self, is_ipv4, predicate):
		all_lhs = [ element for element in self._lhs.networks if predicate(element) ]
		all_rhs = [ element for element in self._rhs.networks if predicate(element) ]

		ifname = self._wggen.concentrator.get("ifname", "wg0")

		for (lhs, rhs) in itertools.product(all_lhs, all_rhs):
			if self.only_wg_interface:
				in_ifname = ifname
				out_ifname = ifname
			else:
				in_ifname = ifname if self._lhs.bind_interface else None
				out_ifname = ifname if self._rhs.bind_interface else None
			yield self._iptables_rule(src = lhs, dst = rhs, is_ipv4 = is_ipv4, in_ifname = in_ifname, out_ifname = out_ifname)
			yield self._iptables_rule(src = rhs, dst = lhs, is_ipv4 = is_ipv4, in_ifname = out_ifname, out_ifname = in_ifname, only_established = not self.bidirectional)

	def _iterate_commands(self):
		yield from self._iterate_ipversion_commands(is_ipv4 = True, predicate = lambda addr: (addr is None) or (addr.version == 4))
		yield from self._iterate_ipversion_commands(is_ipv4 = False, predicate = lambda addr: (addr is None) or (addr.version == 6))

	def generate(self, f):
		cle = CmdlineEscape()
		print(f"# {self._rule_str}", file = f)
		for command in self._iterate_commands():
			print(cle.cmdline(command), file = f)
		print(file = f)

class IPTablesRulesGenerator():
	def __init__(self, wggen):
		self._wggen = wggen

	def generate(self, filename):
		with open(filename, "w") as f:
			print("#!/bin/bash", file = f)
			for rule in self._wggen.routing_rules:
				parsed_rule = IPTablesRule(self._wggen, rule)
				parsed_rule.generate(f)
