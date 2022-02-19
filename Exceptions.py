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

class AssignmentException(Exception): pass
class NetworkOverlapException(Exception): pass
class DuplicateNameException(Exception): pass
class InvalidFixedAddressException(Exception): pass
class RuleParseException(Exception): pass
class NoSuchGroupException(Exception): pass
class NoSuchHostException(Exception): pass
