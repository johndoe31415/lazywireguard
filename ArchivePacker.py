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

import os
import tarfile

class ArchivePacker():
	def __init__(self, wggen):
		self._wggen = wggen

	def _create_tar_gz(self, destination_filename, included_directories):
		with tarfile.open(destination_filename, "w|gz") as f:
			for dirname in included_directories:
				arcname = os.path.basename(dirname)
				f.add(dirname, arcname = arcname)

	def _create_host_archive(self, hostname):
		outdir = self._wggen.get_output_directory(hostname)
		return self._create_tar_gz(outdir + ".tar.gz", [ outdir ])

	def create_all_host_archives(self):
		for host in self._wggen.hosts:
			self._create_host_archive(host["name"])

	def create_group_archives(self):
		for (group_name, members) in self._wggen.groups:
			targz_filename = self._wggen.get_output_directory(group_name) + ".tar.gz"
			outdirs = [ self._wggen.get_output_directory(host["name"]) for host in members ]
			outdirs.sort()
			return self._create_tar_gz(targz_filename, outdirs)
