#!/usr/bin/python
# Bootstrap Samba and run a number of tests against it.
# Copyright (C) 2005-2007 Jelmer Vernooij <jelmer@samba.org>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

__all__ = ['setup_dir', 'setup_pcap', 'set_default_iface']

import os
import shutil

def setup_dir(dir, pcap):
    """Setup a socket wrapper directory.

    :param dir: Socket wrapper directory (None if socket wrapper should be
        disabled)
    :param pcap: Whether to generate pcap files
    :return: The socket wrapper directory
    """
    pcap_dir = None

    if dir is not None:
        if os.path.isdir(dir):
            shutil.rmtree(dir)
        os.mkdir(dir, 0777)

        if pcap:
            pcap_dir = os.path.join(dir, "pcap")

            if os.path.isdir(pcap_dir):
                shutil.rmtree(pcap_dir)
            os.mkdir(pcap_dir, 0777)

    if pcap_dir is not None:
        os.environ["SOCKET_WRAPPER_PCAP_DIR"] = pcap_dir
    else:
        del os.environ["SOCKET_WRAPPER_PCAP_DIR"]

    if dir is not None:
        os.environ["SOCKET_WRAPPER_DIR"] = dir
    else:
        del os.environ["SOCKET_WRAPPER_DIR"]

    return dir

def setup_pcap(pcap_file):
    os.environ["SOCKET_WRAPPER_PCAP_FILE"] = pcap_file

def set_default_iface(i):
    os.environ["SOCKET_WRAPPER_DEFAULT_IFACE"] = str(i)
