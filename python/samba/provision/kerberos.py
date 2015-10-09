# Unix SMB/CIFS implementation
#
# Backend code for provisioning a Samba AD server
#
# Copyright (c) 2015      Andreas Schneider <asn@samba.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from samba.provision.kerberos_implementation import (
    kdb_modules_dir,
    kdc_default_config_dir)
from samba import _glue
import os

def make_kdcconf(realm, domain, kdcconfdir, logdir):

    if _glue.is_heimdal_built:
        return

    # Do nothing if kdc.conf has been set
    if 'KRB5_KDC_PROFILE' in os.environ:
        return

    # We are in selftest
    if 'SAMBA_SELFTEST' in os.environ and 'MITKRB5' in os.environ:
        return

    # If not specified use the default
    if kdcconfdir is None:
        kdcconfdir = kdc_default_config_dir

    kdcconf = "%s/kdc.conf" % kdcconfdir

    assert domain is not None
    domain = domain.upper()

    assert realm is not None
    realm = realm.upper()

    f = open(kdcconf, 'w')
    try:
        f.write("[kdcdefaults]\n")

        f.write("\tkdc_ports = 88\n")
        f.write("\tkdc_tcp_ports = 88\n")
        f.write("\tkadmind_port = 464\n")
        f.write("\n")

        f.write("[realms]\n")

        f.write("\t%s = {\n" % realm)
        f.write("\t}\n")
        f.write("\n")

        f.write("\t%s = {\n" % realm.lower())
        f.write("\t}\n")
        f.write("\n")

        f.write("\t%s = {\n" % domain)
        f.write("\t}\n")
        f.write("\n")

        f.write("[dbmodules]\n")

        f.write("\tdb_modules_dir = %s\n" % kdb_modules_dir)
        f.write("\n")

        f.write("\t%s = {\n" % realm)
        f.write("\t\tdb_library = samba\n")
        f.write("\t}\n")
        f.write("\n")

        f.write("\t%s = {\n" % realm.lower())
        f.write("\t\tdb_library = samba\n")
        f.write("\t}\n")
        f.write("\n")

        f.write("\t%s = {\n" % domain)
        f.write("\t\tdb_library = samba\n")
        f.write("\t}\n")
        f.write("\n")

        f.write("[logging]\n")

        f.write("\tkdc = FILE:%s/mit_kdc.log\n" % logdir)
        f.write("\tadmin_server = FILE:%s/mit_kadmin.log\n" % logdir)
        f.write("\n")
    finally:
        f.close()
