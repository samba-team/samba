# Add/remove subnets to sites.
#
# Copyright (C) Catalyst.Net Ltd 2015
# Copyright Matthieu Patou <mat@matws.net> 2011
#
# Catalyst.Net's contribution was written by Douglas Bagnall
# <douglas.bagnall@catalyst.net.nz>.
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

import ldb
from ldb import FLAG_MOD_ADD, FLAG_MOD_REPLACE, LdbError
from . sites import SiteNotFoundException


class SubnetException(Exception):
    """Base element for Subnet errors"""
    pass


class SubnetNotFound(SubnetException):
    """The subnet requested does not exist."""
    pass


class SubnetAlreadyExists(SubnetException):
    """The subnet being added already exists."""
    pass


class SubnetInvalid(SubnetException):
    """The subnet CIDR is invalid."""
    pass


class SiteNotFound(SubnetException):
    """The site to be used for the subnet does not exist."""
    pass


def create_subnet(samdb, configDn, subnet_name, site_name):
    """Create a subnet and associate it with a site.

    :param samdb: A samdb connection
    :param configDn: The DN of the configuration partition
    :param subnet_name: name of the subnet to create (a CIDR range)
    :return: None
    :raise SubnetAlreadyExists: if the subnet to be created already exists.
    :raise SiteNotFound: if the site does not exist.
    """
    ret = samdb.search(base=configDn, scope=ldb.SCOPE_SUBTREE,
                       expression='(&(objectclass=Site)(cn=%s))' %
                       ldb.binary_encode(site_name))
    if len(ret) != 1:
        raise SiteNotFound('A site with the name %s does not exist' %
                           site_name)
    dn_site = ret[0].dn

    if not isinstance(subnet_name, str):
        raise SubnetInvalid("%s is not a valid subnet (not a string)" % subnet_name)

    dnsubnet = ldb.Dn(samdb, "CN=Subnets,CN=Sites")
    if dnsubnet.add_base(configDn) == False:
        raise SubnetException("dnsubnet.add_base() failed")
    if dnsubnet.add_child("CN=X") == False:
        raise SubnetException("dnsubnet.add_child() failed")
    dnsubnet.set_component(0, "CN", subnet_name)

    try:
        m = ldb.Message()
        m.dn = dnsubnet
        m["objectclass"] = ldb.MessageElement("subnet", FLAG_MOD_ADD,
                                              "objectclass")
        m["siteObject"] = ldb.MessageElement(str(dn_site), FLAG_MOD_ADD,
                                             "siteObject")
        samdb.add(m)
    except ldb.LdbError as e:
        (enum, estr) = e.args
        if enum == ldb.ERR_INVALID_DN_SYNTAX:
            raise SubnetInvalid("%s is not a valid subnet: %s" % (subnet_name, estr))
        elif enum == ldb.ERR_ENTRY_ALREADY_EXISTS:
            # Subnet collisions are checked by exact match only, not
            # overlapping range. This won't stop you creating
            # 10.1.1.0/24 when there is already 10.1.0.0/16, or
            # prevent you from having numerous IPv6 subnets that refer
            # to the same range (e.g 5::0/16, 5::/16, 5:0:0::/16).
            raise SubnetAlreadyExists('A subnet with the CIDR %s already exists'
                                      % subnet_name)
        else:
            raise


def delete_subnet(samdb, configDn, subnet_name):
    """Delete a subnet.

    :param samdb: A samdb connection
    :param configDn: The DN of the configuration partition
    :param subnet_name: Name of the subnet to delete
    :return: None
    :raise SubnetNotFound: if the subnet to be deleted does not exist.
    """
    dnsubnet = ldb.Dn(samdb, "CN=Subnets,CN=Sites")
    if dnsubnet.add_base(configDn) == False:
        raise SubnetException("dnsubnet.add_base() failed")
    if dnsubnet.add_child("CN=X") == False:
        raise SubnetException("dnsubnet.add_child() failed")
    dnsubnet.set_component(0, "CN", subnet_name)

    try:
        ret = samdb.search(base=dnsubnet, scope=ldb.SCOPE_BASE,
                           expression="objectClass=subnet")
        if len(ret) != 1:
            raise SubnetNotFound('Subnet %s does not exist' % subnet_name)
    except LdbError as e1:
        (enum, estr) = e1.args
        if enum == ldb.ERR_NO_SUCH_OBJECT:
            raise SubnetNotFound('Subnet %s does not exist' % subnet_name)

    samdb.delete(dnsubnet)


def rename_subnet(samdb, configDn, subnet_name, new_name):
    """Rename a subnet.

    :param samdb: A samdb connection
    :param configDn: The DN of the configuration partition
    :param subnet_name: Name of the subnet to rename
    :param new_name: New name for the subnet
    :return: None
    :raise SubnetNotFound: if the subnet to be renamed does not exist.
    :raise SubnetExists: if the subnet to be created already exists.
    """
    dnsubnet = ldb.Dn(samdb, "CN=Subnets,CN=Sites")
    if dnsubnet.add_base(configDn) == False:
        raise SubnetException("dnsubnet.add_base() failed")
    if dnsubnet.add_child("CN=X") == False:
        raise SubnetException("dnsubnet.add_child() failed")
    dnsubnet.set_component(0, "CN", subnet_name)

    newdnsubnet = ldb.Dn(samdb, str(dnsubnet))
    newdnsubnet.set_component(0, "CN", new_name)
    try:
        samdb.rename(dnsubnet, newdnsubnet)
    except LdbError as e2:
        (enum, estr) = e2.args
        if enum == ldb.ERR_NO_SUCH_OBJECT:
            raise SubnetNotFound('Subnet %s does not exist' % dnsubnet)
        elif enum == ldb.ERR_ENTRY_ALREADY_EXISTS:
            raise SubnetAlreadyExists('A subnet with the CIDR %s already exists'
                                      % new_name)
        elif enum == ldb.ERR_INVALID_DN_SYNTAX:
            raise SubnetInvalid("%s is not a valid subnet: %s" % (new_name,
                                                                  estr))
        else:
            raise


def set_subnet_site(samdb, configDn, subnet_name, site_name):
    """Assign a subnet to a site.

    This dissociates the subnet from its previous site.

    :param samdb: A samdb connection
    :param configDn: The DN of the configuration partition
    :param subnet_name: Name of the subnet
    :param site_name: Name of the site
    :return: None
    :raise SubnetNotFound: if the subnet does not exist.
    :raise SiteNotFound: if the site does not exist.
    """

    dnsubnet = ldb.Dn(samdb, "CN=Subnets,CN=Sites")
    if dnsubnet.add_base(configDn) == False:
        raise SubnetException("dnsubnet.add_base() failed")
    if dnsubnet.add_child("CN=X") == False:
        raise SubnetException("dnsubnet.add_child() failed")
    dnsubnet.set_component(0, "CN", subnet_name)

    try:
        ret = samdb.search(base=dnsubnet, scope=ldb.SCOPE_BASE,
                           expression="objectClass=subnet")
        if len(ret) != 1:
            raise SubnetNotFound('Subnet %s does not exist' % subnet_name)
    except LdbError as e3:
        (enum, estr) = e3.args
        if enum == ldb.ERR_NO_SUCH_OBJECT:
            raise SubnetNotFound('Subnet %s does not exist' % subnet_name)

    dnsite = ldb.Dn(samdb, "CN=Sites")
    if dnsite.add_base(configDn) == False:
        raise SubnetException("dnsites.add_base() failed")
    if dnsite.add_child("CN=X") == False:
        raise SubnetException("dnsites.add_child() failed")
    dnsite.set_component(0, "CN", site_name)

    dnservers = ldb.Dn(samdb, "CN=Servers")
    dnservers.add_base(dnsite)

    try:
        ret = samdb.search(base=dnsite, scope=ldb.SCOPE_BASE,
                           expression="objectClass=site")
        if len(ret) != 1:
            raise SiteNotFoundException('Site %s does not exist' % site_name)
    except LdbError as e4:
        (enum, estr) = e4.args
        if enum == ldb.ERR_NO_SUCH_OBJECT:
            raise SiteNotFoundException('Site %s does not exist' % site_name)

    siteDn = str(ret[0].dn)

    m = ldb.Message()
    m.dn = dnsubnet
    m["siteObject"] = ldb.MessageElement(siteDn, FLAG_MOD_REPLACE,
                                         "siteObject")
    samdb.modify(m)
