#!/usr/bin/perl
# Bootstrap Samba and run a number of tests against it.
# Copyright (C) 2005-2012 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL, v3 or later.

import os
import sys
import warnings

from selftest.target import Target

def bindir_path(binary_mapping, bindir, path):
    """Find the executable to use.

    :param binary_mapping: Dictionary mapping binary names
    :param bindir: Directory with binaries
    :param path: Name of the executable to run
    :return: Full path to the executable to run
    """
    path = binary_mapping.get(path, path)
    valpath = os.path.join(bindir, path)
    if os.path.isfile(valpath):
        return valpath
    return path


def mk_realms_stanza(realm, dnsname, domain, kdc_ipv4):
    """Create a realms stanza for use in a krb5.conf file.

    :param realm: Real name
    :param dnsname: DNS name matching the realm
    :param domain: Domain name
    :param kdc_ipv4: IPv4 address of the KDC
    :return: String with stanza
    """
    return """\
 %(realm)s = {
  kdc = %(kdc_ipv4)s:88
  admin_server = %(kdc_ipv4)s:88
  default_domain = %(dnsname)s
 }
 %(dnsname)s = {
  kdc = %(kdc_ipv4)s:88
  admin_server = %(kdc_ipv4)s:88
  default_domain = %(dnsname)s
 }
 %(domain)s = {
  kdc = %(kdc_ipv4)s:88
  admin_server = %(kdc_ipv4)s:88
  default_domain = %(dnsname)s
 }

""" % {
    "kdc_ipv4": kdc_ipv4, "dnsname": dnsname, "realm": realm, "domain": domain}


