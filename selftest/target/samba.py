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


def write_krb5_conf(f, realm, dnsname, domain, kdc_ipv4, tlsdir=None,
        other_realms_stanza=None):
    """Write a krb5.conf file.

    :param f: File-like object to write to
    :param realm: Realm
    :param dnsname: DNS domain name
    :param domain: Domain name
    :param kdc_ipv4: IPv4 address of KDC
    :param tlsdir: Optional TLS directory
    :param other_realms_stanza: Optional extra raw text for [realms] section
    """
    f.write("""\
#Generated krb5.conf for %(realm)s

[libdefaults]
\tdefault_realm = %(realm)s
\tdns_lookup_realm = false
\tdns_lookup_kdc = false
\tticket_lifetime = 24h
\tforwardable = yes
\tallow_weak_crypto = yes
""" % {"realm": realm})

    f.write("\n[realms]\n")
    f.write(mk_realms_stanza(realm, dnsname, domain, kdc_ipv4))
    if other_realms_stanza:
        f.write(other_realms_stanza)

    if tlsdir:
        f.write("""
[appdefaults]
	pkinit_anchors = FILE:%(tlsdir)s/ca.pem

[kdc]
	enable-pkinit = true
	pkinit_identity = FILE:%(tlsdir)s/kdc.pem,%(tlsdir)s/key.pem
	pkinit_anchors = FILE:%(tlsdir)s/ca.pem

    """ % {"tlsdir": tlsdir})
