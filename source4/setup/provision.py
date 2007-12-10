#!/usr/bin/python
#
# Unix SMB/CIFS implementation.
# provision a Samba4 server
# Copyright (C) Andrew Tridgell 2005
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
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

import getopt
import optparse
import sys

# Add path to the library for in-tree use
sys.path.append("bin/python")
sys.path.append("scripting/python")

from auth import system_session
import samba.getopt as options
import param
from samba.provision import (provision, provision_guess, 
		                     provision_default_paths, provision_ldapbase, 
							 provision_dns)

parser = optparse.OptionParser("provision [options]")
parser.add_option_group(options.SambaOptions(parser))
parser.add_option_group(options.VersionOptions(parser))
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
parser.add_option("--setupdir", type="string", metavar="DIR", 
		help="directory with setup files")
parser.add_option("--realm", type="string", metavar="REALM", help="set realm")
parser.add_option("--domain", type="string", metavar="DOMAIN",
				  help="set domain")
parser.add_option("--domain-guid", type="string", metavar="GUID", 
		help="set domainguid (otherwise random)")
parser.add_option("--domain-sid", type="string", metavar="SID", 
		help="set domainsid (otherwise random)")
parser.add_option("--policy-guid", type="string", metavar="GUID",
				  help="set policy guid")
parser.add_option("--host-name", type="string", metavar="HOSTNAME", 
		help="set hostname")
parser.add_option("--host-ip", type="string", metavar="IPADDRESS", 
		help="set ipaddress")
parser.add_option("--host-guid", type="string", metavar="GUID", 
		help="set hostguid (otherwise random)")
parser.add_option("--invocationid", type="string", metavar="GUID", 
		help="set invocationid (otherwise random)")
parser.add_option("--adminpass", type="string", metavar="PASSWORD", 
		help="choose admin password (otherwise random)")
parser.add_option("--krbtgtpass", type="string", metavar="PASSWORD", 
		help="choose krbtgt password (otherwise random)")
parser.add_option("--machinepass", type="string", metavar="PASSWORD", 
		help="choose machine password (otherwise random)")
parser.add_option("--dnspass", type="string", metavar="PASSWORD", 
		help="choose dns password (otherwise random)")
parser.add_option("--root", type="string", metavar="USERNAME", 
		help="choose 'root' unix username")
parser.add_option("--nobody", type="string", metavar="USERNAME", 
		help="choose 'nobody' user")
parser.add_option("--nogroup", type="string", metavar="GROUPNAME", 
		help="choose 'nogroup' group")
parser.add_option("--wheel", type="string", metavar="GROUPNAME", 
		help="choose 'wheel' privileged group")
parser.add_option("--users", type="string", metavar="GROUPNAME", 
		help="choose 'users' group")
parser.add_option("--quiet", help="Be quiet")
parser.add_option("--blank", 
		help="do not add users or groups, just the structure")
parser.add_option("--ldap-base", 
		help="output only an LDIF file, suitable for creating an LDAP baseDN")
parser.add_option("--ldap-backend", type="string", metavar="LDAPSERVER", 
		help="LDAP server to use for this provision")
parser.add_option("--ldap-module=", type="string", metavar="MODULE", 
		help="LDB mapping module to use for the LDAP backend")
parser.add_option("--aci", type="string", metavar="ACI", 
		help="An arbitary LDIF fragment, particularly useful to loading a backend ACI value into a target LDAP server. You must provide at least a realm and domain")
parser.add_option("--server-role", type="choice", metavar="ROLE",
		          choices=["domain controller", "domain server"],
		help="Set server role to provision for (default standalone)")
parser.add_option("--partitions-only", 
		help="Configure Samba's partitions, but do not modify them (ie, join a BDC)")

opts = parser.parse_args()[0]

def message(text):
	"""print a message if quiet is not set."""
	if opts.quiet:
		print text

hostname = opts.host_name

if opts.realm is None or opts.domain is None or opts.host_name is None:
	if opts.realm is None:
		print >>sys.stderr, "No realm set"
	if opts.domain is None:
		print >>sys.stderr, "No domain set"
	if opts.host_name is None:
		print >>sys.stderr, "No host name set"
	parser.print_help()
	sys.exit(1)

# cope with an initially blank smb.conf 
lp = param.ParamFile(opts.configfile)
lp.set("realm", opts.realm);
lp.set("workgroup", opts.domain);
lp.set("server role", opts.server_role);
lp.use()

subobj = provision_guess(lp)
subobj.domain_guid = opts.domain_guid
subobj.host_guid = opts.host_guid

if opts.aci is not None:
	print "set ACI: %s" % subobj.aci

print "set domain sid: %s" % subobj.domainsid
paths = provision_default_paths(lp, subobj)
paths.smbconf = opts.configfile
subobj.fix(paths);

if opts.ldap_backend:
	if opts.ldap_backend == "ldapi":
		subobj.ldap_backend = subobj.ldapi_uri

	if not opts.ldap_module:
		subobj.ldapmodule = "entryuuid"

	subobj.domaindn_ldb = subobj.ldap_backend
	subobj.domaindn_mod2 = ",%s,paged_searches" % subobj.ldapmodule
	subobj.configdn_ldb = subobj.ldap_backend
	subobj.configdn_mod2 = ",%s,paged_searches" % subobj.ldapmodule
	subobj.schemadn_ldb = subobj.ldap_backend
	subobj.schemadn_mod2 = ",%s,paged_searches" % subobj.ldapmodule
	message("LDAP module: %s on backend: %s" % (subobj.ldapmodule, subobj.ldap_backend))

subobj.validate(lp)

creds = credopts.get_credentials()
message("Provisioning for %s in realm %s" % (subobj.domain, subobj.realm))
message("Using administrator password: %s" % subobj.adminpass)

setup_dir = opts.setupdir
if setup_dir is None:
	setup_dir = "setup"
if opts.ldap_base:
	provision_ldapbase(setup_dir, subobj, message, paths)
	message("Please install the LDIF located in %s, %s and  into your LDAP server, and re-run with --ldap-backend=ldap://my.ldap.server" % (paths.ldap_basedn_ldif, paths.ldap_config_basedn_ldif, paths.ldap_schema_basedn_ldif))
elif opts.partitions_only:
	provision_become_dc(setup_dir, subobj, message, False, 
			            paths, system_session, creds)
else:
	provision(lp, setup_dir, subobj, message, opts.blank, paths, 
			  system_session, creds, opts.ldap_backend)
	provision_dns(setup_dir, subobj, message, paths, 
			      system_session, creds)
	message("To reproduce this provision, run with:")
	message("--realm='" + subobj.realm_conf + "' --domain='" + subobj.domain_conf + "' --domain-guid='" + subobj.domain_guid + "' \\")
	message("--policy-guid='" + subobj.policyguid + "' --host-name='" + subobj.hostname + "' --host-ip='" + subobj.hostip + "' \\")
	message("--host-guid='" + subobj.host_guid + "' --invocationid='" + subobj.invocationid + "' \\")
	message("--adminpass='" + subobj.adminpass + "' --krbtgtpass='" + subobj.krbtgtpass + "' \\")
	message("--machinepass='" + subobj.machinepass + "' --dnspass='" + subobj.dnspass + "' \\")
	message("--root='" + subobj.root + "' --nobody='" + subobj.nobody + "' --nogroup-'" + subobj.nogroup + "' \\")
	message("--wheel='" + subobj.wheel + "' --users='" + subobj.users + "' --server-role='" + subobj.serverrole + "' \\")
	message("--ldap-backend='" + subobj.ldap_backend + "' --ldap-module='" + subobj.ldapmodule + "' \\")
	message("--aci='" + subobj.aci + "' \\")

message("All OK")
