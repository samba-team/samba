#!/usr/bin/python
#
#	Upgrade from Samba3
#	Copyright Jelmer Vernooij 2005-2007
#	Released under the GNU GPL v3 or later
#
import getopt
import optparse
import samba.options

parser = optparse.OptionParser("upgrade [options]")
parser.add_option_group(options.SambaOptions(parser))
parser.add_option_group(options.VersionOptions(parser))
parser.add_option_group(options.CredentialsOptions(parser))
parser.add_option("--realm", type="string", metavar="REALM", help="set realm")
parser.add_option("--quiet", help="Be quiet")
parser.add_option("--verify", help="Verify resulting configuration")
parser.add_option("--blank", 
		help="do not add users or groups, just the structure")
parser.add_option("--targetdir", type="string", metavar="DIR", 
		          help="Set target directory")

def message(text):
    """Print a message if quiet is not set."""
	if opts.quiet:
		print text

message("Reading Samba3 databases and smb.conf\n")
samba3 = samba3_read(options.ARGV[0], options.ARGV[1])

message("Provisioning\n")
subobj = upgrade_provision(samba3)
if options.targetdir is not None:
	paths = ProvisionPaths()
	paths.smbconf = os.path.join(options.targetdir, "smb.conf")
	ldbs = ["hklm","hkcr","hku","hkcu","hkpd","hkpt","samdb","rootdse","secrets","wins"]
	for n in ldbs:
		paths[n] = sprintf("tdb://%s/%s.ldb", options.targetdir, n)
	paths.dns = os.path.join(options.targetdir, "dns.zone")
else:
	paths = provision_default_paths(subobj)

creds = options.get_credentials()
system_session = system_session()
paths = provision_default_paths(subobj)

if options.realm:
	subobj.realm = options.realm

provision(lp, subobj, message, options.blank, paths, system_session, creds, undefined)

ret = upgrade(subobj,samba3,message,paths, system_session, creds)
if ret > 0:
	message("Failed to import %d entries\n", ret)
else:
	provision_dns(subobj, message, paths, system_session, creds)
	message("All OK\n")

if options.verify:
	message("Verifying...\n")
	ret = upgrade_verify(subobj, samba3, paths, message)
