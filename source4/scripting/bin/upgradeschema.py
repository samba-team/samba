#!/usr/bin/python
#
# Copyright (C) Matthieu Patou <mat@matws.net> 2009
#
# Based on provision a Samba4 server by
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2008
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2008
#
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


import getopt
import shutil
import optparse
import os
import sys
import random
import string
import re
import base64
# Find right directory when running from source tree
sys.path.insert(0, "bin/python")

from base64 import b64encode

import samba
from samba.credentials import DONT_USE_KERBEROS
from samba.auth import system_session, admin_session
from samba import Ldb
from ldb import SCOPE_SUBTREE, SCOPE_ONELEVEL, SCOPE_BASE, LdbError
import ldb
import samba.getopt as options
from samba.samdb import SamDB
from samba import param
from samba.provision import  ProvisionNames,provision_paths_from_lp,find_setup_dir,FILL_FULL,provision
from samba.schema import get_dnsyntax_attributes, get_linked_attributes, Schema
from samba.dcerpc import misc, security
from samba.ndr import ndr_pack, ndr_unpack

replace=2^ldb.FLAG_MOD_REPLACE
add=2^ldb.FLAG_MOD_ADD
delete=2^ldb.FLAG_MOD_DELETE

CHANGE = 0x01
CHANGESD = 0x02
GUESS = 0x04
CHANGEALL = 0xff

# Attributes that not copied from the reference provision even if they do not exists in the destination object
# This is most probably because they are populated automatcally when object is created
hashAttrNotCopied = { 	"dn": 1,"whenCreated": 1,"whenChanged": 1,"objectGUID": 1,"replPropertyMetaData": 1,"uSNChanged": 1,\
						"uSNCreated": 1,"parentGUID": 1,"objectCategory": 1,"distinguishedName": 1,\
						"showInAdvancedViewOnly": 1,"instanceType": 1, "cn": 1, "msDS-Behavior-Version":1, "nextRid":1,\
						"nTMixedDomain": 1,"versionNumber":1, "lmPwdHistory":1, "pwdLastSet": 1, "ntPwdHistory":1, "unicodePwd":1,\
						"dBCSPwd":1,"supplementalCredentials":1,"gPCUserExtensionNames":1, "gPCMachineExtensionNames":1,\
						"maxPwdAge":1, "mail":1, "secret":1}

# Usually for an object that already exists we do not overwrite attributes as they might have been changed for good
# reasons. Anyway for a few of thems it's mandatory to replace them otherwise the provision will be broken somehow.
hashOverwrittenAtt = {	 "prefixMap": replace, "systemMayContain": replace,"systemOnly":replace, "searchFlags":replace,\
					 	 "mayContain":replace,  "systemFlags":replace, 
						 "oEMInformation":replace, "operatingSystemVersion":replace, "adminPropertyPages":1,"possibleInferiors":replace+delete}
backlinked = []

def define_what_to_log(opts):
	what = 0
	if opts.debugchange:
		what = what | CHANGE
	if opts.debugchangesd:
		what = what | CHANGESD
	if opts.debugguess:
		what = what | GUESS
	if opts.debugall:
		what = what | CHANGEALL
	return what



parser = optparse.OptionParser("provision [options]")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
parser.add_option("--setupdir", type="string", metavar="DIR", 
					help="directory with setup files")
parser.add_option("--debugprovision", help="Debug provision", action="store_true")
parser.add_option("--debugguess", help="Print information on what is different but won't be changed", action="store_true")
parser.add_option("--debugchange", help="Print information on what is different but won't be changed", action="store_true")
parser.add_option("--debugchangesd", help="Print information security descriptors differences", action="store_true")
parser.add_option("--debugall", help="Print all available information (very verbose)", action="store_true")
parser.add_option("--targetdir", type="string", metavar="DIR", 
					help="Set target directory")

opts = parser.parse_args()[0]

whatToLog = define_what_to_log(opts)

def messageprovision(text):
	"""print a message if quiet is not set."""
	if opts.debugprovision or opts.debugall:
		print text

def message(what,text):
	"""print a message if quiet is not set."""
	if whatToLog & what:
		print text

if len(sys.argv) == 1:
	opts.interactive = True
lp = sambaopts.get_loadparm()
smbconf = lp.configfile

creds = credopts.get_credentials(lp)
creds.set_kerberos_state(DONT_USE_KERBEROS)
setup_dir = opts.setupdir
if setup_dir is None:
    setup_dir = find_setup_dir()

setup_dir = "/usr/local/src/samba4/source4/setup"
session = system_session()

# Create an array of backlinked attributes
def populate_backlink(newpaths,creds,session,schemadn):
	newsam_ldb = Ldb(newpaths.samdb, session_info=session, credentials=creds,lp=lp)
	backlinked.extend(get_linked_attributes(ldb.Dn(newsam_ldb,str(schemadn)),newsam_ldb).values())

# Get Paths for important objects (ldb, keytabs ...)
def get_paths(targetdir=None,smbconf=None):
	if targetdir is not None:
		if (not os.path.exists(os.path.join(targetdir, "etc"))):
			os.makedirs(os.path.join(targetdir, "etc"))
		smbconf = os.path.join(targetdir, "etc", "smb.conf")
	if smbconf is None:
			smbconf = param.default_path()

	if not os.path.exists(smbconf):
		print >>sys.stderr, "Unable to find smb.conf .."
		parser.print_usage()
		sys.exit(1)

	lp = param.LoadParm()
	lp.load(smbconf)
# Normaly we need the domain name for this function but for our needs it's pointless 
	paths = provision_paths_from_lp(lp,"foo")
	return paths

# This function guess(fetch) informations needed to make a fresh provision from the current provision  	
# It includes: realm, workgroup, partitions, netbiosname, domain guid, ...
def guess_names_from_current_provision(credentials,session_info,paths):
	lp = param.LoadParm()
	lp.load(paths.smbconf)
	names = ProvisionNames()
	# NT domain, kerberos realm, root dn, domain dn, domain dns name
	names.domain = string.upper(lp.get("workgroup"))
	names.realm = lp.get("realm")
	rootdn = "DC=" + names.realm.replace(".",",DC=")
	names.domaindn = rootdn
	names.dnsdomain = names.realm
	names.realm = string.upper(names.realm)
	# netbiosname
	secrets_ldb = Ldb(paths.secrets, session_info=session_info, credentials=credentials,lp=lp)
	# Get the netbiosname first (could be obtained from smb.conf in theory)
	attrs = ["sAMAccountName"]
	res = secrets_ldb.search(expression="(flatname=%s)"%names.domain,base="CN=Primary Domains", scope=SCOPE_SUBTREE, attrs=attrs)
	names.netbiosname = str(res[0]["sAMAccountName"]).replace("$","")

	#partitions = get_partitions(credentials,session_info,paths,lp)
	names.smbconf = smbconf
	samdb = SamDB(paths.samdb, session_info=session_info,
								credentials=credentials, lp=lp)
	
	# partitions (schema,config,root)
	# That's a bit simplistic but it's ok as long as we have only 3 partitions 
	attrs2 = ["schemaNamingContext","configurationNamingContext","rootDomainNamingContext"]
	res2 = samdb.search(expression="(objectClass=*)",base="", scope=SCOPE_BASE, attrs=attrs2)

	names.configdn = res2[0]["configurationNamingContext"]
	configdn = str(names.configdn)
	names.schemadn = res2[0]["schemaNamingContext"]
	if not (rootdn == str(res2[0]["rootDomainNamingContext"])):
		print >>sys.stderr, "rootdn in sam.ldb and smb.conf is not the same ..."
	else:
		names.rootdn=res2[0]["rootDomainNamingContext"]
	# default site name
	attrs3 = ["cn"]
	res3= samdb.search(expression="(objectClass=*)",base="CN=Sites,"+configdn, scope=SCOPE_ONELEVEL, attrs=attrs3)
	names.sitename = str(res3[0]["cn"])
	
	# dns hostname and server dn 
	attrs4 = ["dNSHostName"]
	res4= samdb.search(expression="(CN=%s)"%names.netbiosname,base="OU=Domain Controllers,"+rootdn, \
						scope=SCOPE_ONELEVEL, attrs=attrs4)
	names.hostname = str(res4[0]["dNSHostName"]).replace("."+names.dnsdomain,"")

	names.serverdn = "CN=%s,CN=Servers,CN=%s,CN=Sites,%s" % (names.netbiosname, names.sitename, configdn)
	
	# invocation id
	attrs5 = ["invocationId"]
	res5 = samdb.search(expression="(objectClass=*)",base="CN=Sites,"+configdn, scope=SCOPE_SUBTREE, attrs=attrs5)
	for i in range(0,len(res5)):
		if ( len(res5[i]) > 0):
			names.invocation = str(ndr_unpack( misc.GUID,res5[i]["invocationId"][0]))
			break
	# domain guid/sid
	attrs6 = ["objectGUID", "objectSid", ]
	res6 = samdb.search(expression="(objectClass=*)",base=rootdn, scope=SCOPE_BASE, attrs=attrs6)
	names.domainguid = str(ndr_unpack( misc.GUID,res6[0]["objectGUID"][0]))
	names.domainsid = str(ndr_unpack( security.dom_sid,res6[0]["objectSid"][0]))

	# policy guid
	attrs7 = ["cn","displayName"]
	res7 = samdb.search(expression="(displayName=Default Domain Policy)",base="CN=Policies,CN=System,"+rootdn, \
							scope=SCOPE_ONELEVEL, attrs=attrs7)
	names.policyid = str(res7[0]["cn"]).replace("{","").replace("}","")
	# dc policy guid
	attrs8 = ["cn","displayName"]
	res8 = samdb.search(expression="(displayName=Default Domain Controllers Policy)",base="CN=Policies,CN=System,"+rootdn, \
							scope=SCOPE_ONELEVEL, attrs=attrs7)
	if len(res8) == 1:
		names.policyid_dc = str(res8[0]["cn"]).replace("{","").replace("}","")
	else:
		names.policyid_dc = None
	# ntds guid
	attrs9 = ["objectGUID" ]
	exp = "(dn=CN=NTDS Settings,%s)"%(names.serverdn)
	print exp
	res9 = samdb.search(expression="(dn=CN=NTDS Settings,%s)"%(names.serverdn),base=str(names.configdn), scope=SCOPE_SUBTREE, attrs=attrs9)
	names.ntdsguid = str(ndr_unpack( misc.GUID,res9[0]["objectGUID"][0]))


	return names

# Debug a little bit
def print_names(names):
	message(GUESS, "rootdn      :"+str(names.rootdn))
	message(GUESS, "configdn    :"+str(names.configdn))
	message(GUESS, "schemadn    :"+str(names.schemadn))
	message(GUESS, "serverdn    :"+names.serverdn)
	message(GUESS, "netbiosname :"+names.netbiosname)
	message(GUESS, "defaultsite :"+names.sitename)
	message(GUESS, "dnsdomain   :"+names.dnsdomain)
	message(GUESS, "hostname    :"+names.hostname)
	message(GUESS, "domain      :"+names.domain)
	message(GUESS, "realm       :"+names.realm)
	message(GUESS, "invocationid:"+names.invocation)
	message(GUESS, "policyguid  :"+names.policyid)
	message(GUESS, "policyguiddc:"+str(names.policyid_dc))
	message(GUESS, "domainsid   :"+names.domainsid)
	message(GUESS, "domainguid  :"+names.domainguid)
	message(GUESS, "ntdsguid    :"+names.ntdsguid)

# Create a fresh new reference provision
# This provision will be the reference for knowing what has changed in the 
# since the latest upgrade in the current provision
def newprovision(names,setup_dir,creds,session,smbconf):
	random.seed()
	provdir=os.path.join(os.environ["HOME"],"provision"+str(int(100000*random.random())))
	logstd=os.path.join(provdir,"log.std")
	os.chdir(os.path.join(setup_dir,".."))
	os.mkdir(provdir)

	provision(setup_dir, messageprovision,
		session, creds, smbconf=smbconf, targetdir=provdir,
		samdb_fill=FILL_FULL, realm=names.realm, domain=names.domain,
		domainguid=names.domainguid, domainsid=names.domainsid,ntdsguid=names.ntdsguid,
		policyguid=names.policyid,policyguid_dc=names.policyid_dc,hostname=names.hostname,
		hostip=None, hostip6=None,
		invocationid=names.invocation, adminpass=None,
		krbtgtpass=None, machinepass=None,
		dnspass=None, root=None, nobody=None,
		wheel=None, users=None,
		serverrole="domain controller",
		ldap_backend_extra_port=None,
		backend_type=None,
		ldapadminpass=None,
		ol_mmr_urls=None,
		slapd_path=None,
		setup_ds_path=None,
		nosync=None,
		ldap_dryrun_mode=None)
	print >>sys.stderr, "provisiondir: "+provdir
	return provdir

# This function sorts two dn in the lexicographical order and put higher level DN before
# So given the dns cn=bar,cn=foo and cn=foo the later will be return as smaller (-1) as it has less 
# level
def dn_sort(x,y):
	p = re.compile(r'(?<!\\),')
	tab1 = p.split(str(x))
	tab2 = p.split(str(y))
	min = 0
	if (len(tab1) > len(tab2)):
		min = len(tab2)
	elif (len(tab1) < len(tab2)):
		min = len(tab1) 
	else: 
		min = len(tab1)
	len1=len(tab1)-1
	len2=len(tab2)-1
	space = " "
	# Note: python range go up to upper limit but do not include it
	for i in range(0,min):
		ret=cmp(tab1[len1-i],tab2[len2-i])
		if(ret != 0):
			return ret	
		else:
			if(i==min-1):
				if(len1==len2):
					print >>sys.stderr,"PB PB PB"+space.join(tab1)+" / "+space.join(tab2)
				if(len1>len2):
					return 1
				else:
					return -1
	return ret

# check from security descriptors modifications return 1 if it is 0 otherwise
# it also populate hash structure for later use in the upgrade process
def handle_security_desc(ischema,att,msgElt,hashallSD,old,new):
	if ischema == 1 and att == "defaultSecurityDescriptor"  and msgElt.flags() == ldb.FLAG_MOD_REPLACE:
		hashSD = {}
		hashSD["oldSD"] = old[0][att]
		hashSD["newSD"] = new[0][att]
		hashallSD[str(old[0].dn)] = hashSD
		return 1
	if att == "nTSecurityDescriptor"  and msgElt.flags() == ldb.FLAG_MOD_REPLACE:
		if ischema == 0:
			hashSD = {}
			hashSD["oldSD"] =  ndr_unpack(security.descriptor,str(old[0][att]))
			hashSD["newSD"] =  ndr_unpack(security.descriptor,str(new[0][att]))
			hashallSD[str(old[0].dn)] = hashSD
		return 1
	return 0

# Hangle special cases ... That's when we want to update an attribute only 
# if it has a certain value or if it's for a certain object or 
# a class of object. 
# It can be also if we want to do a merge of value instead of a simple replace 

def handle_special_case(att,delta,new,old,ischema):
	flag = delta.get(att).flags()
	if (att == "gPLink" or att == "gPCFileSysPath") and flag ==  ldb.FLAG_MOD_REPLACE and str(new[0].dn).lower() == str(old[0].dn).lower():
		delta.remove(att)
		return 1
	if att == "forceLogoff":
		ref=0x8000000000000000 
		oldval=int(old[0][att][0])
		newval=int(new[0][att][0])
		ref == old and ref == abs(new)
		return 1
	if (att == "adminDisplayName" or att == "adminDescription") and ischema:
		return 1
	if (str(old[0].dn) == "CN=Samba4-Local-Domain,%s"%(str(names.schemadn)) and att == "defaultObjectCategory" and flag  == ldb.FLAG_MOD_REPLACE):
		return 1
	if (str(old[0].dn) == "CN=S-1-5-11,CN=ForeignSecurityPrincipals,%s"%(str(names.rootdn)) and att == "description" and flag  == ldb.FLAG_MOD_DELETE):
		return 1
	if (str(old[0].dn) == "CN=Title,%s"%(str(names.schemadn)) and att == "rangeUpper" and flag  == ldb.FLAG_MOD_REPLACE):
		return 1
	if ( (att == "member" or att == "servicePrincipalName") and flag  == ldb.FLAG_MOD_REPLACE):

		hash = {}
		newval = []
		changeDelta=0
		for elem in old[0][att]:
			hash[str(elem)]=1
			newval.append(str(elem))

		for elem in new[0][att]:
			if not hash.has_key(str(elem)):
				changeDelta=1
				newval.append(str(elem))
		if changeDelta == 1:
			delta[att] = ldb.MessageElement(newval, ldb.FLAG_MOD_REPLACE, att)
		else:
			delta.remove(att)
		return 1
	if (str(old[0].dn) == "%s"%(str(names.rootdn)) and att == "subRefs" and flag  == ldb.FLAG_MOD_REPLACE):
		return 1
	if str(delta.dn).endswith("CN=DisplaySpecifiers,%s"%names.configdn):
		return 1
	return 0

def update_secrets(newpaths,paths,creds,session):
	newsam_ldb = Ldb(newpaths.secrets, session_info=session, credentials=creds,lp=lp)
	sam_ldb = Ldb(paths.secrets, session_info=session, credentials=creds,lp=lp)
	res = newsam_ldb.search(expression="dn=@MODULES",base="", scope=SCOPE_SUBTREE)
	res2 = sam_ldb.search(expression="dn=@MODULES",base="", scope=SCOPE_SUBTREE)
	delta = sam_ldb.msg_diff(res2[0],res[0])
	delta.dn = res2[0].dn
	sam_ldb.modify(delta)	

	newsam_ldb = Ldb(newpaths.secrets, session_info=session, credentials=creds,lp=lp)
	sam_ldb = Ldb(paths.secrets, session_info=session, credentials=creds,lp=lp)
	res = newsam_ldb.search(expression="objectClass=top",base="", scope=SCOPE_SUBTREE,attrs=["dn"])
	res2 = sam_ldb.search(expression="objectClass=top",base="", scope=SCOPE_SUBTREE,attrs=["dn"])
	hash_new = {}
	hash = {}
	listMissing = []
	listPresent = []

	empty = ldb.Message()
	for i in range(0,len(res)):
		hash_new[str(res[i]["dn"]).lower()] = res[i]["dn"]
	
	# Create a hash for speeding the search of existing object in the current provision
	for i in range(0,len(res2)):
		hash[str(res2[i]["dn"]).lower()] = res2[i]["dn"]

	for k in hash_new.keys():
		if not hash.has_key(k):
			listMissing.append(hash_new[k])
		else:
			listPresent.append(hash_new[k])
	for entry in listMissing:
		res = newsam_ldb.search(expression="dn=%s"%entry,base="", scope=SCOPE_SUBTREE)
		res2 = sam_ldb.search(expression="dn=%s"%entry,base="", scope=SCOPE_SUBTREE)
		delta = sam_ldb.msg_diff(empty,res[0])
		for att in hashAttrNotCopied.keys():
			delta.remove(att)
		message(CHANGE,"Entry %s is missing from secrets.ldb"%res[0].dn)
		for att in delta:
			message(CHANGE," Adding attribute %s"%att)
		delta.dn = res[0].dn
		sam_ldb.add(delta)	

	for entry in listPresent:
		res = newsam_ldb.search(expression="dn=%s"%entry,base="", scope=SCOPE_SUBTREE)
		res2 = sam_ldb.search(expression="dn=%s"%entry,base="", scope=SCOPE_SUBTREE)
		delta = sam_ldb.msg_diff(res2[0],res[0])
		i=0
		for att in hashAttrNotCopied.keys():
			delta.remove(att)
		for att in delta:
			i = i + 1
			if att != "dn":
				message(CHANGE," Adding/Changing attribute %s to %s"%(att,res2[0].dn))
				
		delta.dn = res2[0].dn
		sam_ldb.modify(delta)	
# Check difference between the current provision and the reference provision.
# It looks for all object which base DN is name if ischema is false then scan is done in 
# cross partition mode.
# If ischema is true, then special handling is done for dealing with schema
def check_diff_name(newpaths,paths,creds,session,basedn,names,ischema):
	hash_new = {}
	hash = {}
	hashallSD = {}
	listMissing = []
	listPresent = []
	res = []
	res2 = []
	# Connect to the reference provision and get all the attribute in the partition referred by name
	newsam_ldb = Ldb(newpaths.samdb, session_info=session, credentials=creds,lp=lp)
	sam_ldb = Ldb(paths.samdb, session_info=session, credentials=creds,lp=lp)
	if ischema:
		res = newsam_ldb.search(expression="objectClass=*",base=basedn, scope=SCOPE_SUBTREE,attrs=["dn"])
		res2 = sam_ldb.search(expression="objectClass=*",base=basedn, scope=SCOPE_SUBTREE,attrs=["dn"])
	else:
		res = newsam_ldb.search(expression="objectClass=*",base=basedn, scope=SCOPE_SUBTREE,attrs=["dn"],controls=["search_options:1:2"])
		res2 = sam_ldb.search(expression="objectClass=*",base=basedn, scope=SCOPE_SUBTREE,attrs=["dn"],controls=["search_options:1:2"])
		
	# Create a hash for speeding the search of new object
	for i in range(0,len(res)):
		hash_new[str(res[i]["dn"]).lower()] = res[i]["dn"]
	
	# Create a hash for speeding the search of existing object in the current provision
	for i in range(0,len(res2)):
		hash[str(res2[i]["dn"]).lower()] = res2[i]["dn"]

	for k in hash_new.keys():
		if not hash.has_key(k):
			listMissing.append(hash_new[k])
		else:
			listPresent.append(hash_new[k])

	# Sort the missing object in order to have object of the lowest level first (which can be 
	# containers for higher level objects)
	listMissing.sort(dn_sort)
	listPresent.sort(dn_sort)

	if ischema:
		# The following lines (up to the for loop) is to load the up to date schema into our current LDB 
		# a complete schema is needed as the insertion of attributes and class is done against it 
		# and the schema is self validated
		# The double ldb open and schema validation is taken from the initial provision script
		# it's not certain that it is really needed ....
		sam_ldb = Ldb(session_info=session, credentials=creds, lp=lp)
		schema = Schema(setup_path, security.dom_sid(names.domainsid), schemadn=basedn, serverdn=names.serverdn)
		# Load the schema from the one we computed earlier
		sam_ldb.set_schema_from_ldb(schema.ldb)
		# And now we can connect to the DB - the schema won't be loaded from the DB
		sam_ldb.connect(paths.samdb)
		sam_ldb.transaction_start()
	else:	
		sam_ldb.transaction_start()

	empty = ldb.Message()
	print "There are %d missing objects"%(len(listMissing))
	for dn in listMissing:
		res = newsam_ldb.search(expression="dn=%s"%(str(dn)),base=basedn, scope=SCOPE_SUBTREE,controls=["search_options:1:2"])
		#print >>sys.stderr, "@@@"+str(dn)
		delta = sam_ldb.msg_diff(empty,res[0])
		for att in hashAttrNotCopied.keys():
			delta.remove(att)
		for att in backlinked:
			delta.remove(att)
		delta.dn = dn

		sam_ldb.add(delta,["relax:0"])

	changed = 0
	for dn in listPresent:
		res = newsam_ldb.search(expression="dn=%s"%(str(dn)),base=basedn, scope=SCOPE_SUBTREE,controls=["search_options:1:2"])
		res2 = sam_ldb.search(expression="dn=%s"%(str(dn)),base=basedn, scope=SCOPE_SUBTREE,controls=["search_options:1:2"])
		delta = sam_ldb.msg_diff(res2[0],res[0])
		for att in hashAttrNotCopied.keys():
			delta.remove(att)
		for att in backlinked:
			delta.remove(att)
		delta.remove("parentGUID")
		nb = 0
		for att in delta:
			msgElt = delta.get(att)
			if att == "dn":
				continue
			if handle_security_desc(ischema,att,msgElt,hashallSD,res2,res):
				delta.remove(att)
				continue
			if (not hashOverwrittenAtt.has_key(att) or not (hashOverwrittenAtt.get(att)&2^msgElt.flags())):
				if  handle_special_case(att,delta,res,res2,ischema)==0 and msgElt.flags()!=ldb.FLAG_MOD_ADD:
					i = 0
					if opts.debugchange:
						message(CHANGE, "dn= "+str(dn)+ " "+att + " with flag "+str(msgElt.flags())+ " is not allowed to be changed/removed, I discard this change ...")
						for e in range(0,len(res2[0][att])):
							message(CHANGE,"old %d : %s"%(i,str(res2[0][att][e])))
						if msgElt.flags() == 2:
							i = 0
							for e in range(0,len(res[0][att])):
								message(CHANGE,"new %d : %s"%(i,str(res[0][att][e])))
					delta.remove(att)
		delta.dn = dn
		if len(delta.items()) >1:
			attributes=",".join(delta.keys())
			message(CHANGE,"%s is different from the reference one, changed attributes: %s"%(dn,attributes))
			changed = changed + 1
			sam_ldb.modify(delta)

	sam_ldb.transaction_commit()
	print "There are %d changed objects"%(changed)
	return hashallSD


# This function updates SD for AD objects.
# As SD in the upgraded provision can be different for various reasons 
# this function check if an automatic update can be performed and do it 
# or if it can't be done.
def update_sds(diffDefSD,diffSD,paths,creds,session,rootdn,domSIDTxt):
	sam_ldb = Ldb(paths.samdb, session_info=session, credentials=creds,lp=lp)
	sam_ldb.transaction_start()
	domSID = security.dom_sid(domSIDTxt)
	hashClassSD = {}
	admin_session_info = admin_session(lp, str(domSID))
	system_session_info = system_session()
	upgrade = 0
	for dn in diffSD.keys():
		newSD = diffSD[dn]["newSD"].as_sddl(domSID)
		oldSD = diffSD[dn]["oldSD"].as_sddl(domSID)
		message(CHANGESD, "ntsecuritydescriptor for %s has changed old %s new %s"%(dn,oldSD,diffSD[dn]["newSD"].as_sddl(domSID)))
		# First let's find the defaultSD for the object which SD is different from the reference one.
		res = sam_ldb.search(expression="dn=%s"%(dn),base=rootdn, scope=SCOPE_SUBTREE,attrs=["objectClass"],controls=["search_options:1:2"])
		classObj = res[0]["objectClass"][-1]
		defSD = ""
		if hashClassSD.has_key(classObj):
			defSD = hashClassSD[classObj]
		else:
			res2 = sam_ldb.search(expression="lDAPDisplayName=%s"%(classObj),base=rootdn, scope=SCOPE_SUBTREE,attrs=["defaultSecurityDescriptor"],controls=["search_options:1:2"])
			if len(res2) > 0:
				defSD = str(res2[0]["defaultSecurityDescriptor"])
				hashClassSD[classObj] = defSD
		# Because somewhere between alpha8 and alpha9 samba4 changed the owner of ACLs in the AD so 
		# we check if it's the case and if so use the "old" owner to see if the ACL is a direct calculation 
		# from the defaultSecurityDescriptor
		session = admin_session_info
		if oldSD.startswith("O:SYG:BA"):
			session = system_session_info
		descr = security.descriptor.ntsd_from_defaultsd(defSD, domSID,session)
		if descr.as_sddl(domSID) != oldSD:
			print "nTSecurity Descriptor for %s do not directly inherit from the defaultSecurityDescriptor and is different from the one of the reference provision, therefor I can't upgrade i"
			print "Old Descriptor: %s"%(oldSD)
			print "New Descriptor: %s"%(newSD)
			if diffDefSD.has_key(classObj):
				# We have a pending modification for the defaultSecurityDescriptor of the class Object of the currently inspected object
				# and we have a conflict so write down that we won't upgrade this defaultSD for this class object
				diffDefSD[classObj]["noupgrade"]=1
		else:
			# At this point we know that the SD was directly generated from the defaultSecurityDescriptor
			# so we can take the new SD and replace the old one
			upgrade = upgrade +1
			delta = ldb.Message()
			delta.dn = ldb.Dn(sam_ldb,dn)
			delta["nTSecurityDescriptor"] = ldb.MessageElement( ndr_pack(diffSD[dn]["newSD"]),ldb.FLAG_MOD_REPLACE,"nTSecurityDescriptor" )
        	sam_ldb.modify(delta)
		
	sam_ldb.transaction_commit()
	print "%d nTSecurityDescriptor attribute(s) have been updated"%(upgrade)
	sam_ldb.transaction_start()
	upgrade = 0
	for dn in diffDefSD:
		message(CHANGESD, "DefaultSecurityDescriptor for class object %s has changed"%(dn)) 
		if not diffDefSD[dn].has_key("noupgrade"):
			upgrade = upgrade +1
			delta = ldb.Message()
			delta.dn = ldb.Dn(sam_ldb,dn)
			delta["defaultSecurityDescriptor"] = ldb.MessageElement(diffDefSD[dn]["newSD"],ldb.FLAG_MOD_REPLACE,"defaultSecurityDescriptor" )
			sam_ldb.modify(delta)
		else:
			message(CHANGESD,"Not updating the defaultSecurityDescriptor for class object %s as one or more dependant object hasn't been upgraded"%(dn))

	sam_ldb.transaction_commit()
	print "%d defaultSecurityDescriptor attribute(s) have been updated"%(upgrade)
			
def rmall(topdir):
	for root, dirs, files in os.walk(topdir, topdown=False):
		for name in files:
			os.remove(os.path.join(root, name))
		for name in dirs:
			os.rmdir(os.path.join(root, name))
	os.rmdir(topdir)

# For each partition check the differences

def check_diff(newpaths,paths,creds,session,names):
	#for name in [str(names.schemadn), str(names.configdn), str(names.rootdn)] :
	#for name in [str(names.configdn)] :
	print "Copy samdb"
	shutil.copy(newpaths.samdb,paths.samdb)

	print "Update ldb names if needed"
	schemaldb=os.path.join(paths.private_dir,"schema.ldb")
	configldb=os.path.join(paths.private_dir,"configuration.ldb")
	usersldb=os.path.join(paths.private_dir,"users.ldb")
	if os.path.isfile(schemaldb):
		shutil.copy(schemaldb,os.path.join(paths.private_dir,"%s.ldb"%str(names.schemadn).upper()))
		os.remove(schemaldb)
	if os.path.isfile(usersldb):
		shutil.copy(usersldb,os.path.join(paths.private_dir,"%s.ldb"%str(names.rootdn).upper()))
		os.remove(usersldb)
	if os.path.isfile(configldb):
		shutil.copy(configldb,os.path.join(paths.private_dir,"%s.ldb"%str(names.configdn).upper()))
		os.remove(configldb)
	shutil.copy(os.path.join(newpaths.private_dir,"privilege.ldb"),os.path.join(paths.private_dir,"privilege.ldb"))

	print "Doing schema update"
	hashdef = check_diff_name(newpaths,paths,creds,session,str(names.schemadn),names,1)
	print "Done with schema update"
	print "Scanning whole provision for updates and additions"
	hashSD = check_diff_name(newpaths,paths,creds,session,str(names.rootdn),names,0)
	print "Done with scanning"
	print "Updating secrets"
	update_secrets(newpaths,paths,creds,session)
#	update_sds(hashdef,hashSD,paths,creds,session,str(names.rootdn),names.domainsid)

# From here start the big steps of the program
# First get files paths
paths=get_paths(targetdir=opts.targetdir,smbconf=smbconf)
paths.setup = setup_dir
def setup_path(file):
	return os.path.join(setup_dir, file)
# Guess all the needed names (variables in fact) from the current 
# provision.
names = guess_names_from_current_provision(creds,session,paths)
# Let's see them
print_names(names)
# With all this information let's create a fresh new provision used as reference
provisiondir = newprovision(names,setup_dir,creds,session,smbconf)
#provisiondir = "/home/mat/provision12962"
# Get file paths of this new provision
newpaths = get_paths(targetdir=provisiondir)
populate_backlink(newpaths,creds,session,names.schemadn)
# Check the difference
check_diff(newpaths,paths,creds,session,names)
# remove reference provision now that everything is done !
rmall(provisiondir)
