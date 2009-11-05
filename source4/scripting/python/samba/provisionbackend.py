#
# Unix SMB/CIFS implementation.
# backend code for provisioning a Samba4 server

# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2008
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2008-2009
# Copyright (C) Oliver Liebel <oliver@itc.li> 2008-2009
#
# Based on the original in EJS:
# Copyright (C) Andrew Tridgell <tridge@samba.org> 2005
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

"""Functions for setting up a Samba configuration (LDB and LDAP backends)."""

from base64 import b64encode
import ldb
import os
import sys
import uuid
import time
import shutil
import subprocess

from samba import read_and_sub_file
from samba import Ldb
import urllib
from ldb import SCOPE_BASE, SCOPE_ONELEVEL, LdbError, timestring
from credentials import Credentials, DONT_USE_KERBEROS
from samba import setup_file

def setup_db_config(setup_path, dbdir):
    """Setup a Berkeley database.
    
    :param setup_path: Setup path function.
    :param dbdir: Database directory."""
    if not os.path.isdir(os.path.join(dbdir, "bdb-logs")):
        os.makedirs(os.path.join(dbdir, "bdb-logs"), 0700)
        if not os.path.isdir(os.path.join(dbdir, "tmp")):
            os.makedirs(os.path.join(dbdir, "tmp"), 0700)

    setup_file(setup_path("DB_CONFIG"), os.path.join(dbdir, "DB_CONFIG"),
               {"LDAPDBDIR": dbdir})

class ProvisionBackend(object):
    def __init__(self, backend_type, paths=None, setup_path=None, lp=None, credentials=None, 
                 names=None, message=None, 
                 hostname=None, root=None, 
                 schema=None, ldapadminpass=None,
                 ldap_backend_extra_port=None,
                 ol_mmr_urls=None, 
                 setup_ds_path=None, slapd_path=None, 
                 nosync=False, ldap_dryrun_mode=False,
                 domainsid=None):
        """Provision an LDAP backend for samba4
        
        This works for OpenLDAP and Fedora DS
        """
        self.paths = paths
        self.setup_path = setup_path
        self.slapd_command = None
        self.slapd_command_escaped = None
        self.lp = lp
        self.names = names

        self.type = backend_type
        
        # Set a default - the code for "existing" below replaces this
        self.ldap_backend_type = backend_type

        if self.type is "ldb":
            self.credentials = None
            self.secrets_credentials = None
    
            # Wipe the old sam.ldb databases away
            shutil.rmtree(paths.samdb + ".d", True)
            return

        self.ldapi_uri = "ldapi://" + urllib.quote(os.path.join(paths.ldapdir, "ldapi"), safe="")
        
        if self.type == "existing":
            #Check to see that this 'existing' LDAP backend in fact exists
            ldapi_db = Ldb(self.ldapi_uri, credentials=credentials)
            search_ol_rootdse = ldapi_db.search(base="", scope=SCOPE_BASE,
                                                expression="(objectClass=OpenLDAProotDSE)")

            # If we have got here, then we must have a valid connection to the LDAP server, with valid credentials supplied
            self.credentials = credentials
            # This caused them to be set into the long-term database later in the script.
            self.secrets_credentials = credentials

            self.ldap_backend_type = "openldap" #For now, assume existing backends at least emulate OpenLDAP
            return
    
        # we will shortly start slapd with ldapi for final provisioning. first check with ldapsearch -> rootDSE via self.ldapi_uri
        # if another instance of slapd is already running 
        try:
            ldapi_db = Ldb(self.ldapi_uri)
            search_ol_rootdse = ldapi_db.search(base="", scope=SCOPE_BASE,
                                                expression="(objectClass=OpenLDAProotDSE)");
            try:
                f = open(paths.slapdpid, "r")
                p = f.read()
                f.close()
                message("Check for slapd Process with PID: " + str(p) + " and terminate it manually.")
            except:
                pass
            
            raise ProvisioningError("Warning: Another slapd Instance seems already running on this host, listening to " + self.ldapi_uri + ". Please shut it down before you continue. ")
        
        except LdbError, e:
            pass

        # Try to print helpful messages when the user has not specified the path to slapd
        if slapd_path is None:
            raise ProvisioningError("Warning: LDAP-Backend must be setup with path to slapd, e.g. --slapd-path=\"/usr/local/libexec/slapd\"!")
        if not os.path.exists(slapd_path):
            message (slapd_path)
            raise ProvisioningError("Warning: Given Path to slapd does not exist!")


        if not os.path.isdir(paths.ldapdir):
            os.makedirs(paths.ldapdir, 0700)

        # Put the LDIF of the schema into a database so we can search on
        # it to generate schema-dependent configurations in Fedora DS and
        # OpenLDAP
        schemadb_path = os.path.join(paths.ldapdir, "schema-tmp.ldb")
        try:
            os.unlink(schemadb_path)
        except OSError:
            pass

        schema.write_to_tmp_ldb(schemadb_path);

        self.credentials = Credentials()
        self.credentials.guess(lp)
        #Kerberos to an ldapi:// backend makes no sense
        self.credentials.set_kerberos_state(DONT_USE_KERBEROS)
        self.credentials.set_password(ldapadminpass)

        self.secrets_credentials = Credentials()
        self.secrets_credentials.guess(lp)
        #Kerberos to an ldapi:// backend makes no sense
        self.secrets_credentials.set_kerberos_state(DONT_USE_KERBEROS)
        self.secrets_credentials.set_username("samba-admin")
        self.secrets_credentials.set_password(ldapadminpass)


        if self.type == "fedora-ds":
            provision_fds_backend(self, setup_path=setup_path,
                                  names=names, message=message, 
                                  hostname=hostname,
                                  ldapadminpass=ldapadminpass, root=root, 
                                  schema=schema,
                                  ldap_backend_extra_port=ldap_backend_extra_port, 
                                  setup_ds_path=setup_ds_path,
                                  slapd_path=slapd_path,
                                  nosync=nosync,
                                  ldap_dryrun_mode=ldap_dryrun_mode,
                                  domainsid=domainsid)
            
        elif self.type == "openldap":
            provision_openldap_backend(self, setup_path=setup_path,
                                       names=names, message=message, 
                                       hostname=hostname,
                                       ldapadminpass=ldapadminpass, root=root, 
                                       schema=schema,
                                       ldap_backend_extra_port=ldap_backend_extra_port, 
                                       ol_mmr_urls=ol_mmr_urls, 
                                       slapd_path=slapd_path,
                                       nosync=nosync,
                                       ldap_dryrun_mode=ldap_dryrun_mode)
        else:
            raise ProvisioningError("Unknown LDAP backend type selected")

    def start(self):
        pass

    def shutdown(self):
        pass

    def post_setup(self):
        pass


class LDAPBackend(ProvisionBackend):
    def start(self):
        self.slapd_command_escaped = "\'" + "\' \'".join(self.slapd_command) + "\'"
        setup_file(self.setup_path("ldap_backend_startup.sh"), self.paths.ldapdir + "/ldap_backend_startup.sh", {
                "SLAPD_COMMAND" : self.slapd_command_escaped})

        # Now start the slapd, so we can provision onto it.  We keep the
        # subprocess context around, to kill this off at the successful
        # end of the script
        self.slapd = subprocess.Popen(self.slapd_provision_command, close_fds=True, shell=False)
    
        while self.slapd.poll() is None:
            # Wait until the socket appears
            try:
                ldapi_db = Ldb(self.ldapi_uri, lp=self.lp, credentials=self.credentials)
                search_ol_rootdse = ldapi_db.search(base="", scope=SCOPE_BASE,
                                                    expression="(objectClass=OpenLDAProotDSE)")
                # If we have got here, then we must have a valid connection to the LDAP server!
                return
            except LdbError, e:
                time.sleep(1)
                pass
        
        raise ProvisioningError("slapd died before we could make a connection to it")

    def shutdown(self):
        # if an LDAP backend is in use, terminate slapd after final provision and check its proper termination
        if self.slapd.poll() is None:
            #Kill the slapd
            if hasattr(self.slapd, "terminate"):
                self.slapd.terminate()
            else:
                # Older python versions don't have .terminate()
                import signal
                os.kill(self.slapd.pid, signal.SIGTERM)
    
            #and now wait for it to die
            self.slapd.communicate()


class OpenLDAPBackend(LDAPBackend):
    pass

def provision_openldap_backend(result, setup_path=None, names=None,
                               message=None, 
                               hostname=None, ldapadminpass=None, root=None, 
                               schema=None, 
                               ldap_backend_extra_port=None,
                               ol_mmr_urls=None, 
                               slapd_path=None, nosync=False,
                               ldap_dryrun_mode=False):

    # Wipe the directories so we can start
    shutil.rmtree(os.path.join(result.paths.ldapdir, "db"), True)

    #Allow the test scripts to turn off fsync() for OpenLDAP as for TDB and LDB
    nosync_config = ""
    if nosync:
        nosync_config = "dbnosync"
        
    lnkattr = schema.linked_attributes()
    refint_attributes = ""
    memberof_config = "# Generated from Samba4 schema\n"
    for att in  lnkattr.keys():
        if lnkattr[att] is not None:
            refint_attributes = refint_attributes + " " + att 
            
            memberof_config += read_and_sub_file(setup_path("memberof.conf"),
                                                 { "MEMBER_ATTR" : att ,
                                                   "MEMBEROF_ATTR" : lnkattr[att] })
            
    refint_config = read_and_sub_file(setup_path("refint.conf"),
                                      { "LINK_ATTRS" : refint_attributes})
    
    attrs = ["linkID", "lDAPDisplayName"]
    res = schema.ldb.search(expression="(&(objectclass=attributeSchema)(searchFlags:1.2.840.113556.1.4.803:=1))", base=names.schemadn, scope=SCOPE_ONELEVEL, attrs=attrs)
    index_config = ""
    for i in range (0, len(res)):
        index_attr = res[i]["lDAPDisplayName"][0]
        if index_attr == "objectGUID":
            index_attr = "entryUUID"
            
        index_config += "index " + index_attr + " eq\n"

# generate serverids, ldap-urls and syncrepl-blocks for mmr hosts
    mmr_on_config = ""
    mmr_replicator_acl = ""
    mmr_serverids_config = ""
    mmr_syncrepl_schema_config = "" 
    mmr_syncrepl_config_config = "" 
    mmr_syncrepl_user_config = "" 
       
    
    if ol_mmr_urls is not None:
        # For now, make these equal
        mmr_pass = ldapadminpass
        
        url_list=filter(None,ol_mmr_urls.split(' ')) 
        if (len(url_list) == 1):
            url_list=filter(None,ol_mmr_urls.split(',')) 
                     
            
            mmr_on_config = "MirrorMode On"
            mmr_replicator_acl = "  by dn=cn=replicator,cn=samba read"
            serverid=0
            for url in url_list:
                serverid=serverid+1
                mmr_serverids_config += read_and_sub_file(setup_path("mmr_serverids.conf"),
                                                          { "SERVERID" : str(serverid),
                                                            "LDAPSERVER" : url })
                rid=serverid*10
                rid=rid+1
                mmr_syncrepl_schema_config += read_and_sub_file(setup_path("mmr_syncrepl.conf"),
                                                                {  "RID" : str(rid),
                                                                   "MMRDN": names.schemadn,
                                                                   "LDAPSERVER" : url,
                                                                   "MMR_PASSWORD": mmr_pass})
                
                rid=rid+1
                mmr_syncrepl_config_config += read_and_sub_file(setup_path("mmr_syncrepl.conf"),
                                                                {  "RID" : str(rid),
                                                                   "MMRDN": names.configdn,
                                                                   "LDAPSERVER" : url,
                                                                   "MMR_PASSWORD": mmr_pass})
                
                rid=rid+1
                mmr_syncrepl_user_config += read_and_sub_file(setup_path("mmr_syncrepl.conf"),
                                                              {  "RID" : str(rid),
                                                                 "MMRDN": names.domaindn,
                                                                 "LDAPSERVER" : url,
                                                                 "MMR_PASSWORD": mmr_pass })
    # OpenLDAP cn=config initialisation
    olc_syncrepl_config = ""
    olc_mmr_config = "" 
    # if mmr = yes, generate cn=config-replication directives
    # and olc_seed.lif for the other mmr-servers
    if ol_mmr_urls is not None:
        serverid=0
        olc_serverids_config = ""
        olc_syncrepl_seed_config = ""
        olc_mmr_config += read_and_sub_file(setup_path("olc_mmr.conf"),{})
        rid=1000
        for url in url_list:
            serverid=serverid+1
            olc_serverids_config += read_and_sub_file(setup_path("olc_serverid.conf"),
                                                      { "SERVERID" : str(serverid),
                                                        "LDAPSERVER" : url })
            
            rid=rid+1
            olc_syncrepl_config += read_and_sub_file(setup_path("olc_syncrepl.conf"),
                                                     {  "RID" : str(rid),
                                                        "LDAPSERVER" : url,
                                                        "MMR_PASSWORD": mmr_pass})
            
            olc_syncrepl_seed_config += read_and_sub_file(setup_path("olc_syncrepl_seed.conf"),
                                                          {  "RID" : str(rid),
                                                             "LDAPSERVER" : url})
                
        setup_file(setup_path("olc_seed.ldif"), result.paths.olcseedldif,
                   {"OLC_SERVER_ID_CONF": olc_serverids_config,
                    "OLC_PW": ldapadminpass,
                    "OLC_SYNCREPL_CONF": olc_syncrepl_seed_config})
    # end olc
                
    setup_file(setup_path("slapd.conf"), result.paths.slapdconf,
               {"DNSDOMAIN": names.dnsdomain,
                "LDAPDIR": result.paths.ldapdir,
                "DOMAINDN": names.domaindn,
                "CONFIGDN": names.configdn,
                "SCHEMADN": names.schemadn,
                "MEMBEROF_CONFIG": memberof_config,
                "MIRRORMODE": mmr_on_config,
                "REPLICATOR_ACL": mmr_replicator_acl,
                "MMR_SERVERIDS_CONFIG": mmr_serverids_config,
                "MMR_SYNCREPL_SCHEMA_CONFIG": mmr_syncrepl_schema_config,
                "MMR_SYNCREPL_CONFIG_CONFIG": mmr_syncrepl_config_config,
                "MMR_SYNCREPL_USER_CONFIG": mmr_syncrepl_user_config,
                "OLC_SYNCREPL_CONFIG": olc_syncrepl_config,
                "OLC_MMR_CONFIG": olc_mmr_config,
                "REFINT_CONFIG": refint_config,
                "INDEX_CONFIG": index_config,
                "NOSYNC": nosync_config})
        
    setup_db_config(setup_path, os.path.join(result.paths.ldapdir, "db", "user"))
    setup_db_config(setup_path, os.path.join(result.paths.ldapdir, "db", "config"))
    setup_db_config(setup_path, os.path.join(result.paths.ldapdir, "db", "schema"))
    
    if not os.path.exists(os.path.join(result.paths.ldapdir, "db", "samba",  "cn=samba")):
        os.makedirs(os.path.join(result.paths.ldapdir, "db", "samba",  "cn=samba"), 0700)
        
    setup_file(setup_path("cn=samba.ldif"), 
               os.path.join(result.paths.ldapdir, "db", "samba",  "cn=samba.ldif"),
               { "UUID": str(uuid.uuid4()), 
                 "LDAPTIME": timestring(int(time.time()))} )
    setup_file(setup_path("cn=samba-admin.ldif"), 
               os.path.join(result.paths.ldapdir, "db", "samba",  "cn=samba", "cn=samba-admin.ldif"),
               {"LDAPADMINPASS_B64": b64encode(ldapadminpass),
                "UUID": str(uuid.uuid4()), 
                "LDAPTIME": timestring(int(time.time()))} )
    
    if ol_mmr_urls is not None:
        setup_file(setup_path("cn=replicator.ldif"),
                   os.path.join(result.paths.ldapdir, "db", "samba",  "cn=samba", "cn=replicator.ldif"),
                   {"MMR_PASSWORD_B64": b64encode(mmr_pass),
                    "UUID": str(uuid.uuid4()),
                    "LDAPTIME": timestring(int(time.time()))} )
        

    mapping = "schema-map-openldap-2.3"
    backend_schema = "backend-schema.schema"

    backend_schema_data = schema.ldb.convert_schema_to_openldap("openldap", open(setup_path(mapping), 'r').read())
    assert backend_schema_data is not None
    open(os.path.join(result.paths.ldapdir, backend_schema), 'w').write(backend_schema_data)

    # now we generate the needed strings to start slapd automatically,
    # first ldapi_uri...
    if ldap_backend_extra_port is not None:
        # When we use MMR, we can't use 0.0.0.0 as it uses the name
        # specified there as part of it's clue as to it's own name,
        # and not to replicate to itself
        if ol_mmr_urls is None:
            server_port_string = "ldap://0.0.0.0:%d" % ldap_backend_extra_port
        else:
            server_port_string = "ldap://" + names.hostname + "." + names.dnsdomain +":%d" % ldap_backend_extra_port
    else:
        server_port_string = ""

    # Prepare the 'result' information - the commands to return in particular
    result.slapd_provision_command = [slapd_path]

    result.slapd_provision_command.append("-F" + result.paths.olcdir)

    result.slapd_provision_command.append("-h")

    # copy this command so we have two version, one with -d0 and only ldapi, and one with all the listen commands
    result.slapd_command = list(result.slapd_provision_command)
    
    result.slapd_provision_command.append(result.ldapi_uri)
    result.slapd_provision_command.append("-d0")

    uris = result.ldapi_uri
    if server_port_string is not "":
        uris = uris + " " + server_port_string

    result.slapd_command.append(uris)

    # Set the username - done here because Fedora DS still uses the admin DN and simple bind
    result.credentials.set_username("samba-admin")
    
    # If we were just looking for crashes up to this point, it's a
    # good time to exit before we realise we don't have OpenLDAP on
    # this system
    if ldap_dryrun_mode:
        sys.exit(0)

    # Finally, convert the configuration into cn=config style!
    if not os.path.isdir(result.paths.olcdir):
        os.makedirs(result.paths.olcdir, 0770)

        retcode = subprocess.call([slapd_path, "-Ttest", "-f", result.paths.slapdconf, "-F", result.paths.olcdir], close_fds=True, shell=False)

#        We can't do this, as OpenLDAP is strange.  It gives an error
#        output to the above, but does the conversion sucessfully...
#
#        if retcode != 0:
#            raise ProvisioningError("conversion from slapd.conf to cn=config failed")

        if not os.path.exists(os.path.join(result.paths.olcdir, "cn=config.ldif")):
            raise ProvisioningError("conversion from slapd.conf to cn=config failed")

        # Don't confuse the admin by leaving the slapd.conf around
        os.remove(result.paths.slapdconf)        


def provision_fds_backend(result, setup_path=None, names=None,
                          message=None, 
                          hostname=None, ldapadminpass=None, root=None, 
                          schema=None,
                          ldap_backend_extra_port=None,
                          setup_ds_path=None,
                          slapd_path=None,
                          nosync=False, 
                          ldap_dryrun_mode=False,
                          domainsid=None):

    if ldap_backend_extra_port is not None:
        serverport = "ServerPort=%d" % ldap_backend_extra_port
    else:
        serverport = ""
        
    setup_file(setup_path("fedorads.inf"), result.paths.fedoradsinf, 
               {"ROOT": root,
                "HOSTNAME": hostname,
                "DNSDOMAIN": names.dnsdomain,
                "LDAPDIR": result.paths.ldapdir,
                "DOMAINDN": names.domaindn,
                "LDAPMANAGERDN": names.ldapmanagerdn,
                "LDAPMANAGERPASS": ldapadminpass, 
                "SERVERPORT": serverport})

    setup_file(setup_path("fedorads-partitions.ldif"), result.paths.fedoradspartitions, 
               {"CONFIGDN": names.configdn,
                "SCHEMADN": names.schemadn,
                "SAMBADN": names.sambadn,
                })

    setup_file(setup_path("fedorads-sasl.ldif"), result.paths.fedoradssasl, 
               {"SAMBADN": names.sambadn,
                })

    setup_file(setup_path("fedorads-dna.ldif"), result.paths.fedoradsdna, 
               {"DOMAINDN": names.domaindn,
                "SAMBADN": names.sambadn,
                "DOMAINSID": str(domainsid),
                })

    setup_file(setup_path("fedorads-pam.ldif"), result.paths.fedoradspam)

    lnkattr = schema.linked_attributes()

    refint_config = data = open(setup_path("fedorads-refint-delete.ldif"), 'r').read()
    memberof_config = ""
    index_config = ""
    argnum = 3

    for attr in lnkattr.keys():
        if lnkattr[attr] is not None:
            refint_config += read_and_sub_file(setup_path("fedorads-refint-add.ldif"),
                                                 { "ARG_NUMBER" : str(argnum) ,
                                                   "LINK_ATTR" : attr })
            memberof_config += read_and_sub_file(setup_path("fedorads-linked-attributes.ldif"),
                                                 { "MEMBER_ATTR" : attr ,
                                                   "MEMBEROF_ATTR" : lnkattr[attr] })
            index_config += read_and_sub_file(setup_path("fedorads-index.ldif"),
                                                 { "ATTR" : attr })
            argnum += 1

    open(result.paths.fedoradsrefint, 'w').write(refint_config)
    open(result.paths.fedoradslinkedattributes, 'w').write(memberof_config)

    attrs = ["lDAPDisplayName"]
    res = schema.ldb.search(expression="(&(objectclass=attributeSchema)(searchFlags:1.2.840.113556.1.4.803:=1))", base=names.schemadn, scope=SCOPE_ONELEVEL, attrs=attrs)

    for i in range (0, len(res)):
        attr = res[i]["lDAPDisplayName"][0]

        if attr == "objectGUID":
            attr = "nsUniqueId"

        index_config += read_and_sub_file(setup_path("fedorads-index.ldif"),
                                             { "ATTR" : attr })

    open(result.paths.fedoradsindex, 'w').write(index_config)

    setup_file(setup_path("fedorads-samba.ldif"), result.paths.fedoradssamba,
                {"SAMBADN": names.sambadn, 
                 "LDAPADMINPASS": ldapadminpass
                })

    mapping = "schema-map-fedora-ds-1.0"
    backend_schema = "99_ad.ldif"
    
    # Build a schema file in Fedora DS format
    backend_schema_data = schema.ldb.convert_schema_to_openldap("fedora-ds", open(setup_path(mapping), 'r').read())
    assert backend_schema_data is not None
    open(os.path.join(result.paths.ldapdir, backend_schema), 'w').write(backend_schema_data)

    result.credentials.set_bind_dn(names.ldapmanagerdn)

    # Destory the target directory, or else setup-ds.pl will complain
    fedora_ds_dir = os.path.join(result.paths.ldapdir, "slapd-samba4")
    shutil.rmtree(fedora_ds_dir, True)

    result.slapd_provision_command = [slapd_path, "-D", fedora_ds_dir, "-i", result.paths.slapdpid];
    #In the 'provision' command line, stay in the foreground so we can easily kill it
    result.slapd_provision_command.append("-d0")

    #the command for the final run is the normal script
    result.slapd_command = [os.path.join(result.paths.ldapdir, "slapd-samba4", "start-slapd")]

    # If we were just looking for crashes up to this point, it's a
    # good time to exit before we realise we don't have Fedora DS on
    if ldap_dryrun_mode:
        sys.exit(0)

    # Try to print helpful messages when the user has not specified the path to the setup-ds tool
    if setup_ds_path is None:
        raise ProvisioningError("Warning: Fedora DS LDAP-Backend must be setup with path to setup-ds, e.g. --setup-ds-path=\"/usr/sbin/setup-ds.pl\"!")
    if not os.path.exists(setup_ds_path):
        message (setup_ds_path)
        raise ProvisioningError("Warning: Given Path to slapd does not exist!")

    # Run the Fedora DS setup utility
    retcode = subprocess.call([setup_ds_path, "--silent", "--file", result.paths.fedoradsinf], close_fds=True, shell=False)
    if retcode != 0:
        raise ProvisioningError("setup-ds failed")

    # Load samba-admin
    retcode = subprocess.call([
        os.path.join(result.paths.ldapdir, "slapd-samba4", "ldif2db"), "-s", names.sambadn, "-i", result.paths.fedoradssamba],
        close_fds=True, shell=False)
    if retcode != 0:
        raise("ldib2db failed")


class FDSBackend(LDAPBackend):
    def post_setup(self):
        ldapi_db = Ldb(self.ldapi_uri, credentials=self.credentials)

        # delete default SASL mappings
        res = ldapi_db.search(expression="(!(cn=samba-admin mapping))", base="cn=mapping,cn=sasl,cn=config", scope=SCOPE_ONELEVEL, attrs=["dn"])
    
        # configure in-directory access control on Fedora DS via the aci attribute (over a direct ldapi:// socket)
        for i in range (0, len(res)):
            dn = str(res[i]["dn"])
            ldapi_db.delete(dn)
            
            aci = """(targetattr = "*") (version 3.0;acl "full access to all by samba-admin";allow (all)(userdn = "ldap:///CN=samba-admin,%s");)""" % self.names.sambadn
        
            m = ldb.Message()
            m["aci"] = ldb.MessageElement([aci], ldb.FLAG_MOD_REPLACE, "aci")

            m.dn = ldb.Dn(1, self.names.domaindn)
            ldapi_db.modify(m)
            
            m.dn = ldb.Dn(1, self.names.configdn)
            ldapi_db.modify(m)
            
            m.dn = ldb.Dn(1, self.names.schemadn)
            ldapi_db.modify(m)
