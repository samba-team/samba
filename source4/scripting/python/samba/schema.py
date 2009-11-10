#
# Unix SMB/CIFS implementation.
# backend code for provisioning a Samba4 server
#
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

"""Functions for setting up a Samba Schema."""

from base64 import b64encode
from ms_schema import read_ms_schema
from samba.dcerpc import security
from samba import read_and_sub_file, substitute_var, check_all_substituted
from samba import Ldb
from samba.ndr import ndr_pack
from ldb import SCOPE_SUBTREE, SCOPE_ONELEVEL, SCOPE_BASE
import os

def get_schema_descriptor(domain_sid):
    sddl = "O:SAG:SAD:(A;CI;RPLCLORC;;;AU)(A;CI;RPWPCRCCLCLORCWOWDSW;;;SA)" \
           "(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)" \
           "(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
           "(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)" \
           "(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
           "(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)" \
           "S:(AU;SA;WPCCDCWOWDSDDTSW;;;WD)" \
           "(AU;CISA;WP;;;WD)(AU;SA;CR;;;BA)" \
           "(AU;SA;CR;;;DU)(OU;SA;CR;e12b56b6-0a95-11d1-adbb-00c04fd8d5cd;;WD)" \
           "(OU;SA;CR;45ec5156-db7e-47bb-b53f-dbeb2d03c40f;;WD)"
    sec = security.descriptor.from_sddl(sddl, domain_sid)
    return b64encode(ndr_pack(sec))

   
class Schema(object):
    def __init__(self, setup_path, domain_sid, schemadn=None,
                 serverdn=None):
        """Load schema for the SamDB from the AD schema files and samba4_schema.ldif
        
        :param samdb: Load a schema into a SamDB.
        :param setup_path: Setup path function.
        :param schemadn: DN of the schema
        :param serverdn: DN of the server
        
        Returns the schema data loaded, to avoid double-parsing when then needing to add it to the db
        """

        self.schemadn = schemadn
        self.ldb = Ldb()
        self.schema_data = read_ms_schema(setup_path('ad-schema/MS-AD_Schema_2K8_Attributes.txt'),
                                          setup_path('ad-schema/MS-AD_Schema_2K8_Classes.txt'))
        self.schema_data += open(setup_path("schema_samba4.ldif"), 'r').read()
        self.schema_data = substitute_var(self.schema_data, {"SCHEMADN": schemadn})
        check_all_substituted(self.schema_data)

        self.schema_dn_modify = read_and_sub_file(setup_path("provision_schema_basedn_modify.ldif"),
                                                  {"SCHEMADN": schemadn,
                                                   "SERVERDN": serverdn,
                                                   })

        descr = get_schema_descriptor(domain_sid)
        self.schema_dn_add = read_and_sub_file(setup_path("provision_schema_basedn.ldif"),
                                               {"SCHEMADN": schemadn,
                                                "DESCRIPTOR": descr
                                                })

        prefixmap = open(setup_path("prefixMap.txt"), 'r').read()
        prefixmap = b64encode(prefixmap)

        

        # We don't actually add this ldif, just parse it
        prefixmap_ldif = "dn: cn=schema\nprefixMap:: %s\n\n" % prefixmap
        self.ldb.set_schema_from_ldif(prefixmap_ldif, self.schema_data)

    def write_to_tmp_ldb(self, schemadb_path):
        self.ldb.connect(schemadb_path)
        self.ldb.transaction_start()
    
        self.ldb.add_ldif("""dn: @ATTRIBUTES
linkID: INTEGER

dn: @INDEXLIST
@IDXATTR: linkID
@IDXATTR: attributeSyntax
""")
        # These bits of LDIF are supplied when the Schema object is created
        self.ldb.add_ldif(self.schema_dn_add)
        self.ldb.modify_ldif(self.schema_dn_modify)
        self.ldb.add_ldif(self.schema_data)
        self.ldb.transaction_commit()

    # Return a hash with the forward attribute as a key and the back as the value 
    def linked_attributes(self):
        return get_linked_attributes(self.schemadn, self.ldb)

    def dnsyntax_attributes(self):
        return get_dnsyntax_attributes(self.schemadn, self.ldb)

# Return a hash with the forward attribute as a key and the back as the value 
def get_linked_attributes(schemadn,schemaldb):
    attrs = ["linkID", "lDAPDisplayName"]
    res = schemaldb.search(expression="(&(linkID=*)(!(linkID:1.2.840.113556.1.4.803:=1))(objectclass=attributeSchema)(attributeSyntax=2.5.5.1))", base=schemadn, scope=SCOPE_ONELEVEL, attrs=attrs)
    attributes = {}
    for i in range (0, len(res)):
        expression = "(&(objectclass=attributeSchema)(linkID=%d)(attributeSyntax=2.5.5.1))" % (int(res[i]["linkID"][0])+1)
        target = schemaldb.searchone(basedn=schemadn, 
                                     expression=expression, 
                                     attribute="lDAPDisplayName", 
                                     scope=SCOPE_SUBTREE)
        if target is not None:
            attributes[str(res[i]["lDAPDisplayName"])]=str(target)
            
    return attributes

def get_dnsyntax_attributes(schemadn,schemaldb):
    attrs = ["linkID", "lDAPDisplayName"]
    res = schemaldb.search(expression="(&(!(linkID=*))(objectclass=attributeSchema)(attributeSyntax=2.5.5.1))", base=schemadn, scope=SCOPE_ONELEVEL, attrs=attrs)
    attributes = []
    for i in range (0, len(res)):
        attributes.append(str(res[i]["lDAPDisplayName"]))
        
    return attributes

def ldb_with_schema(setup_dir=None, schemadn="cn=schema,cn=configuration,dc=example,dc=com", 
                    serverdn="cn=server,cn=servers,cn=default-first-site-name,cn=sites,cn=cn=configuration,dc=example,dc=com",
                    domainsid=None):
    """Load schema for the SamDB from the AD schema files and samba4_schema.ldif
    
    :param setup_dir: Setup path
    :param schemadn: DN of the schema
    :param serverdn: DN of the server
    
    Returns the schema data loaded as an object, with .ldb being a
    new ldb with the schema loaded.  This allows certain tests to
    operate without a remote or local schema.
    """
    
    def setup_path(file):
        return os.path.join(setup_dir, file)

    if domainsid is None:
        domainsid = security.random_sid()
    else:
        domainsid = security.dom_sid(domainsid)
    return Schema(setup_path, domainsid, schemadn=schemadn, serverdn=serverdn)
