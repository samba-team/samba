
# Unix SMB/CIFS implementation.
# backend code for provisioning a Samba4 server

# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2010
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2008-2009
# Copyright (C) Oliver Liebel <oliver@itc.li> 2008-2009
# Copyright (C) Amitay Isaacs <amitay@samba.org> 2011
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

"""Functions for setting up a Samba configuration (security descriptors)."""

from samba.dcerpc import security
from samba.ndr import ndr_pack

# Descriptors of naming contexts and other important objects

def sddl2binary(sddl_in, domain_sid, name_map):
    sddl = "%s" % sddl_in

    for [name, sid] in name_map.items():
        sddl = sddl.replace(name, sid)

    sec = security.descriptor.from_sddl(sddl, domain_sid)
    return ndr_pack(sec)

def get_empty_descriptor(domain_sid, name_map={}):
    sddl= ""
    return sddl2binary(sddl, domain_sid, name_map)

# "get_schema_descriptor" is located in "schema.py"

def get_config_descriptor(domain_sid, name_map={}):
    sddl = "O:EAG:EAD:(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
           "(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
           "(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
           "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
           "(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
           "(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
           "(A;;RPLCLORC;;;AU)(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)" \
           "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;CIIO;RPWPCRCCLCLORCWOWDSDSW;;;DA)" \
           "(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
           "(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)" \
           "(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
           "(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)" \
           "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ER)" \
           "S:(AU;SA;WPWOWD;;;WD)(AU;SA;CR;;;BA)(AU;SA;CR;;;DU)" \
           "(OU;SA;CR;45ec5156-db7e-47bb-b53f-dbeb2d03c40f;;WD)"
    return sddl2binary(sddl, domain_sid, name_map)

def get_config_partitions_descriptor(domain_sid, name_map={}):
    sddl = "D:" \
    "(A;;LCLORC;;;AU)" \
    "(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)" \
    "(OA;;RP;d31a8757-2447-4545-8081-3bb610cacbf2;;AU)" \
    "(OA;;RP;66171887-8f3c-11d0-afda-00c04fd930c9;;AU)" \
    "(OA;;RP;032160bf-9824-11d1-aec0-0000f80367c1;;AU)" \
    "(OA;;RP;789ee1eb-8c8e-4e4c-8cec-79b31b7617b5;;AU)" \
    "(OA;;RP;5706aeaf-b940-4fb2-bcfc-5268683ad9fe;;AU)" \
    "(A;;RPWPCRCCLCLORCWOWDSW;;;EA)" \
    "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)" \
    "(A;;CC;;;ED)" \
    "(OA;CIIO;WP;3df793df-9858-4417-a701-735a1ecebf74;bf967a8d-0de6-11d0-a285-00aa003049e2;BA)" \
    "S:" \
    "(AU;CISA;WPCRCCDCWOWDSDDT;;;WD)"
    return sddl2binary(sddl, domain_sid, name_map)

def get_config_sites_descriptor(domain_sid, name_map={}):
    sddl = "D:" \
    "(A;;RPLCLORC;;;AU)" \
    "(OA;CIIO;SW;d31a8757-2447-4545-8081-3bb610cacbf2;f0f8ffab-1191-11d0-a060-00aa006c33ed;ER)" \
    "(A;;RPWPCRCCLCLORCWOWDSW;;;EA)" \
    "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)" \
    "S:" \
    "(AU;CISA;CCDCSDDT;;;WD)" \
    "(OU;CIIOSA;CR;;f0f8ffab-1191-11d0-a060-00aa006c33ed;WD)" \
    "(OU;CIIOSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967ab3-0de6-11d0-a285-00aa003049e2;WD)" \
    "(OU;CIIOSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967ab3-0de6-11d0-a285-00aa003049e2;WD)" \
    "(OU;CIIOSA;WP;3e10944c-c354-11d0-aff8-0000f80367c1;b7b13124-b82e-11d0-afee-0000f80367c1;WD)"
    return sddl2binary(sddl, domain_sid, name_map)

def get_config_ntds_quotas_descriptor(domain_sid, name_map={}):
    sddl = "D:" \
    "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)" \
    "(A;;RPLCLORC;;;BA)" \
    "(OA;;CR;4ecc03fe-ffc0-4947-b630-eb672a8a9dbc;;WD)"
    return sddl2binary(sddl, domain_sid, name_map)

def get_config_delete_protected1_descriptor(domain_sid, name_map={}):
    sddl = "D:AI" \
    "(A;;RPLCLORC;;;AU)" \
    "(A;;RPWPCRCCLCLORCWOWDSW;;;EA)" \
    "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
    return sddl2binary(sddl, domain_sid, name_map)

def get_config_delete_protected1wd_descriptor(domain_sid, name_map={}):
    sddl = "D:AI" \
    "(A;;RPLCLORC;;;WD)" \
    "(A;;RPWPCRCCLCLORCWOWDSW;;;EA)" \
    "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
    return sddl2binary(sddl, domain_sid, name_map)

def get_config_delete_protected2_descriptor(domain_sid, name_map={}):
    sddl = "D:AI" \
    "(A;;RPLCLORC;;;AU)" \
    "(A;;RPWPCRCCDCLCLORCWOWDSW;;;EA)" \
    "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
    return sddl2binary(sddl, domain_sid, name_map)

def get_domain_descriptor(domain_sid, name_map={}):
    sddl= "O:BAG:BAD:AI(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
        "(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
    "(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
    "(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
    "(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
    "(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ER)" \
    "(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;DD)" \
    "(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)" \
    "(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)" \
    "(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)" \
    "(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)" \
    "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
    "(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
    "(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
    "(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
    "(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
    "(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;IF)" \
    "(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)" \
    "(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)" \
    "(OA;CIIO;RPLCLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
    "(OA;CIIO;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;CIIO;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)" \
    "(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)" \
    "(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)" \
    "(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)" \
    "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
    "(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
    "(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
    "(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
    "(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)" \
    "(OA;CIIO;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)" \
    "(A;;RPWPCRCCLCLORCWOWDSW;;;DA)" \
    "(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)" \
    "(A;;RPRC;;;RU)" \
    "(A;CI;LC;;;RU)" \
    "(A;CI;RPWPCRCCLCLORCWOWDSDSW;;;BA)" \
    "(A;;RP;;;WD)" \
    "(A;;RPLCLORC;;;ED)" \
    "(A;;RPLCLORC;;;AU)" \
    "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)" \
    "S:AI(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)" \
    "(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)" \
    "(AU;SA;CR;;;DU)(AU;SA;CR;;;BA)(AU;SA;WPWOWD;;;WD)"
    return sddl2binary(sddl, domain_sid, name_map)

def get_domain_infrastructure_descriptor(domain_sid, name_map={}):
    sddl = "D:" \
    "(A;;RPLCLORC;;;AU)" \
    "(A;;RPWPCRCCLCLORCWOWDSW;;;DA)" \
    "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)" \
    "S:" \
    "(AU;SA;WPCR;;;WD)"
    return sddl2binary(sddl, domain_sid, name_map)

def get_domain_builtin_descriptor(domain_sid, name_map={}):
    sddl = "D:" \
    "(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
    "(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
    "(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
    "(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
    "(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
    "(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ER)" \
    "(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;DD)" \
    "(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)" \
    "(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)" \
    "(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)" \
    "(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)" \
    "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
    "(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
    "(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
    "(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
    "(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
    "(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;IF)" \
    "(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)" \
    "(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)" \
    "(OA;CIIO;RPLCLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
    "(OA;CIIO;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;CIIO;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)" \
    "(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)" \
    "(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)" \
    "(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)" \
    "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
    "(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
    "(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
    "(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
    "(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)" \
    "(OA;CIIO;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)" \
    "(A;;RPWPCRCCLCLORCWOWDSW;;;DA)" \
    "(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)" \
    "(A;;RPRC;;;RU)" \
    "(A;CI;LC;;;RU)" \
    "(A;CI;RPWPCRCCLCLORCWOWDSDSW;;;BA)" \
    "(A;;RP;;;WD)" \
    "(A;;RPLCLORC;;;ED)" \
    "(A;;RPLCLORC;;;AU)" \
    "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)" \
    "S:" \
    "(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)" \
    "(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)" \
    "(AU;SA;CR;;;DU)" \
    "(AU;SA;CR;;;BA)" \
    "(AU;SA;WPWOWD;;;WD)"
    return sddl2binary(sddl, domain_sid, name_map)

def get_domain_computers_descriptor(domain_sid, name_map={}):
    sddl = "D:" \
    "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)" \
    "(A;;RPWPCRCCDCLCLORCWOWDSW;;;DA)" \
    "(OA;;CCDC;bf967a86-0de6-11d0-a285-00aa003049e2;;AO)" \
    "(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;AO)" \
    "(OA;;CCDC;bf967a9c-0de6-11d0-a285-00aa003049e2;;AO)" \
    "(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)" \
    "(A;;RPLCLORC;;;AU)" \
    "(OA;;CCDC;4828cc14-1437-45bc-9b07-ad6f015e5f28;;AO)" \
    "S:"
    return sddl2binary(sddl, domain_sid, name_map)

def get_domain_users_descriptor(domain_sid, name_map={}):
    sddl = "D:" \
    "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)" \
    "(A;;RPWPCRCCDCLCLORCWOWDSW;;;DA)" \
    "(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;AO)" \
    "(OA;;CCDC;bf967a9c-0de6-11d0-a285-00aa003049e2;;AO)" \
    "(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)" \
    "(A;;RPLCLORC;;;AU)" \
    "(OA;;CCDC;4828cc14-1437-45bc-9b07-ad6f015e5f28;;AO)" \
    "S:"
    return sddl2binary(sddl, domain_sid, name_map)

def get_domain_controllers_descriptor(domain_sid, name_map={}):
    sddl = "D:" \
    "(A;;RPLCLORC;;;AU)" \
    "(A;;RPWPCRCCLCLORCWOWDSW;;;DA)" \
    "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)" \
    "(A;;RPLCLORC;;;ED)" \
    "S:" \
    "(AU;SA;CCDCWOWDSDDT;;;WD)" \
    "(AU;CISA;WP;;;WD)"
    return sddl2binary(sddl, domain_sid, name_map)

def get_domain_delete_protected1_descriptor(domain_sid, name_map={}):
    sddl = "D:AI" \
    "(A;;RPLCLORC;;;AU)" \
    "(A;;RPWPCRCCLCLORCWOWDSW;;;DA)" \
    "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
    return sddl2binary(sddl, domain_sid, name_map)

def get_domain_delete_protected2_descriptor(domain_sid, name_map={}):
    sddl = "D:AI" \
    "(A;;RPLCLORC;;;AU)" \
    "(A;;RPWPCRCCDCLCLORCWOWDSW;;;DA)" \
    "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
    return sddl2binary(sddl, domain_sid, name_map)

def get_dns_partition_descriptor(domain_sid, name_map={}):
    sddl = "O:SYG:BAD:AI" \
    "(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
    "(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
    "(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
    "(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
    "(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
    "(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ER)" \
    "(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)" \
    "(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)" \
    "(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)" \
    "(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)" \
    "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
    "(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
    "(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
    "(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
    "(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
    "(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;IF)" \
    "(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)" \
    "(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)" \
    "(OA;CIIO;RPLCLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
    "(OA;CIIO;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;CIIO;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)" \
    "(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)" \
    "(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)" \
    "(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)" \
    "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
    "(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
    "(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
    "(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
    "(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
    "(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)" \
    "(OA;CIIO;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)" \
    "(A;;RPWPCRCCLCLORCWOWDSW;;;DA)" \
    "(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)" \
    "(A;;RPRC;;;RU)" \
    "(A;CI;LC;;;RU)" \
    "(A;CI;RPWPCRCCLCLORCWOWDSDSW;;;BA)" \
    "(A;;RP;;;WD)" \
    "(A;;RPLCLORC;;;ED)" \
    "(A;;RPLCLORC;;;AU)" \
    "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)" \
    "S:AI" \
    "(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)" \
    "(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)" \
    "(AU;SA;CR;;;DU)(AU;SA;CR;;;BA)(AU;SA;WPWOWD;;;WD)"
    return sddl2binary(sddl, domain_sid, name_map)

def get_dns_forest_microsoft_dns_descriptor(domain_sid, name_map={}):
    sddl = "O:SYG:SYD:AI" \
    "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)" \
    "(A;CI;RPWPCRCCDCLCRCWOWDSDDTSW;;;ED)"
    return sddl2binary(sddl, domain_sid, name_map)

def get_dns_domain_microsoft_dns_descriptor(domain_sid, name_map={}):
    sddl = "O:SYG:SYD:AI" \
    "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)" \
    "(A;CI;RPWPCRCCDCLCRCWOWDSDDTSW;;;DnsAdmins)" \
    "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)" \
    "(A;CI;RPWPCRCCDCLCRCWOWDSDDTSW;;;ED)"
    return sddl2binary(sddl, domain_sid, name_map)
