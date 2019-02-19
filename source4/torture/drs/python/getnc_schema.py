import drs_base
import ldb
import time
from samba.dcerpc import misc
from samba.drs_utils import drs_Replicate, drsException
import samba
import random
import time
import os

break_me = os.getenv("PLEASE_BREAK_MY_WINDOWS") == "1"
assert break_me, ("This test breaks Windows active directory after "
                  "a few runs.  Set PLEASE_BREAK_MY_WINDOWS=1 to run.")

# This test runs against Windows.  To run, set up two Windows AD DCs, join one
# to the other, and make sure the passwords are the same.  SMB_CONF_PATH must
# also be set to any smb.conf file. Set DC1 to the PDC's hostname, and DC2 to
# the join'd DC's hostname. Example:
# PLEASE_BREAK_MY_WINDOWS=1
# DC1=pdc DC2=joindc
# SMB_CONF_PATH=st/ad_dc/etc/smb.conf
# PYTHONPATH=$PYTHONPATH:./source4/torture/drs/python
# python3 ./source4/scripting/bin/subunitrun getnc_schema
# -UAdministrator%Password

class SchemaReplicationTests(drs_base.DrsBaseTestCase):

    def setUp(self):
        super(SchemaReplicationTests, self).setUp()
        self.creds = self.get_credentials()
        self.cmdline_auth = "-U{}%{}".format(self.creds.get_username(),
                                             self.creds.get_password())

        self.from_ldb = self.ldb_dc1
        self.dest_ldb = self.ldb_dc2
        self._disable_inbound_repl(self.url_dc1)
        self._disable_all_repl(self.url_dc1)
        self.free_offset = 0

    def tearDown(self):
        self._enable_inbound_repl(self.url_dc1)
        self._enable_all_repl(self.url_dc1)

    def do_repl(self, partition_dn):
        self._enable_inbound_repl(self.url_dc1)
        self._enable_all_repl(self.url_dc1)

        samba_tool_cmd = ["drs", "replicate", self.url_dc2, self.url_dc1]
        samba_tool_cmd += [partition_dn]
        username = self.creds.get_username()
        password = self.creds.get_password()
        samba_tool_cmd += ["-U{0}%{1}".format(username, password)]

        (result, out, err) = self.runsubcmd(*samba_tool_cmd)

        try:
            self.assertCmdSuccess(result, out, err)
        except AssertionError:
            print("Failed repl, retrying in 10s")
            time.sleep(10)
            (result, out, err) = self.runsubcmd(*samba_tool_cmd)

        self._disable_inbound_repl(self.url_dc1)
        self._disable_all_repl(self.url_dc1)

        self.assertCmdSuccess(result, out, err)

    # Get a unique prefix for some search expression like "([att]=[pref]{i}*)"
    def get_unique(self, expr_templ):
        found = True
        while found:
            i = random.randint(0, 65535)
            res = self.from_ldb.search(base=self.schema_dn,
                                       scope=ldb.SCOPE_SUBTREE,
                                       expression=expr_templ.format(i=i))
            found = len(res) > 0

        return str(i)

    def unique_gov_id_prefix(self):
        prefix = "1.3.6.1.4.1.7165.4.6.2.8."
        return prefix + self.get_unique("(governsId=" + prefix + "{i}.*)")

    def unique_cn_prefix(self, prefix="testobj"):
        return prefix + self.get_unique("(cn=" + prefix + "{i}x*)") + "x"

    # Make test schema classes linked to each other in a line, then modify
    # them in reverse order so when we repl, a link crosses the chunk
    # boundary.  Chunk size is 133 by default so we do 150.
    def test_poss_superiors_across_chunk(self):
        num_schema_objects_to_add = 150
        class_name = self.unique_cn_prefix()

        ldif_template = """
dn: CN={class_name}{i},{schema_dn}
objectClass: top
objectClass: classSchema
adminDescription: {class_name}{i}
adminDisplayName: {class_name}{i}
cn: {class_name}{i}
governsId: {gov_id}.{i}
instanceType: 4
objectClassCategory: 1
systemFlags: 16
systemOnly: FALSE
"""

        ldif_kwargs = {'class_name': class_name,
                       'schema_dn': self.schema_dn}
        gov_id = self.unique_gov_id_prefix()
        ldif = ldif_template.format(i=0, gov_id=gov_id, **ldif_kwargs)
        self.from_ldb.add_ldif(ldif)

        ldif_template += "systemPossSuperiors: {possSup}\n"

        ids = list(range(num_schema_objects_to_add))
        got_no_such_attrib = False
        for i in ids[1:]:
            last_class_name = class_name + str(i-1)
            ldif = ldif_template.format(i=i, gov_id=gov_id,
                                        possSup=last_class_name,
                                        **ldif_kwargs)

            try:
                self.from_ldb.add_ldif(ldif)
                if got_no_such_attrib:
                    self.from_ldb.set_schema_update_now()
            except ldb.LdbError as e:
                if e.args[0] != ldb.ERR_NO_SUCH_ATTRIBUTE:
                    self.fail(e)
                if got_no_such_attrib:
                    self.fail(("got NO_SUCH_ATTRIB even after "
                               "setting schemaUpdateNow", str(e)))
                print("got NO_SUCH_ATTRIB, trying schemaUpdateNow")
                got_no_such_attrib = True
                self.from_ldb.set_schema_update_now()
                self.from_ldb.add_ldif(ldif)
                self.from_ldb.set_schema_update_now()

        ldif_template = """
dn: CN={class_name}{i},{schema_dn}
changetype: modify
replace: adminDescription
adminDescription: new_description
"""

        for i in reversed(ids):
            ldif = ldif_template.format(i=i, **ldif_kwargs)
            self.from_ldb.modify_ldif(ldif)

        self.do_repl(self.schema_dn)

        dn_templ = "CN={class_name}{i},{schema_dn}"
        for i in ids:
            dn = dn_templ.format(i=i, **ldif_kwargs)
            res = self.dest_ldb.search(base=dn, scope=ldb.SCOPE_BASE)
            self.assertEqual(len(res), 1)

    # Test for method of adding linked attributes in schema partition
    # required by other tests.
    def test_create_linked_attribute_in_schema(self):
        # Make an object outside of the schema partition that we can link to
        user_name = self.unique_cn_prefix("user")
        user_dn = "CN={},CN=Users,{}".format(user_name, self.domain_dn)

        ldif_template = """
dn: {user_dn}
objectClass: person
objectClass: user"""
        ldif = ldif_template.format(user_dn=user_dn)
        self.from_ldb.add_ldif(ldif)

        # Make test class name unique so test can run multiple times
        class_name = self.unique_cn_prefix("class")

        kwargs = {'class_name': class_name,
                  'schema_dn': self.schema_dn,
                  'user_dn': user_dn}

        # Add an auxiliary schemaClass (cat 3) class and give it managedBy
        # so we can create schema objects with linked attributes.
        ldif_template = """
dn: CN={class_name},{schema_dn}
objectClass: classSchema
governsId: {gov_id}.0
instanceType: 4
systemFlags: 16
systemOnly: FALSE
objectClassCategory: 3
mayContain: managedBy
"""

        gov_id = self.unique_gov_id_prefix()
        ldif = ldif_template.format(gov_id=gov_id, **kwargs)
        self.from_ldb.add_ldif(ldif)

        # Now make an instance that points back to the user with managedBy,
        # thus creating an object in the schema with a linked attribute
        ldif_template = """
dn: CN=link{class_name},{schema_dn}
objectClass: classSchema
objectClass: {class_name}
instanceType: 4
governsId: {gov_id}.0
systemFlags: 16
managedBy: {user_dn}
"""

        gov_id = self.unique_gov_id_prefix()
        ldif = ldif_template.format(gov_id=gov_id, **kwargs)
        self.from_ldb.add_ldif(ldif)

        # Check link exists on test schema object
        dn_templ = "CN=link{class_name},{schema_dn}"
        dn = dn_templ.format(**kwargs)
        res = self.from_ldb.search(base=dn, scope=ldb.SCOPE_BASE)
        self.assertEqual(len(res), 1)
        self.assertIsNotNone(res[0].get("managedBy"))
        self.assertEqual(str(res[0].get("managedBy")[0]), user_dn)

        # Check backlink on user object
        res = self.from_ldb.search(base=user_dn, scope=ldb.SCOPE_BASE)
        self.assertEqual(len(res), 1)
        managed_objs = res[0].get("managedObjects")
        self.assertEqual(len(managed_objs), 1)
        managed_objs = [str(o) for o in managed_objs]
        self.assertEqual(managed_objs, [dn_templ.format(**kwargs)])

    def test_schema_linked_attributes(self):
        num_test_objects = 9

        # Make an object outside of the schema partition that we can link to
        user_name = self.unique_cn_prefix("user")
        user_dn = "CN={},CN=Users,{}".format(user_name, self.domain_dn)

        ldif_template = """
dn: {user_dn}
objectClass: person
objectClass: user"""
        ldif = ldif_template.format(user_dn=user_dn)
        self.from_ldb.add_ldif(ldif)

        self.do_repl(self.domain_dn)

        # Make test object name prefixes unique so test can run multiple times
        # in a single testenv (can't delete schema objects)
        class_name = self.unique_cn_prefix("class")
        link_class_name = self.unique_cn_prefix("linkClass")

        kwargs = {'class_name': class_name,
                  'schema_dn': self.schema_dn,
                  'link_class_name': link_class_name,
                  'user_dn': user_dn}

        # Add an auxiliary schemaClass (cat 3) class and give it managedBy
        # so we can create schema objects with linked attributes.
        ldif_template = """
dn: CN={class_name},{schema_dn}
objectClass: classSchema
governsId: {gov_id}.0
instanceType: 4
systemFlags: 16
systemOnly: FALSE
objectClassCategory: 3
mayContain: managedBy
"""

        gov_id = self.unique_gov_id_prefix()
        ldif = ldif_template.format(gov_id=gov_id, **kwargs)
        self.from_ldb.add_ldif(ldif)

        # Now make instances that point back to the user with managedBy,
        # thus creating objects in the schema with linked attributes
        ldif_template = """
dn: CN={link_class_name}{i},{schema_dn}
objectClass: classSchema
objectClass: {class_name}
instanceType: 4
governsId: {gov_id}.0
systemFlags: 16
managedBy: {user_dn}
"""

        id_range = list(range(num_test_objects))
        for i in id_range:
            gov_id = self.unique_gov_id_prefix()
            ldif = ldif_template.format(i=i, gov_id=gov_id, **kwargs)
            self.from_ldb.add_ldif(ldif)

        self.do_repl(self.schema_dn)

        # Check link exists in each test schema objects at destination DC
        dn_templ = "CN={link_class_name}{i},{schema_dn}"
        for i in id_range:
            dn = dn_templ.format(i=i, **kwargs)
            res = self.dest_ldb.search(base=dn, scope=ldb.SCOPE_BASE)
            self.assertEqual(len(res), 1)
            self.assertIsNotNone(res[0].get("managedBy"))
            self.assertEqual(str(res[0].get("managedBy")[0]), user_dn)

        # Check backlinks list on user object contains DNs of test objects.
        res = self.dest_ldb.search(base=user_dn, scope=ldb.SCOPE_BASE)
        self.assertEqual(len(res), 1)
        managed_objs = res[0].get("managedObjects")
        self.assertIsNotNone(managed_objs)
        managed_objs_set = {str(el) for el in managed_objs}
        expected = {dn_templ.format(i=i, **kwargs) for i in id_range}
        self.assertEqual(managed_objs_set, expected)
