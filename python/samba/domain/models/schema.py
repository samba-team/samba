# Unix SMB/CIFS implementation.
#
# Class and attribute schema models.
#
# Copyright (C) Catalyst.Net Ltd. 2023
#
# Written by Rob van der Linde <rob@catalyst.net.nz>
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

from .exceptions import NotFound
from .fields import BinaryField, BooleanField, DnField, GUIDField,\
    IntegerField, StringField
from .model import Model


class ClassSchema(Model):
    default_object_category = DnField("defaultObjectCategory")
    governs_id = StringField("governsID")
    schema_id_guid = GUIDField("schemaIDGUID")
    subclass_of = StringField("subclassOf")
    admin_description = StringField("adminDescription")
    admin_display_name = StringField("adminDisplayName")
    default_hiding_value = BooleanField("defaultHidingValue")
    default_security_descriptor = BinaryField("defaultSecurityDescriptor")
    ldap_display_name = StringField("lDAPDisplayName")
    may_contain = StringField("mayContain", many=True)
    poss_superiors = StringField("possSuperiors", many=True)
    rdn_att_id = StringField("rDNAttID")
    show_in_advanced_view_only = BooleanField("showInAdvancedViewOnly")
    system_only = BooleanField("systemOnly", readonly=True)

    @staticmethod
    def get_base_dn(samdb):
        """Return the base DN for the ClassSchema model.

        This is the same as AttributeSchema, but the objectClass is different.

        :param samdb: SamDB connection
        :return: Dn object of container
        """
        return samdb.get_schema_basedn()

    @staticmethod
    def get_object_class():
        return "classSchema"

    @classmethod
    def find(cls, samdb, name):
        """Helper function to find class by name or raise NotFound.

        :param samdb: SamDB connection
        :param name: Class name
        :raises: NotFound if not found
        :raises: ValueError if name is not provided
        """
        if not name:
            raise ValueError("Class name is required.")

        attr = cls.get(samdb, ldap_display_name=name)
        if attr is None:
            raise NotFound(f"Could not locate {name} in class schema.")

        return attr


class AttributeSchema(Model):
    attribute_id = StringField("attributeID")
    attribute_syntax = StringField("attributeSyntax")
    is_single_valued = BooleanField("isSingleValued")
    ldap_display_name = StringField("lDAPDisplayName")
    om_syntax = IntegerField("oMSyntax")
    admin_description = StringField("adminDescription")
    admin_display_name = StringField("adminDisplayName")
    attribute_security_guid = GUIDField("attributeSecurityGUID")
    schema_flags_ex = IntegerField("schemaFlagsEx")
    search_flags = IntegerField("searchFlags")
    show_in_advanced_view_only = BooleanField("showInAdvancedViewOnly")
    system_flags = IntegerField("systemFlags", readonly=True)
    system_only = BooleanField("systemOnly", readonly=True)

    @staticmethod
    def get_base_dn(samdb):
        """Return the base DN for the AttributeSchema model.

        This is the same as ClassSchema, but the objectClass is different.

        :param samdb: SamDB connection
        :return: Dn object of container
        """
        return samdb.get_schema_basedn()

    @staticmethod
    def get_object_class():
        return "attributeSchema"

    @classmethod
    def find(cls, samdb, name):
        """Helper function to find attribute by name or raise NotFound.

        :param samdb: SamDB connection
        :param name: Attribute name
        :raises: NotFound if not found
        :raises: ValueError if name is not provided
        """
        if not name:
            raise ValueError("Attribute name is required.")

        attr = cls.get(samdb, ldap_display_name=name)
        if attr is None:
            raise NotFound(f"Could not locate {name} in attribute schema.")

        return attr
