# Unix SMB/CIFS implementation.
#
# Model and basic ORM for the Ldb database.
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

import inspect

from ldb import (ERR_NO_SUCH_OBJECT, FLAG_MOD_ADD, FLAG_MOD_REPLACE,
                 LdbError, Message, MessageElement, SCOPE_BASE,
                 SCOPE_ONELEVEL, SCOPE_SUBTREE)
from samba.sd_utils import SDUtils

from .exceptions import (DeleteError, FieldError, NotFound, ProtectError,
                         UnprotectError)
from .fields import (DateTimeField, DnField, Field, GUIDField, IntegerField,
                     SIDField, StringField)
from .query import Query
from .registry import MODELS


class ModelMeta(type):

    def __new__(mcls, name, bases, namespace, **kwargs):
        cls = super().__new__(mcls, name, bases, namespace, **kwargs)
        cls.fields = dict(inspect.getmembers(cls, lambda f: isinstance(f, Field)))
        cls.meta = mcls
        object_class = cls.get_object_class()
        MODELS[object_class] = cls
        return cls


class Model(metaclass=ModelMeta):
    cn = StringField("cn")
    distinguished_name = DnField("distinguishedName")
    dn = DnField("dn")
    ds_core_propagation_data = DateTimeField("dsCorePropagationData",
                                             hidden=True, readonly=True)
    instance_type = IntegerField("instanceType")
    name = StringField("name")
    object_category = DnField("objectCategory")
    object_class = StringField("objectClass",
                               default=lambda obj: obj.get_object_class())
    object_guid = GUIDField("objectGUID")
    object_sid = SIDField("objectSid")
    usn_changed = IntegerField("uSNChanged", hidden=True, readonly=True)
    usn_created = IntegerField("uSNCreated", hidden=True, readonly=True)
    when_changed = DateTimeField("whenChanged", hidden=True, readonly=True)
    when_created = DateTimeField("whenCreated", hidden=True, readonly=True)

    def __init__(self, **kwargs):
        """Create a new model instance and optionally populate fields.

        Does not save the object to the database, call .save() for that.

        :param kwargs: Optional input fields to populate object with
        """
        # Used by the _apply method, holds the original ldb Message,
        # which is used by save() to determine what fields changed.
        self._message = None

        for field_name, field in self.fields.items():
            field_value = kwargs.get(field_name)

            # Set fields from values provided in kwargs dict.
            # If field is set to None we use the field default (if any)
            if field_value is not None:
                default = field_value
            elif callable(field.default):
                default = field.default(self)
            else:
                default = field.default

            setattr(self, field_name, default)

    def __repr__(self):
        """Return object representation for this model."""
        return f"<{self.__class__.__name__}: {self}>"

    def __str__(self):
        """Stringify model instance to implement in each model."""
        return str(self.cn)

    def __eq__(self, other):
        """Basic object equality check only really checks if the dn matches.

        :param other: The other object to compare with
        """
        if other is None:
            return False
        else:
            return self.dn == other.dn

    def __json__(self, **kwargs):
        """Automatically called by custom JSONEncoder class."""
        return self.as_dict(**kwargs)

    @staticmethod
    def get_base_dn(samdb):
        """Return the base DN for the container of this model.

        :param samdb: SamDB connection
        :return: Dn to use for new objects
        """
        return samdb.get_default_basedn()

    @classmethod
    def get_search_dn(cls, samdb):
        """Return the DN used for querying.

        By default, this just calls get_base_dn, but it is possible to
        return a different Dn for querying.

        :param samdb: SamDB connection
        :return: Dn to use for searching
        """
        return cls.get_base_dn(samdb)

    @staticmethod
    def get_object_class():
        """Returns the objectClass for this model."""
        return "top"

    @classmethod
    def _from_message(cls, samdb, message):
        """Create a new model instance from the Ldb Message object.

        :param samdb: SamDB connection
        :param message: Ldb Message object to create instance from
        """
        obj = cls()
        obj._apply(samdb, message)
        return obj

    def _apply(self, samdb, message):
        """Internal method to apply Ldb Message to current object.

        :param samdb: SamDB connection
        :param message: Ldb Message object to apply
        """
        # Store the ldb Message so that in save we can see what changed.
        self._message = message

        for attr, field in self.fields.items():
            if field.name in message:
                setattr(self, attr, field.from_db_value(samdb, message[field.name]))

    def refresh(self, samdb, fields=None):
        """Refresh object from database.

        :param samdb: SamDB connection
        :param fields: Optional list of field names to refresh
        """
        attrs = [self.fields[f].name for f in fields] if fields else None

        # This shouldn't normally happen but in case the object refresh fails.
        try:
            res = samdb.search(self.dn, scope=SCOPE_BASE, attrs=attrs)
        except LdbError as e:
            if e.args[0] == ERR_NO_SUCH_OBJECT:
                raise NotFound(f"Refresh failed, object gone: {self.dn}")
            raise

        self._apply(samdb, res[0])

    def as_dict(self, include_hidden=False, **kwargs):
        """Returns a dict representation of the model.

        :param include_hidden: Include fields with hidden=True when set
        :returns: dict representation of model using Ldb field names as keys
        """
        obj_dict = {}

        for attr, field in self.fields.items():
            if not field.hidden or include_hidden:
                value = getattr(self, attr)
                if value not in (None, []):
                    obj_dict[field.name] = value

        return obj_dict

    @classmethod
    def build_expression(cls, **kwargs):
        """Build LDAP search expression from kwargs.

        :param kwargs: fields to use for expression using model field names
        """
        # Take a copy, never modify the original if it can be avoided.
        # Then always add the object_class to the search criteria.
        criteria = dict(kwargs)
        criteria["object_class"] = cls.get_object_class()

        # Build search expression.
        num_fields = len(criteria)
        expression = "" if num_fields == 1 else "(&"

        for field_name, value in criteria.items():
            field = cls.fields.get(field_name)
            if field is None:
                raise ValueError(f"Unknown field '{field_name}'")
            expression += field.expression(value)

        if num_fields > 1:
            expression += ")"

        return expression

    @classmethod
    def query(cls, samdb, polymorphic=False, base_dn=None, scope=SCOPE_SUBTREE,
              **kwargs):
        """Returns a search query for this model.

        NOTE: If polymorphic is enabled then querying will return instances
        of that specific model, for example querying User can return Computer
        and ManagedServiceAccount instances.

        By default, polymorphic querying is disabled, and querying User
        will only return User instances.

        :param samdb: SamDB connection
        :param polymorphic: If true enables polymorphic querying (see note)
        :param base_dn: Optional provide base dn for searching or use the model
        :param scope: Ldb search scope (default SCOPE_SUBTREE)
        :param kwargs: Search criteria as keyword args
        """
        if base_dn is None:
            base_dn = cls.get_search_dn(samdb)

        # If the container does not exist produce a friendly error message.
        try:
            result = samdb.search(base_dn,
                                  scope=scope,
                                  expression=cls.build_expression(**kwargs))
        except LdbError as e:
            if e.args[0] == ERR_NO_SUCH_OBJECT:
                raise NotFound(f"Container does not exist: {base_dn}")
            raise

        return Query(cls, samdb, result, polymorphic)

    @classmethod
    def get(cls, samdb, **kwargs):
        """Get one object, must always return one item.

        Either find object by dn=, or any combination of attributes via kwargs.
        If there are more than one result, MultipleObjectsReturned is raised.

        :param samdb: SamDB connection
        :param kwargs: Search criteria as keyword args
        :returns: Model instance or None if not found
        :raises: MultipleObjects returned if there are more than one results
        """
        # If a DN is provided use that to get the object directly.
        # Otherwise, build a search expression using kwargs provided.
        dn = kwargs.get("dn")

        if dn:
            # Handle LDAP error 32 LDAP_NO_SUCH_OBJECT, but raise for the rest.
            # Return None if the User does not exist.
            try:
                res = samdb.search(dn, scope=SCOPE_BASE)
            except LdbError as e:
                if e.args[0] == ERR_NO_SUCH_OBJECT:
                    return None
                else:
                    raise

            return cls._from_message(samdb, res[0])
        else:
            return cls.query(samdb, **kwargs).get()

    @classmethod
    def create(cls, samdb, **kwargs):
        """Create object constructs object and calls save straight after.

        :param samdb: SamDB connection
        :param kwargs: Fields to populate object from
        :returns: object
        """
        obj = cls(**kwargs)
        obj.save(samdb)
        return obj

    @classmethod
    def get_or_create(cls, samdb, defaults=None, **kwargs):
        """Retrieve object and if it doesn't exist create a new instance.

        :param samdb: SamDB connection
        :param defaults: Attributes only used for create but not search
        :param kwargs: Attributes used for searching existing object
        :returns: (object, bool created)
        """
        obj = cls.get(samdb, **kwargs)
        if obj is None:
            attrs = dict(kwargs)
            if defaults is not None:
                attrs.update(defaults)
            return cls.create(samdb, **attrs), True
        else:
            return obj, False

    def children(self, samdb):
        """Returns a Query of the current models children."""
        return Model.query(
            samdb, base_dn=self.dn, scope=SCOPE_ONELEVEL, polymorphic=True)

    def save(self, samdb):
        """Save model to Ldb database.

        The save operation will save all fields excluding fields that
        return None when calling their `to_db_value` methods.

        The `to_db_value` method can either return a ldb Message object,
        or None if the field is to be excluded.

        For updates, the existing object is fetched and only fields
        that are changed are included in the update ldb Message.

        Also for updates, any fields that currently have a value,
        but are to be set to None will be seen as a delete operation.

        After the save operation the object is refreshed from the server,
        as often the server will populate some fields.

        :param samdb: SamDB connection
        """
        if self.dn is None:
            dn = self.get_base_dn(samdb)
            dn.add_child(f"CN={self.cn or self.name}")
            self.dn = dn

            message = Message(dn=self.dn)
            for attr, field in self.fields.items():
                if attr != "dn" and not field.readonly:
                    value = getattr(self, attr)
                    try:
                        db_value = field.to_db_value(samdb, value, FLAG_MOD_ADD)
                    except ValueError as e:
                        raise FieldError(e, field=field)

                    # Don't add empty fields.
                    if db_value is not None and len(db_value):
                        message.add(db_value)

            # Create object
            samdb.add(message)

            # Fetching object refreshes any automatically populated fields.
            res = samdb.search(dn, scope=SCOPE_BASE)
            self._apply(samdb, res[0])
        else:
            # Existing Message was stored to work out what fields changed.
            existing_obj = self._from_message(samdb, self._message)

            # Only modify replace or modify fields that have changed.
            # Any fields that are set to None or an empty list get unset.
            message = Message(dn=self.dn)
            for attr, field in self.fields.items():
                if attr != "dn" and not field.readonly:
                    value = getattr(self, attr)
                    old_value = getattr(existing_obj, attr)

                    if value != old_value:
                        try:
                            db_value = field.to_db_value(samdb, value,
                                                         FLAG_MOD_REPLACE)
                        except ValueError as e:
                            raise FieldError(e, field=field)

                        # When a field returns None or empty list, delete attr.
                        if db_value in (None, []):
                            db_value = MessageElement([],
                                                      FLAG_MOD_REPLACE,
                                                      field.name)
                        message.add(db_value)

            # Saving nothing only triggers an error.
            if len(message):
                samdb.modify(message)

                # Fetching object refreshes any automatically populated fields.
                self.refresh(samdb)

    def delete(self, samdb):
        """Delete item from Ldb database.

        If self.dn is None then the object has not yet been saved.

        :param samdb: SamDB connection
        """
        if self.dn is None:
            raise DeleteError("Cannot delete object that doesn't have a dn.")

        try:
            samdb.delete(self.dn)
        except LdbError as e:
            raise DeleteError(f"Delete failed: {e}")

    def protect(self, samdb):
        """Protect object from accidental deletion.

        :param samdb: SamDB connection
        """
        utils = SDUtils(samdb)

        try:
            utils.dacl_add_ace(self.dn, "(D;;DTSD;;;WD)")
        except LdbError as e:
            raise ProtectError(f"Failed to protect object: {e}")

    def unprotect(self, samdb):
        """Unprotect object from accidental deletion.

        :param samdb: SamDB connection
        """
        utils = SDUtils(samdb)

        try:
            utils.dacl_delete_aces(self.dn, "(D;;DTSD;;;WD)")
        except LdbError as e:
            raise UnprotectError(f"Failed to unprotect object: {e}")
