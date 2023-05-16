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
from abc import ABCMeta, abstractmethod

from ldb import ERR_NO_SUCH_OBJECT, FLAG_MOD_ADD, FLAG_MOD_REPLACE, LdbError,\
    Message, MessageElement, SCOPE_BASE, SCOPE_SUBTREE, binary_encode
from samba.sd_utils import SDUtils

from .exceptions import MultipleObjectsReturned
from .fields import DateTimeField, DnField, Field, GUIDField, IntegerField,\
    StringField

# Keeps track of registered models.
# This gets populated by the ModelMeta class.
MODELS = {}


class ModelMeta(ABCMeta):

    def __new__(mcls, name, bases, namespace, **kwargs):
        cls = super().__new__(mcls, name, bases, namespace, **kwargs)

        if cls.__name__ != "Model":
            cls.fields = dict(inspect.getmembers(cls, lambda f: isinstance(f, Field)))
            cls.meta = mcls
            MODELS[name] = cls

        return cls


class Model(metaclass=ModelMeta):
    cn = StringField("cn")
    distinguished_name = DnField("distinguishedName")
    dn = DnField("dn")
    ds_core_propagation_data = DateTimeField("dsCorePropagationData",
                                             hidden=True)
    instance_type = IntegerField("instanceType")
    name = StringField("name")
    object_category = DnField("objectCategory")
    object_class = StringField("objectClass",
                               default=lambda obj: obj.get_object_class())
    object_guid = GUIDField("objectGUID")
    usn_changed = IntegerField("uSNChanged", hidden=True)
    usn_created = IntegerField("uSNCreated", hidden=True)
    when_changed = DateTimeField("whenChanged", hidden=True)
    when_created = DateTimeField("whenCreated", hidden=True)

    def __init__(self, **kwargs):
        """Create a new model instance and optionally populate fields.

        Does not save the object to the database, call .save() for that.

        :param kwargs: Optional input fields to populate object with
        """
        for field_name, field in self.fields.items():
            if field_name in kwargs:
                default = kwargs[field_name]
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

    def __json__(self):
        """Automatically called by custom JSONEncoder class.

        When turning an object into json any fields of type RelatedField
        will also end up calling this method.
        """
        if self.dn is not None:
            return str(self.dn)

    @staticmethod
    @abstractmethod
    def get_base_dn(ldb):
        """Return the base DN for the container of this model.

        :param ldb: Ldb connection
        :return: Dn to use for new objects
        """
        pass

    @classmethod
    def get_search_dn(cls, ldb):
        """Return the DN used for querying.

        By default, this just calls get_base_dn, but it is possible to
        return a different Dn for querying.

        :param ldb: Ldb connection
        :return: Dn to use for searching
        """
        return cls.get_base_dn(ldb)

    @staticmethod
    @abstractmethod
    def get_object_class():
        """Returns the objectClass for this model."""
        pass

    @classmethod
    def from_message(cls, ldb, message):
        """Create a new model instance from the Ldb Message object.

        :param ldb: Ldb connection
        :param message: Ldb Message object to create instance from
        """
        obj = cls()
        obj._apply(ldb, message)
        return obj

    def _apply(self, ldb, message):
        """Internal method to apply Ldb Message to current object.

        :param ldb: Ldb connection
        :param message: Ldb Message object to apply
        """
        for attr, field in self.fields.items():
            if field.name in message:
                setattr(self, attr, field.from_db_value(ldb, message[field.name]))

    def refresh(self, ldb, fields=None):
        """Refresh object from database.

        :param ldb: Ldb connection
        :param fields: Optional list of field names to refresh
        """
        attrs = [self.fields[f].name for f in fields] if fields else None
        res = ldb.search(self.dn, scope=SCOPE_BASE, attrs=attrs)
        self._apply(ldb, res[0])

    def as_dict(self, include_hidden=False):
        """Returns a dict representation of the model.

        :param include_hidden: Include fields with hidden=True when set
        :returns: dict representation of model using Ldb field names as keys
        """
        obj_dict = {}

        for attr, field in self.fields.items():
            if not field.hidden or include_hidden:
                value = getattr(self, attr)
                if value is not None:
                    obj_dict[field.name] = value

        return obj_dict

    @classmethod
    def build_expression(cls, **kwargs):
        """Build LDAP search expression from kwargs.

        :kwargs: fields to use for expression using model field names
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
            if not field:
                raise ValueError(f"Unknown field '{field_name}'")
            expression += f"({field.name}={binary_encode(value)})"

        if num_fields > 1:
            expression += ")"

        return expression

    @classmethod
    def query(cls, ldb, **kwargs):
        """Returns a search query for this model.

        :param ldb: Ldb connection
        :param kwargs: Search criteria as keyword args
        """
        result = ldb.search(cls.get_search_dn(ldb),
                            scope=SCOPE_SUBTREE,
                            expression=cls.build_expression(**kwargs))

        # For now this returns a simple generator of model instances.
        # This could eventually become a QuerySet class if we need to add
        # additional methods on the return value for example .order_by()
        for message in result:
            yield cls.from_message(ldb, message)

    @classmethod
    def get(cls, ldb, **kwargs):
        """Get one object, must always return one item.

        Either find object by dn=, or any combination of attributes via kwargs.
        If there are more than one result, MultipleObjectsReturned is raised.

        :param ldb: Ldb connection
        :param kwargs: Search criteria as keyword args
        :returns: User object or None if not found
        :raises: MultipleObjects returned if there are more than one results
        """
        # If a DN is provided use that to get the object directly.
        # Otherwise, build a search expression using kwargs provided.
        dn = kwargs.get("dn")

        if dn:
            # Handle LDAP error 32 LDAP_NO_SUCH_OBJECT, but raise for the rest.
            # Return None if the User does not exist.
            try:
                res = ldb.search(dn, scope=SCOPE_BASE)
            except LdbError as e:
                if e.args[0] == ERR_NO_SUCH_OBJECT:
                    return None
                else:
                    raise
        else:
            res = ldb.search(cls.get_search_dn(ldb),
                             scope=SCOPE_SUBTREE,
                             expression=cls.build_expression(**kwargs))

        # Expect to get one object back or raise MultipleObjectsReturned.
        # For multiple records, please call .query() instead.
        count = len(res)
        if count > 1:
            raise MultipleObjectsReturned(
                f"More than one object returned (got {count}).")
        elif count == 1:
            return cls.from_message(ldb, res[0])

    @classmethod
    def create(cls, ldb, **kwargs):
        """Create object constructs object and calls save straight after.

        :param ldb: Ldb connection
        :param kwargs: Fields to populate object from
        :returns: object
        """
        obj = cls(**kwargs)
        obj.save(ldb)
        return obj

    @classmethod
    def get_or_create(cls, ldb, defaults=None, **kwargs):
        """Retrieve object and if it doesn't exist create a new instance.

        :param ldb: Ldb connection
        :param defaults: Attributes only used for create but not search
        :param kwargs: Attributes used for searching existing object
        :returns: (object, bool created)
        """
        obj = cls.get(ldb, **kwargs)
        if obj is None:
            attrs = dict(kwargs)
            if defaults is not None:
                attrs.update(defaults)
            return cls.create(ldb, **attrs), True
        else:
            return obj, False

    def save(self, ldb):
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

        :param ldb: Ldb connection
        """
        if self.dn is None:
            dn = self.get_base_dn(ldb)
            dn.add_child(f"CN={self.cn or self.name}")
            self.dn = dn

            message = Message(dn=self.dn)
            for attr, field in self.fields.items():
                if attr != "dn":
                    value = getattr(self, attr)
                    db_value = field.to_db_value(value, FLAG_MOD_ADD)

                    # Don't add empty fields.
                    if db_value is not None and len(db_value):
                        message.add(db_value)

            # Create object
            ldb.add(message)

            # Fetching object refreshes any automatically populated fields.
            res = ldb.search(dn, scope=SCOPE_BASE)
            self._apply(ldb, res[0])
        else:
            # Fetch existing object to work out what fields changed.
            existing_msg = ldb.search(self.dn, scope=SCOPE_BASE)
            existing_obj = self.from_message(ldb, existing_msg[0])

            # Only modify replace or modify fields that have changed.
            # Any fields that are set to None or an empty list get unset.
            message = Message(dn=self.dn)
            for attr, field in self.fields.items():
                if attr != "dn":
                    value = getattr(self, attr)
                    old_value = getattr(existing_obj, attr)

                    if value != old_value:
                        db_value = field.to_db_value(value, FLAG_MOD_REPLACE)

                        # When a field returns None or empty list, delete attr.
                        if db_value in (None, []):
                            db_value = MessageElement([],
                                                      FLAG_MOD_REPLACE,
                                                      field.name)
                        message.add(db_value)

            # Saving nothing only triggers an error.
            if len(message):
                ldb.modify(message)

                # Fetching object refreshes any automatically populated fields.
                self.refresh(ldb)

    def delete(self, ldb):
        """Delete item from Ldb database.

        If self.dn is None then the object has not yet been saved.

        :param ldb: Ldb connection
        """
        if self.dn is not None:
            ldb.delete(self.dn)

    def protect(self, ldb):
        """Protect object from accidental deletion.

        :param ldb: Ldb connection
        """
        utils = SDUtils(ldb)
        utils.dacl_add_ace(self.dn, "(D;;DTSD;;;WD)")

    def unprotect(self, ldb):
        """Unprotect object from accidental deletion.

        :param ldb: Ldb connection
        """
        utils = SDUtils(ldb)
        utils.dacl_delete_aces(self.dn, "(D;;DTSD;;;WD)")
