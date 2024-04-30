# Unix SMB/CIFS implementation.
#
# Query class for the ORM to the Ldb database.
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

import re

from .exceptions import NotFound, MultipleObjectsReturned
from .registry import MODELS

RE_SPLIT_CAMELCASE = re.compile(r"[A-Z](?:[a-z]+|[A-Z]*(?=[A-Z]|$))")


class Query:
    """Simple Query class used by the `Model.query` method."""

    def __init__(self, model, samdb, result, polymorphic):
        self.model = model
        self.samdb = samdb
        self.result = result
        self.count = result.count
        self.name = " ".join(RE_SPLIT_CAMELCASE.findall(model.__name__)).lower()
        self.polymorphic = polymorphic

    def __iter__(self):
        """Loop over Query class yields Model instances."""
        for message in self.result:
            yield self._from_message(message)

    def __repr__(self):
        """Provide repr method that provides more useful output in the shell."""
        return f"<Query {list(self)}>"

    def _from_message(self, message):
        """Returns the model class to use to construct instances.

        If polymorphic query is enabled it will use the last item from
        the objectClass list.

        Otherwise, it will use the model from the queryset.
        """
        if self.polymorphic:
            object_class = str(message["objectClass"][-1])
            model = MODELS.get(object_class, self.model)
        else:
            model = self.model

        return model._from_message(self.samdb, message)

    def first(self):
        """Returns the first item in the Query or None for no results."""
        if self.count:
            return self._from_message(self.result[0])

    def last(self):
        """Returns the last item in the Query or None for no results."""
        if self.count:
            return self._from_message(self.result[-1])

    def get(self):
        """Returns one item or None if no results were found.

        :returns: Model instance or None if not found.
        :raises MultipleObjectsReturned: if more than one results were returned
        """
        if self.count > 1:
            raise MultipleObjectsReturned(
                f"More than one {self.name} objects returned (got {self.count}).")
        elif self.count:
            return self._from_message(self.result[0])

    def one(self):
        """Must return EXACTLY one item or raise an exception.

        :returns: Model instance
        :raises NotFound: if no results were returned
        :raises MultipleObjectsReturned: if more than one results were returned
        """
        if self.count < 1:
            raise NotFound(
                f"{self.name.capitalize()} matching query not found")
        elif self.count > 1:
            raise MultipleObjectsReturned(
                f"More than one {self.name} objects returned (got {self.count}).")
        else:
            return self._from_message(self.result[0])
