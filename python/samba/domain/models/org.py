# Unix SMB/CIFS implementation.
#
# Organizational models.
#
# Copyright (C) Catalyst.Net Ltd. 2024
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

from .fields import IntegerField, StringField
from .model import Model
from .person import Person


class OrganizationalPerson(Person):
    country_code = IntegerField("countryCode")
    given_name = StringField("givenName")

    @staticmethod
    def get_object_class():
        return "organizationalPerson"


class OrganizationalUnit(Model):
    ou = StringField("ou")

    def __str__(self):
        return str(self.ou)

    @staticmethod
    def get_object_class():
        return "organizationalUnit"
