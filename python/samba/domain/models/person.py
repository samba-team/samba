# Unix SMB/CIFS implementation.
#
# Person and OrganisationalPerson models.
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


class Person(Model):
    sn = StringField("sn")

    @staticmethod
    def get_object_class():
        return "person"


class OrganizationalPerson(Person):
    country_code = IntegerField("countryCode")
    given_name = StringField("givenName")

    @staticmethod
    def get_object_class():
        return "organizationalPerson"
