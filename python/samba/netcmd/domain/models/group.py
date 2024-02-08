# Unix SMB/CIFS implementation.
#
# Group model.
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

from .fields import (BooleanField, DnField, EnumField, IntegerField, SIDField,
                     StringField)
from .model import Model
from .types import AccountType, GroupType, SystemFlags


class Group(Model):
    account_type = EnumField("sAMAccountType", AccountType)
    group_type = EnumField("groupType", GroupType)
    admin_count = IntegerField("adminCount")
    description = StringField("description")
    is_critical_system_object = BooleanField("isCriticalSystemObject",
                                             default=False, readonly=True)
    member = DnField("member", many=True)
    object_sid = SIDField("objectSid")
    system_flags = EnumField("systemFlags", SystemFlags)

    @staticmethod
    def get_object_class():
        return "group"

    def get_authentication_sddl(self):
        return "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID(%s)}))" % (
            self.object_sid)
