# Unix SMB/CIFS implementation.
#
# encoders: JSONEncoder class for dealing with object fields.
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

import json
from datetime import datetime
from decimal import Decimal
from enum import Enum

from ldb import Dn


class JSONEncoder(json.JSONEncoder):
    """Custom JSON encoder class to help out with some data types.

    For example, the json module has no idea how to encode a Dn object to str.
    Another common object that is handled is Decimal types.

    In addition, any objects that have a __json__ method will get called.
    """

    def default(self, obj):
        if isinstance(obj, (Decimal, Dn)):
            return str(obj)
        elif isinstance(obj, Enum):
            return str(obj.value)
        elif isinstance(obj, datetime):
            return obj.isoformat()
        elif getattr(obj, "__json__", None) and callable(obj.__json__):
            return obj.__json__()
        return obj
