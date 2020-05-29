# Unix SMB/CIFS implementation.
# auth util helpers
#
# Copyright (C) Ralph Boehme <slow@samba.org> 2019
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

from samba.auth import (
    system_session,
    session_info_fill_unix,
    copy_session_info,
)

def system_session_unix():
    """
    Return a copy of the system session_info with a valid UNIX token
    """

    session_info = system_session()
    session_info_unix = copy_session_info(session_info)
    session_info_fill_unix(session_info_unix, None)

    return session_info_unix
