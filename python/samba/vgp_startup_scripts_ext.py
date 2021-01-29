# vgp_startup_scripts_ext samba gpo policy
# Copyright (C) David Mulder <dmulder@suse.com> 2021
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

import os
from samba.gpclass import gp_xml_ext

class vgp_startup_scripts_ext(gp_xml_ext):
    def process_group_policy(self, deleted_gpo_list, changed_gpo_list,
                             cdir='/etc/cron.d'):
        pass

    def rsop(self, gpo):
        output = {}
        return output
