/*
   Unix SMB/CIFS implementation.
   Copyright (C) David Mulder <dmulder@suse.com> 2018

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

int unregister_gp_extension(const char *guid_name,
                            const char *smb_conf);
int register_gp_extension(const char *guid_name,
                          const char *gp_ext_cls,
                          const char *module_path,
                          const char *smb_conf,
                          int machine,
                          int user);
