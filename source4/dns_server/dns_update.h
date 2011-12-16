/*
   Unix SMB/CIFS implementation.

   DNS update settings

   Copyright (C) 2011 Kai Blin  <kai@samba.org>

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
enum dns_update_settings {
	DNS_UPDATE_OFF=0,
	DNS_UPDATE_ON=1,
	DNS_UPDATE_SIGNED=2
};
