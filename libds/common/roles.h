/*
   Unix SMB/CIFS implementation.

   domain roles

   Copyright (C) Andrew Tridgell 2011

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

#ifndef _LIBDS_ROLES_H_
#define _LIBDS_ROLES_H_

/* server roles. If you add new roles, please keep ensure that the
 * existing role values match samr_Role from samr.idl
 */
enum server_role {
	ROLE_STANDALONE    = 0,
	ROLE_DOMAIN_MEMBER = 1,
	ROLE_DOMAIN_BDC    = 2,
	ROLE_DOMAIN_PDC    = 3,
	
	/* not in samr.idl */
	ROLE_ACTIVE_DIRECTORY_DC = 4,
	ROLE_IPA_DC = 5,

	/* To determine the role automatically, this is not a valid role */
	ROLE_AUTO          = 100
};

/* security levels for 'security =' option

                       --------------
                      /              \
                     /      REST      \
                    /        IN        \
                   /       PEACE        \
                  /                      \
                  |      SEC_SHARE       |
                  |    security=share    |
                  |                      |
                  |                      |
                  |       5 March        |
                  |                      |
                  |        2012          |
                 *|     *  *  *          | *
        _________)/\\_//(\/(/\)/\//\/\///|_)_______

                       --------------
                      /              \
                     /      REST      \
                    /        IN        \
                   /       PEACE        \
                  /                      \
                  |      SEC_SERVER      |
                  |    security=server   |
                  |                      |
                  |                      |
                  |       12 May         |
                  |                      |
                  |        2012          |
                 *|     *  *  *          | *
        _________)/\\_//(\/(/\)/\//\/\///|_)_______

*/
enum security_types {SEC_AUTO = 0, 
		     SEC_USER = 2, 
		     SEC_DOMAIN = 4,
		     SEC_ADS = 5};

#endif /* _LIBDS_ROLES_H_ */
