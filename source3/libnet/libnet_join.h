/*
 *  Unix SMB/CIFS implementation.
 *  libnet Join Support
 *  Copyright (C) Guenther Deschner 2007-2008
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LIBNET_JOIN_H__
#define __LIBNET_JOIN_H__

struct libnet_JoinCtx {
	struct {
		const char *dc_name;
		const char *machine_name;
		const char *domain_name;
		const char *account_ou;
		const char *admin_account;
		const char *admin_password;
		const char *machine_password;
		uint32_t join_flags;
		const char *os_version;
		const char *os_name;
		bool create_upn;
		const char *upn;
		bool modify_config;
		struct ads_struct *ads;
		bool debug;
	} in;

	struct {
		char *account_name;
		char *netbios_domain_name;
		char *dns_domain_name;
		char *dn;
		struct dom_sid *domain_sid;
		bool modified_config;
		WERROR result;
		char *error_string;
		bool domain_is_ad;
	} out;
};

struct libnet_UnjoinCtx {
	struct {
		const char *dc_name;
		const char *machine_name;
		const char *domain_name;
		const char *admin_account;
		const char *admin_password;
		uint32_t unjoin_flags;
		bool modify_config;
		struct dom_sid *domain_sid;
		struct ads_struct *ads;
	} in;

	struct {
		bool modified_config;
		WERROR result;
		char *error_string;
	} out;
};

#endif
