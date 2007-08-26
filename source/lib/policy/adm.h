/* 
   Unix SMB/CIFS implementation.
   Copyright (C) 2006 Wilco Baan Hofman <wilco@baanhofman.nl>
   Copyright (C) 2006 Jelmer Vernooij <jelmer@samba.org>
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifndef __ADM_H__
#define __ADM_H__

struct adm_file {
	struct adm_class *classes;
};

struct adm_class {
	struct adm_category *categories;
};

struct adm_category {
	struct adm_category *subcategories;
	struct adm_policy *policies;
};

struct adm_policy {
	struct adm_part *parts;
};

struct adm_part {
	int dummy;	
};

struct adm_file *adm_read_file(const char *);

#endif /* __ADM_H__ */
