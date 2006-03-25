/* 
   Unix SMB/CIFS implementation.
   SMB torture UI functions

   Copyright (C) Jelmer Vernooij 2006
   
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

struct torture_test;

enum torture_result { 
	TORTURE_OK=0, 
	TORTURE_FAIL=1, 
	TORTURE_TODO=2, 
	TORTURE_SKIP=3
};

struct torture_ui_ops
{
	void (*comment) (struct torture_test *, const char *);
	void (*test_start) (struct torture_test *);
	void (*test_result) (struct torture_test *, enum torture_result);
};

struct torture_test
{
	char *name;
	char *description;

	void *ui_data;

	struct torture_context *context;
};

struct torture_context
{
	const struct torture_ui_ops *ui_ops;
	void *ui_data;
};
