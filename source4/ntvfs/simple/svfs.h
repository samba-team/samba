#ifndef __NTFVFS_SIMPLE_SVFS_H__
#define __NTFVFS_SIMPLE_SVFS_H__

/*
   Unix SMB/CIFS implementation.

   (C) 2011 Samba Team.

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

struct svfs_private {
	struct ntvfs_module_context *ntvfs;

	/* the base directory */
	char *connectpath;

	/* a linked list of open searches */
	struct search_state *search;

	/* next available search handle */
	uint16_t next_search_handle;

	struct svfs_file *open_files;
};

struct svfs_dir {
	unsigned int count;
	char *unix_dir;
	struct svfs_dirfile {
		char *name;
		struct stat st;
	} *files;
};

struct svfs_file {
	struct svfs_file *next, *prev;
	int fd;
	struct ntvfs_handle *handle;
	char *name;
};

struct search_state {
	struct search_state *next, *prev;
	uint16_t handle;
	unsigned int current_index;
	struct svfs_dir *dir;
};
#endif
