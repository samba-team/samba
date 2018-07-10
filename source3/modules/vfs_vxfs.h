/*
Unix SMB/CIFS implementation.
Wrap VxFS xattr calls in vfs functions.

Copyright (C) Veritas Technologies LLC <www.veritas.com> 2016

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

int vxfs_setxattr_path(const char *, const char *, const void *, size_t, int,
		       bool);
int vxfs_setxattr_fd(int, const char *, const void *, size_t, int);

int vxfs_getxattr_path(const char *, const char *, void *, size_t);
int vxfs_getxattr_fd(int, const char *, void *, size_t);

int vxfs_removexattr_path(const char *, const char *, bool);
int vxfs_removexattr_fd(int, const char *);

int vxfs_listxattr_path(const char *, char *, size_t);
int vxfs_listxattr_fd(int, char *, size_t);

int vxfs_setwxattr_path(const char *, bool);
int vxfs_setwxattr_fd(int);

int vxfs_clearwxattr_path(const char *, bool);
int vxfs_clearwxattr_fd(int);

int vxfs_checkwxattr_path(const char *);
int vxfs_checkwxattr_fd(int);

void vxfs_init(void);
