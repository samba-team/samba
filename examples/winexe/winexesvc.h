/*
 * Copyright (C) Andrzej Hajda 2009-2013
 * Contact: andrzej.hajda@wp.pl
 *
 * Source of this file: https://git.code.sf.net/p/winexe/winexe-waf
 * commit b787d2a2c4b1abc3653bad10aec943b8efcd7aab.
 *
 * ** NOTE! The following "GPLv3 only" license applies to the winexe
 * ** service files.  This does NOT imply that all of Samba is released
 * ** under the "GPLv3 only" license.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 3 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Shared by winexe and winexesvc
 */

#define VERSION_MAJOR 1
#define VERSION_MINOR 1

#define VERSION ((VERSION_MAJOR * 100) + VERSION_MINOR)

#define SERVICE_NAME "winexesvc"

#define PIPE_NAME "ahexec"
#define PIPE_NAME_IN "ahexec_stdin%08X"
#define PIPE_NAME_OUT "ahexec_stdout%08X"
#define PIPE_NAME_ERR "ahexec_stderr%08X"

#define CMD_STD_IO_ERR "std_io_err"
#define CMD_RETURN_CODE "return_code"
