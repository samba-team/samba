/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
   
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

#ifndef __SAMBA_PYTHON_MODULES_H__
#define __SAMBA_PYTHON_MODULES_H__

bool py_update_path(void);
/* discard signature of 'func' in favour of 'target_sig' */
#define PY_DISCARD_FUNC_SIG(target_sig, func) (target_sig)(void(*)(void))func
#endif /* __SAMBA_PYTHON_MODULES_H__ */ 
