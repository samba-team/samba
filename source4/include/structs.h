/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Andrew Tridgell 2004
   
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

/*
  this file contains pre-declarations of private structures to avoid the
  "scope is only this definition or declaration" warning
*/

union spoolss_PrinterInfo;
union spoolss_FormInfo;
union spoolss_JobInfo;
union spoolss_DriverInfo;
union spoolss_PortInfo;

struct MULTI_QI;
struct COSERVERINFO;


struct epm_floor;
struct epm_tower;

struct drsuapi_DsCrackNames;

struct samr_ChangePasswordUser;
struct samr_OemChangePasswordUser2;
struct samr_ChangePasswordUser3;
struct samr_ChangePasswordUser2;
struct samr_CryptPassword;
struct samr_CryptPasswordEx;

struct netr_SamInfo3;
struct netr_Authenticator;

