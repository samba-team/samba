/*
   Unix SMB/CIFS implementation.

   Winbind client API

   Copyright (C) Gerald (Jerry) Carter 2007

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _WBC_ERR_H
#define _WBC_ERR_H


/* Define error types */

/**
 *  @brief Status codes returned from wbc functions
 **/

enum _wbcErrType {
	WBC_ERR_SUCCESS = 0,    /**< Successful completion **/
	WBC_ERR_NOT_IMPLEMENTED,/**< Function not implemented **/
	WBC_ERR_UNKNOWN_FAILURE,/**< General failure **/
	WBC_ERR_NO_MEMORY,      /**< Memory allocation error **/
	WBC_ERR_INVALID_SID,    /**< Invalid SID format **/
	WBC_ERR_INVALID_PARAM,  /**< An Invalid parameter was supplied **/
	WBC_ERR_WINBIND_NOT_AVAILABLE,   /**< Winbind daemon is not available **/
	WBC_ERR_DOMAIN_NOT_FOUND,        /**< Domain is not trusted or cannot be found **/
	WBC_INVALID_RESPONSE,        /**< Winbind returned an invalid response **/
	WBC_ERR_NSS_ERROR            /**< NSS_STATUS error **/
};

typedef enum _wbcErrType wbcErr;

#define WBC_ERROR_IS_OK(x) ((x) == WBC_ERR_SUCCESS)

char *wbcErrorString(wbcErr error);

#endif	/* _WBC_ERR_H */
