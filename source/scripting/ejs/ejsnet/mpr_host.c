/* 
   Unix SMB/CIFS implementation.

   provides interfaces to libnet calls from ejs scripts

   Copyright (C) Rafal Szczesniak  2005-2007
   
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


#include "includes.h"
#include "lib/appweb/ejs/ejs.h"
#include "libnet/libnet.h"
#include "scripting/ejs/smbcalls.h"
#include "events/events.h"
#include "auth/credentials/credentials.h"


/*
  Properties:
  DomainsList.Domains[0]
  DomainsList.Status
*/
struct MprVar mprDomainsList(TALLOC_CTX *mem_ctx, struct libnet_DomainList *list, NTSTATUS result)
{
	const char *name = "DomainsList";
	NTSTATUS status;
	struct MprVar mprDomainList, mprDomains;
	struct MprVar mprSid, mprDomainName;
	struct MprVar mprDomain;
	int i;

	if (list == NULL || mem_ctx == NULL) {
		mprDomainList = mprCreateNullVar();
		goto done;
	}

	mprDomains = mprArray("Domains");
	for (i = 0; i < list->out.count; i++) {
		struct domainlist d = list->out.domains[i];

		/* get domainlist fields */
		mprSid        = mprString(d.sid);
		mprDomainName = mprString(d.name);

		mprDomain = mprObject("Domain");
		mprSetVar(&mprDomain, "Name", mprDomainName);
		mprSetVar(&mprDomain, "SID", mprSid);

		mprAddArray(&mprDomains, i, mprDomain);
	}

	mprDomainList = mprObject(name);
	status = mprSetVar(&mprDomainList, "Domains", mprDomains);
	if (!NT_STATUS_IS_OK(status)) goto done;
	status = mprSetVar(&mprDomainList, "Count", mprCreateIntegerVar(list->out.count));
	if (!NT_STATUS_IS_OK(status)) goto done;
	status = mprSetVar(&mprDomainList, "Status", mprNTSTATUS(result));

done:
	return mprDomainList;
}
