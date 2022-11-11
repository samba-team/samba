/*
 *  Unix SMB/CIFS implementation.
 *
 *  Window Search Service
 *
 *  Copyright (c)  Noel Power
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

#ifndef WSP_ABS_IF_H
#define WSP_ABS_IF_H

#include "bin/default/librpc/gen_ndr/ndr_wsp.h"


struct tevent_context;
struct tevent_req;
struct wspd_client_state;
struct wsp_abstract_state;
struct wsp_crestrictionarray;
struct messaging_context;

typedef struct wsp_abstract_state *(*init_fn)(
			struct tevent_context *event_ctx);

typedef struct wsp_ctablecolumn *(*getbindings_fn)(
			struct wspd_client_state *client_state,
			uint32_t queryidentifier,
			uint32_t cursorhandle,
			uint32_t *ncols);

typedef bool (*iscatalogavailable_fn)(struct wspd_client_state *client_state,
				      const char *catalogname);

typedef void (*getserverversions_fn)(struct wspd_client_state* client_state,
				     uint32_t *dwwinvermajor,
				     uint32_t *dwwinverminor,
				     uint32_t *dwnlsvermajor,
				     uint32_t *dwnlsverminor,
				     uint32_t *serverversion,
				     bool *supportsversioninginfo);

typedef struct tevent_req *(*getstate_send_fn)(
			TALLOC_CTX *ctx,
			struct tevent_context *ev,
			struct wspd_client_state *client_state);
typedef HRESULT (*getstate_recv_fn)(struct tevent_req *req,
			struct wsp_cpmcistateinout *out);

typedef void (*storeclientinformation_fn)(
		struct wspd_client_state *wspd_client_state,
		uint32_t queryidentifier,
		struct wsp_cpmconnectin *connectmessage,
		uint32_t namedpipehandle);

typedef struct wsp_cpmconnectin *(*getclientinformation_fn)(
		struct wspd_client_state *wsp_client,
		uint32_t queryidentifier);

typedef struct tevent_req *(*runnewquery_send_fn)(
				TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *client_state,
				uint32_t queryidentifier,
				struct wsp_ccolumnset *projectioncolumnsoffsets,
				struct wsp_crestrictionarray *restrictionSet,
				struct wsp_csortset *sortorders,
				struct wsp_ccategorizationset *groupings,
				struct wsp_crowsetproperties *rowsetproperties,
				struct wsp_cpidmapper *pidmapper,
				struct wsp_ccolumngrouparray *grouparray,
				uint32_t lcid);
typedef HRESULT (*runnewquery_recv_fn)(
				struct tevent_req *req,
				TALLOC_CTX *ctx,
				uint32_t **cursorhandleslist,
				bool *ftruesequential,
				bool *fworkidunique,
				bool *canquerynew);

typedef bool (*clientqueryhascursorhandle_fn)(
			struct wspd_client_state *wspd_client_state,
			uint32_t queryidentifier,
			uint32_t cursorhandle);

typedef struct tevent_req *(*getquerystatus_send_fn)(
				TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *wspd_client_state,
				uint32_t queryidentifier);
typedef HRESULT (*getquerystatus_recv_fn)(
				struct tevent_req *req,
				uint32_t *querystatus);

typedef struct tevent_req *(*getratiofinishedparams_send_fn)
				(TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *wspd_client_state,
				uint32_t queryidentifier,
				uint32_t cursorhandle);
typedef HRESULT (*getratiofinishedparams_recv_fn)(
				struct tevent_req *req,
				uint32_t *rdwratiofinisheddenominator,
				uint32_t *rdwRatiofinishednumerator,
				uint32_t *crows,
				uint32_t *fnewrows);

typedef struct tevent_req *(*getapproximatepos_send_fn)(
				TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *wspd_client_state,
				uint32_t queryidentifier,
				uint32_t cursorhandle,
				uint32_t bmk);
typedef HRESULT (*getapproximatepos_recv_fn)(struct tevent_req *req,
					uint32_t *position);

typedef uint32_t (*getwhereid_fn)(struct wspd_client_state *wspd_client_state,
				  uint32_t queryidentifier);

typedef struct tevent_req *(*getexpensiveproperties_send_fn)(
				TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *wspd_client_state,
				uint32_t queryidentifier,
				uint32_t cursorhandle);
typedef HRESULT (*getexpensiveproperties_recv_fn)(
				struct tevent_req *req,
				uint32_t *rcrowstotal,
				uint32_t *rdwresultcount,
				uint32_t *maxrank);

typedef bool (*hasbindings_fn)(struct wspd_client_state *wspd_client_state,
			       uint32_t queryidentifier,
			       uint32_t cursorhandle);

typedef uint32_t (*getbookmarkposition_fn)(
			struct wspd_client_state *wspd_client_state,
			uint32_t queryidentifier,
			uint32_t cursorhandle,
			uint32_t bmkhandle);

typedef void (*setnextgetrowsposition_fn)(
			struct wspd_client_state *wspd_client_state,
			uint32_t queryidentifier,
			uint32_t cursorhandle,
			uint32_t chapter,
			uint32_t index);

typedef uint32_t (*getnextgetrowsposition_fn)(
			struct wspd_client_state *wspd_client_state,
			uint32_t queryidentifier,
			uint32_t cursorhandle,
			uint32_t chapter);

typedef struct tevent_req *(*getrows_send_fn)(TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *wspd_client_state,
				 uint32_t queryidentifier,
				 uint32_t cursorhandle,
				 uint32_t numrowsrequested,
				 uint32_t fetchforward);
typedef HRESULT (*getrows_recv_fn)(struct tevent_req *req,
				TALLOC_CTX *ctx,
				struct wsp_cbasestoragevariant ***rowsarray,
				bool *nomorerowsToreturn,
				uint32_t *numrowsreturned);

typedef struct tevent_req *(*hasaccesstoworkid_send_fn)(
				TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *wspd_client_state,
				uint32_t queryidentifier,
				uint32_t workid);
typedef HRESULT (*hasaccesstoworkid_recv_fn)(struct tevent_req *req,
				bool* has_access);

typedef struct tevent_req *(*hasaccesstoproperty_send_fn)(
				TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *wspd_client_state,
				uint32_t QueryIdentifier,
				struct wsp_cfullpropspec *PropSpec);
typedef HRESULT (*hasaccesstoproperty_recv_fn)(struct tevent_req *req,
				bool *has_access);

typedef struct tevent_req *(*getpropvalueforworkid_fn_send)(
				TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *wspd_client_state,
				uint32_t queryidentifier,
				uint32_t workid,
				struct wsp_cfullpropspec *propspec);
typedef HRESULT (*getpropvalueforworkid_fn_recv)(struct tevent_req *req,
				TALLOC_CTX *ctx,
				DATA_BLOB *property,
				uint32_t *valueexists);

typedef void (*setbindings_fn)(struct wspd_client_state *wspd_client_state,
			       uint32_t queryidentifier,
			       uint32_t cursorhandle,
			       struct wsp_ctablecolumn *columns,
			       uint32_t nColumns);

typedef struct tevent_req *(*getquerystatuschanges_send_fn)(
				TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *wspd_client_state,
				uint32_t queryidentifier,
				uint32_t cursorhandle);
typedef HRESULT (*getquerystatuschanges_recv_fn)(struct tevent_req *req,
				uint32_t *latestchange,
				bool *changespresent);

typedef uint32_t (*releasecursor_fn)(
				struct wspd_client_state *wspd_client_state,
				uint32_t queryidentifier,
				uint32_t cursorhandle);

typedef struct tevent_req *(*releasecursor_send_fn)(
				TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *wspd_client_state,
				uint32_t queryidentifier,
				uint32_t cursorhandle);
typedef HRESULT (*releasecursor_recv_fn)(struct tevent_req *req,
				uint32_t *cursorsremaining);

typedef struct tevent_req *(*releasequery_send_fn)(
			TALLOC_CTX* ctx,
			struct tevent_context *ev,
			struct wspd_client_state *wspd_client_state,
			uint32_t queryidentifier);
typedef HRESULT (*releasequery_recv_fn)(
			struct tevent_req *req);

typedef struct tevent_req *(*findnextoccurrenceindex_send_fn)(
				TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *wspd_client_state,
				uint32_t queryidentifier,
				uint32_t *prevocccoordinateslist,
				uint32_t numprevitems);
typedef HRESULT (*findnextoccurrenceindex_recv_fn)(struct tevent_req *req,
				uint32_t *nextocccoordinateslist,
				uint32_t *numnextitems);

typedef struct tevent_req *(*getlastunretrievedevt_send_fn)(
				TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *wspd_client_state,
				uint32_t queryidentifier);
typedef HRESULT (*getlastunretrievedevt_recv_fn)(struct tevent_req *req,
						/* out */
						uint32_t *wid,
						uint8_t *eventtype,
						bool *moreevents,
						uint8_t *rowsetitemstate,
						uint8_t *changeditemstate,
						uint8_t *rowsetevent,
						uint64_t *rowseteventdata1,
						uint64_t *rowseteventdata2);

typedef struct tevent_req *(*getquerystats_send_fn)(
				TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *wspd_client_state,
				uint32_t queryidentifier);
typedef HRESULT (*getquerystats_recv_fn)(struct tevent_req *req,
					  uint32_t *numindexeditems,
					  uint32_t *numoutstandingadds,
					  uint32_t *numOutstandingmodifies);

typedef struct tevent_req *(*setscopepriority_send_fn)(
				TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *wspd_client_state,
				uint32_t queryidentifier,
				uint32_t priority);
typedef HRESULT (*setscopepriority_recv_fn)(struct tevent_req *req);

typedef struct tevent_req *(*filteroutscopestatisticsmessages_send_fn)(
				TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *wspd_client_state,
				uint32_t queryidentifier);
typedef HRESULT (*filteroutscopestatisticsmessages_recv_fn)(
						struct tevent_req*);

typedef struct tevent_req *(*inflect_send_fn)(
			TALLOC_CTX *ctx,
			struct tevent_context *ev,
			struct wspd_client_state *wspd_client_state,
			const char* phrase);
typedef HRESULT (*inflect_recv_fn)(struct tevent_req *req,
			   const char **inflections,
			   uint32_t *inflectionscount);

typedef struct tevent_req *(*generatescopestatisticsevent_send_fn)(
				TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *wspd_client_state,
				uint32_t queryidentifier);
typedef HRESULT (*generatescopestatisticsevent_recv_fn)(
				struct tevent_req *req);

struct wsp_abstract_interface {
	init_fn initialise;
	iscatalogavailable_fn iscatalogavailable;
	getserverversions_fn getserverversions;
	getstate_send_fn getstate_send;
	getstate_recv_fn getstate_recv;
	storeclientinformation_fn storeclientinformation;
	getclientinformation_fn getclientinformation;
	runnewquery_send_fn runnewquery_send;
	runnewquery_recv_fn runnewquery_recv;
	clientqueryhascursorhandle_fn clientqueryhascursorhandle;
	getquerystatus_send_fn getquerystatus_send;
	getquerystatus_recv_fn getquerystatus_recv;
	getratiofinishedparams_send_fn getratiofinishedparams_send;
	getratiofinishedparams_recv_fn getratiofinishedparams_recv;
	getapproximatepos_send_fn getapproximatepos_send;
	getapproximatepos_recv_fn getapproximatepos_recv;
	getwhereid_fn getwhereid;
	getexpensiveproperties_send_fn getexpensiveproperties_send;
	getexpensiveproperties_recv_fn getexpensiveproperties_recv;
	hasbindings_fn hasbindings;
	getbookmarkposition_fn getbookmarkposition;
	setnextgetrowsposition_fn setnextgetrowsposition;
	getnextgetrowsposition_fn getnextgetrowsposition;
	getrows_send_fn getrows_send;
	getrows_recv_fn getrows_recv;
	hasaccesstoworkid_send_fn hasaccesstoworkid_send;
	hasaccesstoworkid_recv_fn hasaccesstoworkid_recv;
	hasaccesstoproperty_send_fn hasaccesstoproperty_send;
	hasaccesstoproperty_recv_fn hasaccesstoproperty_recv;
	getpropvalueforworkid_fn_send getpropertyvalueforworkid_send;
	getpropvalueforworkid_fn_recv getpropertyvalueforworkid_recv;
	getquerystatuschanges_send_fn getquerystatuschanges_send;
	getquerystatuschanges_recv_fn getquerystatuschanges_recv;
	setbindings_fn setbindings;
	getbindings_fn getbindings;
	releasecursor_fn releaseCursor;
	releasecursor_send_fn releasecursor_send;
	releasecursor_recv_fn releasecursor_recv;
	releasequery_send_fn releasequery_send;
	releasequery_recv_fn releasequery_recv;
	findnextoccurrenceindex_send_fn findnextoccurrenceindex_send;
	findnextoccurrenceindex_recv_fn findnextoccurrenceindex_recv;
	getlastunretrievedevt_send_fn getlastunretrievedevt_send;
	getlastunretrievedevt_recv_fn getlastunretrievedevt_recv;
	getquerystats_send_fn getquerystats_send;
	getquerystats_recv_fn getquerystats_recv;
	setscopepriority_send_fn setscopepriority_send;
	setscopepriority_recv_fn setscopepriority_recv;
	filteroutscopestatisticsmessages_send_fn filteroutscopestatsmsgs_send;
	filteroutscopestatisticsmessages_recv_fn filteroutscopestatsmsgs_recv;
	inflect_send_fn inflect_send;
	inflect_recv_fn inflect_recv;
	generatescopestatisticsevent_send_fn generatescopestatisticsevent_send;
	generatescopestatisticsevent_recv_fn generatescopestatisticsevent_recv;
};

#endif
