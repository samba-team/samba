/*
   Unix SMB/CIFS implementation.
   Main metadata server / Spotlight routines

   Copyright (C) Ralph Boehme			2012-2014

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

#include "replace.h"
#include "sparql_mapping.h"

const struct sl_attr_map *sl_attr_map_by_spotlight(const char *sl_attr)
{
	static const struct sl_attr_map spotlight_sparql_attr_map[] = {
		{
			.spotlight_attr = "*",
			.type = ssmt_fts,
			.sparql_attr = "fts:match",
		},

		/* Filesystem metadata */
		{
			.spotlight_attr = "kMDItemFSLabel",
			.type = ssmt_num,
			.sparql_attr = NULL,
		},
		{
			.spotlight_attr = "kMDItemDisplayName",
			.type = ssmt_str,
			.sparql_attr = "nfo:fileName",
		},
		{
			.spotlight_attr = "kMDItemFSName",
			.type = ssmt_str,
			.sparql_attr = "nfo:fileName",
		},
		{
			.spotlight_attr = "kMDItemFSContentChangeDate",
			.type = ssmt_date,
			.sparql_attr = "nfo:fileLastModified",
		},
		{
			.spotlight_attr = "kMDItemLastUsedDate",
			.type = ssmt_date,
			.sparql_attr = "nfo:fileLastAccessed",
		},

		/* Common metadata */
		{
			.spotlight_attr = "kMDItemTextContent",
			.type = ssmt_fts,
			.sparql_attr = "fts:match",
		},
		{
			.spotlight_attr = "kMDItemContentCreationDate",
			.type = ssmt_date,
			.sparql_attr = "nie:contentCreated",
		},
		{
			.spotlight_attr = "kMDItemContentModificationDate",
			.type = ssmt_date,
			.sparql_attr = "nfo:fileLastModified",
		},
		{
			.spotlight_attr = "kMDItemAttributeChangeDate",
			.type = ssmt_date,
			.sparql_attr = "nfo:fileLastModified",
		},
		{
			.spotlight_attr = "kMDItemAuthors",
			.type = ssmt_str,
			.sparql_attr = "dc:creator",
		},
		{
			.spotlight_attr = "kMDItemCopyright",
			.type = ssmt_str,
			.sparql_attr = "nie:copyright",
		},
		{
			.spotlight_attr = "kMDItemCountry",
			.type = ssmt_str,
			.sparql_attr = "nco:country",
		},
		{
			.spotlight_attr = "kMDItemCreator",
			.type = ssmt_str,
			.sparql_attr = "dc:creator",
		},
		{
			.spotlight_attr = "kMDItemDurationSeconds",
			.type = ssmt_num,
			.sparql_attr = "nfo:duration",
		},
		{
			.spotlight_attr = "kMDItemNumberOfPages",
			.type = ssmt_num,
			.sparql_attr = "nfo:pageCount",
		},
		{
			.spotlight_attr = "kMDItemTitle",
			.type = ssmt_str,
			.sparql_attr = "nie:title",
		},
		{
			.spotlight_attr = "kMDItemCity",
			.type = ssmt_str,
			.sparql_attr = "nco:locality",
		},
		{
			.spotlight_attr = "kMDItemCoverage",
			.type = ssmt_str,
			.sparql_attr = "nco:locality",
		},
		{
			.spotlight_attr = "_kMDItemGroupId",
			.type = ssmt_type,
			.sparql_attr = NULL,
		},
		{
			.spotlight_attr = "kMDItemContentTypeTree",
			.type = ssmt_type,
			.sparql_attr = NULL,
		},
		{
			.spotlight_attr = "kMDItemContentType",
			.type = ssmt_type,
			.sparql_attr = NULL,
		},

		/* Image metadata */
		{
			.spotlight_attr = "kMDItemPixelWidth",
			.type = ssmt_num,
			.sparql_attr = "nfo:width",
		},
		{
			.spotlight_attr = "kMDItemPixelHeight",
			.type = ssmt_num,
			.sparql_attr = "nfo:height",
		},
		{
			.spotlight_attr = "kMDItemColorSpace",
			.type = ssmt_str,
			.sparql_attr = "nexif:colorSpace",
		},
		{
			.spotlight_attr = "kMDItemBitsPerSample",
			.type = ssmt_num,
			.sparql_attr = "nfo:colorDepth",
		},
		{
			.spotlight_attr = "kMDItemFocalLength",
			.type = ssmt_num,
			.sparql_attr = "nmm:focalLength",
		},
		{
			.spotlight_attr = "kMDItemISOSpeed",
			.type = ssmt_num,
			.sparql_attr = "nmm:isoSpeed",
		},
		{
			.spotlight_attr = "kMDItemOrientation",
			.type = ssmt_bool,
			.sparql_attr = "nfo:orientation",
		},
		{
			.spotlight_attr = "kMDItemResolutionWidthDPI",
			.type = ssmt_num,
			.sparql_attr = "nfo:horizontalResolution",
		},
		{
			.spotlight_attr = "kMDItemResolutionHeightDPI",
			.type = ssmt_num,
			.sparql_attr = "nfo:verticalResolution",
		},
		{
			.spotlight_attr = "kMDItemExposureTimeSeconds",
			.type = ssmt_num,
			.sparql_attr = "nmm:exposureTime",
		},

		/* Audio metadata */
		{
			.spotlight_attr = "kMDItemComposer",
			.type = ssmt_str,
			.sparql_attr = "nmm:composer",
		},
		{
			.spotlight_attr = "kMDItemMusicalGenre",
			.type = ssmt_str,
			.sparql_attr = "nfo:genre",
		},
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(spotlight_sparql_attr_map); i++) {
		const struct sl_attr_map *m = &spotlight_sparql_attr_map[i];
		int cmp;

		cmp = strcmp(m->spotlight_attr, sl_attr);
		if (cmp == 0) {
			return m;
		}
	}

	return NULL;
}

const struct sl_type_map *sl_type_map_by_spotlight(const char *sl_type)
{
	static const struct sl_type_map spotlight_sparql_type_map[] = {
		{
			.spotlight_type = "1",
			.type = kMDTypeMapRDF,
			.sparql_type = "http://www.semanticdesktop.org/ontologies/2007/03/22/nmo#Email",
		},
		{
			.spotlight_type = "2",
			.type = kMDTypeMapRDF,
			.sparql_type = "http://www.semanticdesktop.org/ontologies/2007/03/22/nco#Contact",
		},
		{
			.spotlight_type = "3",
			.type = kMDTypeMapNotSup,
			.sparql_type = NULL, /*PrefPane*/
		},
		{
			.spotlight_type = "4",
			.type = kMDTypeMapRDF,
			.sparql_type = "http://www.semanticdesktop.org/ontologies/2007/03/22/nfo#Font",
		},
		{
			.spotlight_type = "5",
			.type = kMDTypeMapRDF,
			.sparql_type = "http://www.semanticdesktop.org/ontologies/2007/03/22/nfo#Bookmark",
		},
		{
			.spotlight_type = "6",
			.type = kMDTypeMapRDF,
			.sparql_type = "http://www.semanticdesktop.org/ontologies/2007/03/22/nco#Contact",
		},
		{
			.spotlight_type = "7",
			.type = kMDTypeMapRDF,
			.sparql_type = "http://www.semanticdesktop.org/ontologies/2007/03/22/nfo#Video",
		},
		{
			.spotlight_type = "8",
			.type = kMDTypeMapRDF,
			.sparql_type = "http://www.semanticdesktop.org/ontologies/2007/03/22/nfo#Executable",
		},
		{
			.spotlight_type = "9",
			.type = kMDTypeMapRDF,
			.sparql_type = "http://www.semanticdesktop.org/ontologies/2007/03/22/nfo#Folder",
		},
		{
			.spotlight_type = "10",
			.type = kMDTypeMapRDF,
			.sparql_type = "http://www.semanticdesktop.org/ontologies/2007/03/22/nfo#Audio",
		},
		{
			.spotlight_type = "11",
			.type = kMDTypeMapMime,
			.sparql_type = "application/pdf",
		},
		{
			.spotlight_type = "12",
			.type = kMDTypeMapRDF,
			.sparql_type = "http://www.semanticdesktop.org/ontologies/2007/03/22/nfo#Presentation",
		},
		{
			.spotlight_type = "13",
			.type = kMDTypeMapRDF,
			.sparql_type = "http://www.semanticdesktop.org/ontologies/2007/03/22/nfo#Image",
		},
		{
			.spotlight_type = "public.jpeg",
			.type = kMDTypeMapMime,
			.sparql_type = "image/jpeg",
		},
		{
			.spotlight_type = "public.tiff",
			.type = kMDTypeMapMime,
			.sparql_type = "image/tiff",
		},
		{
			.spotlight_type = "com.compuserve.gif",
			.type = kMDTypeMapMime,
			.sparql_type = "image/gif",
		},
		{
			.spotlight_type = "public.png",
			.type = kMDTypeMapMime,
			.sparql_type = "image/png",
		},
		{
			.spotlight_type = "com.microsoft.bmp",
			.type = kMDTypeMapMime,
			.sparql_type = "image/bmp",
		},
		{
			.spotlight_type = "public.content",
			.type = kMDTypeMapRDF,
			.sparql_type = "http://www.semanticdesktop.org/ontologies/2007/03/22/nfo#Document",
		},
		{
			.spotlight_type = "public.mp3",
			.type = kMDTypeMapMime,
			.sparql_type = "audio/mpeg",
		},
		{
			.spotlight_type = "public.mpeg-4-audio",
			.type = kMDTypeMapMime,
			.sparql_type = "audio/x-aac",
		},
		{
			.spotlight_type = "com.apple.application",
			.type = kMDTypeMapRDF,
			.sparql_type = "http://www.semanticdesktop.org/ontologies/2007/03/22/nfo#Software",
		},
		{
			.spotlight_type = "public.text",
			.type = kMDTypeMapRDF,
			.sparql_type = "http://www.semanticdesktop.org/ontologies/2007/03/22/nfo#TextDocument",
		},
		{
			.spotlight_type = "public.plain-text",
			.type = kMDTypeMapMime,
			.sparql_type = "text/plain",
		},
		{
			.spotlight_type = "public.rtf",
			.type = kMDTypeMapMime,
			.sparql_type = "text/rtf",
		},
		{
			.spotlight_type = "public.html",
			.type = kMDTypeMapMime,
			.sparql_type = "text/html",
		},
		{
			.spotlight_type = "public.xml",
			.type = kMDTypeMapMime,
			.sparql_type = "text/xml",
		},
		{
			.spotlight_type = "public.source-code",
			.type = kMDTypeMapRDF,
			.sparql_type = "http://www.semanticdesktop.org/ontologies/2007/03/22/nfo#SourceCode",
		},
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(spotlight_sparql_type_map); i++) {
		const struct sl_type_map *m = &spotlight_sparql_type_map[i];
		int cmp;

		cmp = strcmp(m->spotlight_type, sl_type);
		if (cmp == 0) {
			return m;
		}
	}

	return NULL;
}
