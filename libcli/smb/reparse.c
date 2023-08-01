/*
 * Unix SMB/CIFS implementation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include "libcli/smb/reparse.h"
#include "libcli/smb/smb_constants.h"
#include "libcli/util/error.h"
#include "lib/util/debug.h"
#include "lib/util/bytearray.h"
#include "lib/util/charset/charset.h"
#include "smb_util.h"

static NTSTATUS reparse_buffer_check(const uint8_t *in_data,
				     size_t in_len,
				     uint32_t *reparse_tag,
				     const uint8_t **_reparse_data,
				     size_t *_reparse_data_length)
{
	uint16_t reparse_data_length;

	if (in_len == 0) {
		DBG_DEBUG("in_len=0\n");
		return NT_STATUS_INVALID_BUFFER_SIZE;
	}
	if (in_len < 8) {
		DBG_DEBUG("in_len=%zu\n", in_len);
		return NT_STATUS_IO_REPARSE_DATA_INVALID;
	}

	reparse_data_length = PULL_LE_U16(in_data, 4);

	if (reparse_data_length > (in_len - 8)) {
		DBG_DEBUG("in_len=%zu, reparse_data_length=%" PRIu16 "\n",
			  in_len,
			  reparse_data_length);
		return NT_STATUS_IO_REPARSE_DATA_INVALID;
	}

	*reparse_tag = PULL_LE_U32(in_data, 0);
	*_reparse_data = in_data + 8;
	*_reparse_data_length = reparse_data_length;

	return NT_STATUS_OK;
}

static int nfs_reparse_buffer_parse(TALLOC_CTX *mem_ctx,
				    struct nfs_reparse_data_buffer *dst,
				    const uint8_t *src,
				    size_t srclen)
{
	uint64_t type;

	if (srclen < 8) {
		DBG_DEBUG("srclen=%zu too short\n", srclen);
		return EINVAL;
	}

	type = PULL_LE_U64(src, 0);

	switch (type) {
	case NFS_SPECFILE_CHR:
		FALL_THROUGH;
	case NFS_SPECFILE_BLK:
		if (srclen < 16) {
			DBG_DEBUG("srclen %zu too short for type %" PRIx64 "\n",
				  srclen,
				  type);
			return EINVAL;
		}
		dst->data.dev.major = PULL_LE_U32(src, 8);
		dst->data.dev.minor = PULL_LE_U32(src, 12);
		break;
	case NFS_SPECFILE_LNK: {
		bool ok;

		ok = convert_string_talloc(mem_ctx,
					   CH_UTF16,
					   CH_UNIX,
					   src + 8,
					   srclen - 8,
					   &dst->data.lnk_target,
					   NULL);
		if (!ok) {
			return errno;
		}
		break;
	}
	case NFS_SPECFILE_FIFO:
		break; /* empty, no data */
	case NFS_SPECFILE_SOCK:
		break; /* empty, no data */
	default:
		DBG_DEBUG("Unknown NFS reparse type %" PRIx64 "\n", type);
		return EINVAL;
	}

	dst->type = type;

	return 0;
}

static int symlink_reparse_buffer_parse(TALLOC_CTX *mem_ctx,
					struct symlink_reparse_struct *dst,
					const uint8_t *src,
					size_t srclen)
{
	uint16_t reparse_data_length;
	uint16_t substitute_name_offset, substitute_name_length;
	uint16_t print_name_offset, print_name_length;
	bool ok;

	if (srclen < 20) {
		DBG_DEBUG("srclen = %zu, expected >= 20\n", srclen);
		return EINVAL;
	}
	if (PULL_LE_U32(src, 0) != IO_REPARSE_TAG_SYMLINK) {
		DBG_DEBUG("Got ReparseTag %8.8x, expected %8.8x\n",
			  PULL_LE_U32(src, 0),
			  IO_REPARSE_TAG_SYMLINK);
		return EINVAL;
	}

	reparse_data_length	= PULL_LE_U16(src, 4);
	substitute_name_offset	= PULL_LE_U16(src, 8);
	substitute_name_length	= PULL_LE_U16(src, 10);
	print_name_offset	= PULL_LE_U16(src, 12);
	print_name_length	= PULL_LE_U16(src, 14);

	if (reparse_data_length < 12) {
		DBG_DEBUG("reparse_data_length = %"PRIu16", expected >= 12\n",
			  reparse_data_length);
		return EINVAL;
	}
	if (smb_buffer_oob(srclen - 8, reparse_data_length, 0)) {
		DBG_DEBUG("reparse_data_length (%"PRIu16") too large for "
			   "src_len (%zu)\n",
			  reparse_data_length,
			  srclen);
		return EINVAL;
	}
	if (smb_buffer_oob(reparse_data_length - 12, substitute_name_offset,
			   substitute_name_length)) {
		DBG_DEBUG("substitute_name (%"PRIu16"/%"PRIu16") does not fit "
			  "in reparse_data_length (%"PRIu16")\n",
			  substitute_name_offset,
			  substitute_name_length,
			  reparse_data_length - 12);
		return EINVAL;
	}
	if (smb_buffer_oob(reparse_data_length - 12, print_name_offset,
			   print_name_length)) {
		DBG_DEBUG("print_name (%"PRIu16"/%"PRIu16") does not fit in "
			  "reparse_data_length (%"PRIu16")\n",
			  print_name_offset,
			  print_name_length,
			  reparse_data_length - 12);
		return EINVAL;
	}

	*dst = (struct symlink_reparse_struct) {
		.unparsed_path_length = PULL_LE_U16(src, 6),
		.flags = PULL_LE_U32(src, 16),
	};

	ok = convert_string_talloc(mem_ctx,
				   CH_UTF16,
				   CH_UNIX,
				   src + 20 + substitute_name_offset,
				   substitute_name_length,
				   &dst->substitute_name,
				   NULL);
	if (!ok) {
		int ret = errno;
		DBG_DEBUG("convert_string_talloc for substitute_name "
			  "failed\n");
		return ret;
	}

	ok = convert_string_talloc(mem_ctx,
				   CH_UTF16,
				   CH_UNIX,
				   src + 20 + print_name_offset,
				   print_name_length,
				   &dst->print_name,
				   NULL);
	if (!ok) {
		int ret = errno;
		DBG_DEBUG("convert_string_talloc for print_name failed\n");
		TALLOC_FREE(dst->substitute_name);
		return ret;
	}

	return 0;
}

NTSTATUS reparse_data_buffer_parse(TALLOC_CTX *mem_ctx,
				   struct reparse_data_buffer *dst,
				   const uint8_t *buf,
				   size_t buflen)
{
	const uint8_t *reparse_data;
	size_t reparse_data_length;
	NTSTATUS status;
	int ret;

	status = reparse_buffer_check(buf,
				      buflen,
				      &dst->tag,
				      &reparse_data,
				      &reparse_data_length);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	switch (dst->tag) {
	case IO_REPARSE_TAG_SYMLINK:
		ret = symlink_reparse_buffer_parse(mem_ctx,
						   &dst->parsed.lnk,
						   reparse_data,
						   reparse_data_length);
		if (ret != 0) {
			return map_nt_error_from_unix_common(ret);
		}
		break;
	case IO_REPARSE_TAG_NFS:
		ret = nfs_reparse_buffer_parse(mem_ctx,
					       &dst->parsed.nfs,
					       reparse_data,
					       reparse_data_length);
		if (ret != 0) {
			return map_nt_error_from_unix_common(ret);
		}
		break;
	default:
		dst->parsed.raw.data = talloc_memdup(mem_ctx,
						     reparse_data,
						     reparse_data_length);
		if (dst->parsed.raw.data == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		dst->parsed.raw.length = reparse_data_length;
		dst->parsed.raw.reserved = PULL_LE_U16(buf, 6);
		break;
	}

	return NT_STATUS_OK;
}

char *reparse_data_buffer_str(TALLOC_CTX *mem_ctx,
			      const struct reparse_data_buffer *dst)
{
	char *s = talloc_strdup(mem_ctx, "");

	switch (dst->tag) {
	case IO_REPARSE_TAG_SYMLINK: {
		const struct symlink_reparse_struct *lnk = &dst->parsed.lnk;
		talloc_asprintf_addbuf(&s,
				       "0x%" PRIx32
				       " (IO_REPARSE_TAG_SYMLINK)\n",
				       dst->tag);
		talloc_asprintf_addbuf(&s,
				       "unparsed=%" PRIu16 "\n",
				       lnk->unparsed_path_length);
		talloc_asprintf_addbuf(&s,
				       "substitute_name=%s\n",
				       lnk->substitute_name);
		talloc_asprintf_addbuf(&s, "print_name=%s\n", lnk->print_name);
		talloc_asprintf_addbuf(&s, "flags=%" PRIu32 "\n", lnk->flags);
		break;
	}
	case IO_REPARSE_TAG_NFS: {
		const struct nfs_reparse_data_buffer *nfs = &dst->parsed.nfs;

		talloc_asprintf_addbuf(&s,
				       "0x%" PRIx32 " (IO_REPARSE_TAG_NFS)\n",
				       dst->tag);

		switch (nfs->type) {
		case NFS_SPECFILE_FIFO:
			talloc_asprintf_addbuf(&s,
					       " 0x%" PRIx64
					       " (NFS_SPECFILE_FIFO)\n",
					       nfs->type);
			break;
		case NFS_SPECFILE_SOCK:
			talloc_asprintf_addbuf(&s,
					       " 0x%" PRIx64
					       " (NFS_SPECFILE_SOCK)\n",
					       nfs->type);
			break;
		case NFS_SPECFILE_LNK:
			talloc_asprintf_addbuf(&s,
					       " 0x%" PRIx64
					       " (NFS_SPECFILE_LNK)\n",
					       nfs->type);
			talloc_asprintf_addbuf(&s,
					       " -> %s\n ",
					       nfs->data.lnk_target);
			break;
		case NFS_SPECFILE_BLK:
			talloc_asprintf_addbuf(&s,
					       " 0x%" PRIx64
					       " (NFS_SPECFILE_BLK)\n",
					       nfs->type);
			talloc_asprintf_addbuf(&s,
					       " %" PRIu32 "/%" PRIu32 "\n",
					       nfs->data.dev.major,
					       nfs->data.dev.minor);
			break;
		case NFS_SPECFILE_CHR:
			talloc_asprintf_addbuf(&s,
					       " 0x%" PRIx64
					       " (NFS_SPECFILE_CHR)\n",
					       nfs->type);
			talloc_asprintf_addbuf(&s,
					       " %" PRIu32 "/%" PRIu32 "\n",
					       nfs->data.dev.major,
					       nfs->data.dev.minor);
			break;
		default:
			talloc_asprintf_addbuf(&s,
					       " 0x%" PRIu64
					       " (Unknown type)\n",
					       nfs->type);
			break;
		}
		break;
	}
	default:
		talloc_asprintf_addbuf(&s, "%" PRIu32 "\n", dst->tag);
		break;
	}
	return s;
}
