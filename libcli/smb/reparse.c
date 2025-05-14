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
#include "lib/util/iov_buf.h"
#include "libcli/smb/smb_constants.h"
#include "libcli/util/error.h"
#include "lib/util/debug.h"
#include "lib/util/bytearray.h"
#include "lib/util/talloc_stack.h"
#include "lib/util/charset/charset.h"
#include "smb_util.h"

NTSTATUS reparse_buffer_check(const uint8_t *in_data,
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

	if (reparse_data_length != (in_len - 8)) {
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
						   buf,
						   buflen);
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

static ssize_t reparse_buffer_marshall(uint32_t reparse_tag,
				       uint16_t reserved,
				       const struct iovec *iov,
				       int iovlen,
				       uint8_t *buf,
				       size_t buflen)
{
	ssize_t reparse_data_length = iov_buflen(iov, iovlen);
	size_t needed;

	if (reparse_data_length == -1) {
		return -1;
	}
	if (reparse_data_length > UINT16_MAX) {
		return -1;
	}

	needed = reparse_data_length + 8;
	if (needed < reparse_data_length) {
		return -1;
	}

	if (buflen >= needed) {
		PUSH_LE_U32(buf, 0, reparse_tag);
		PUSH_LE_U16(buf, 4, reparse_data_length);
		PUSH_LE_U16(buf, 6, reserved);
		iov_buf(iov, iovlen, buf + 8, buflen - 8);
	}

	return needed;
}

static ssize_t
reparse_data_buffer_marshall_syml(const struct symlink_reparse_struct *src,
				  uint8_t *buf,
				  size_t buflen)
{
	uint8_t sbuf[12];
	struct iovec iov[3];
	const char *print_name = src->print_name;
	uint8_t *subst_utf16 = NULL;
	uint8_t *print_utf16 = NULL;
	size_t subst_len = 0;
	size_t print_len = 0;
	ssize_t ret = -1;
	bool ok;

	if (src->substitute_name == NULL) {
		return -1;
	}
	if (src->print_name == NULL) {
		print_name = src->substitute_name;
	}

	iov[0] = (struct iovec){
		.iov_base = sbuf,
		.iov_len = sizeof(sbuf),
	};

	ok = convert_string_talloc(talloc_tos(),
				   CH_UNIX,
				   CH_UTF16,
				   src->substitute_name,
				   strlen(src->substitute_name),
				   &subst_utf16,
				   &subst_len);
	if (!ok) {
		goto fail;
	}
	if (subst_len > UINT16_MAX) {
		goto fail;
	}
	iov[1] = (struct iovec){
		.iov_base = subst_utf16,
		.iov_len = subst_len,
	};

	ok = convert_string_talloc(talloc_tos(),
				   CH_UNIX,
				   CH_UTF16,
				   print_name,
				   strlen(print_name),
				   &print_utf16,
				   &print_len);
	if (!ok) {
		goto fail;
	}
	if (print_len > UINT16_MAX) {
		goto fail;
	}
	iov[2] = (struct iovec){
		.iov_base = print_utf16,
		.iov_len = print_len,
	};

	PUSH_LE_U16(sbuf, 0, 0);	  /* SubstituteNameOffset */
	PUSH_LE_U16(sbuf, 2, subst_len);  /* SubstituteNameLength */
	PUSH_LE_U16(sbuf, 4, subst_len);  /* PrintNameOffset */
	PUSH_LE_U16(sbuf, 6, print_len);  /* PrintNameLength */
	PUSH_LE_U32(sbuf, 8, src->flags); /* Flags */

	ret = reparse_buffer_marshall(IO_REPARSE_TAG_SYMLINK,
				      src->unparsed_path_length,
				      iov,
				      ARRAY_SIZE(iov),
				      buf,
				      buflen);

fail:
	TALLOC_FREE(subst_utf16);
	TALLOC_FREE(print_utf16);
	return ret;
}

static ssize_t
reparse_data_buffer_marshall_nfs(const struct nfs_reparse_data_buffer *src,
				 uint8_t *buf,
				 size_t buflen)
{
	uint8_t typebuf[8];
	uint8_t devbuf[8];
	struct iovec iov[2] = {};
	size_t iovlen;
	uint8_t *lnk_utf16 = NULL;
	size_t lnk_len = 0;
	ssize_t ret;

	PUSH_LE_U64(typebuf, 0, src->type);
	iov[0] = (struct iovec){
		.iov_base = typebuf,
		.iov_len = sizeof(typebuf),
	};
	iovlen = 1;

	switch (src->type) {
	case NFS_SPECFILE_LNK: {
		bool ok = convert_string_talloc(talloc_tos(),
						CH_UNIX,
						CH_UTF16,
						src->data.lnk_target,
						strlen(src->data.lnk_target),
						&lnk_utf16,
						&lnk_len);
		if (!ok) {
			return -1;
		}
		iov[1] = (struct iovec){
			.iov_base = lnk_utf16,
			.iov_len = lnk_len,
		};
		iovlen = 2;
		break;
	}
	case NFS_SPECFILE_CHR:
		FALL_THROUGH;
	case NFS_SPECFILE_BLK:
		PUSH_LE_U32(devbuf, 0, src->data.dev.major);
		PUSH_LE_U32(devbuf, 4, src->data.dev.minor);
		iov[1] = (struct iovec){
			.iov_base = devbuf,
			.iov_len = sizeof(devbuf),
		};
		iovlen = 2;
		break;
	default:
		break;
		/* Nothing to do for NFS_SPECFILE_FIFO and _SOCK */
	}

	ret = reparse_buffer_marshall(IO_REPARSE_TAG_NFS,
				      0,
				      iov,
				      iovlen,
				      buf,
				      buflen);
	TALLOC_FREE(lnk_utf16);
	return ret;
}

ssize_t reparse_data_buffer_marshall(const struct reparse_data_buffer *src,
				     uint8_t *buf,
				     size_t buflen)
{
	TALLOC_CTX *frame = talloc_stackframe();
	ssize_t ret = -1;

	switch (src->tag) {
	case IO_REPARSE_TAG_SYMLINK:

		ret = reparse_data_buffer_marshall_syml(&src->parsed.lnk,
							buf,
							buflen);
		break;

	case IO_REPARSE_TAG_NFS:

		ret = reparse_data_buffer_marshall_nfs(&src->parsed.nfs,
						       buf,
						       buflen);
		break;

	default: {
		struct iovec iov = {
			.iov_base = src->parsed.raw.data,
			.iov_len = src->parsed.raw.length,
		};
		ret = reparse_buffer_marshall(src->tag,
					      src->parsed.raw.reserved,
					      &iov,
					      1,
					      buf,
					      buflen);
	}
	}

	TALLOC_FREE(frame);
	return ret;
}

/*
 * Implement [MS-SMB2] 2.2.2.2.1.1 Handling the Symbolic Link Error Response
 */

int symlink_target_path(TALLOC_CTX *ctx,
			const char *_name_in,
			size_t num_unparsed,
			const char *substitute,
			bool relative,
			char separator,
			char **_target)
{
	size_t name_in_len = strlen(_name_in);
	size_t num_parsed;
	char name_in[name_in_len + 1];
	char *unparsed = NULL;
	char *syml = NULL;
	char *target = NULL;

	if (num_unparsed > name_in_len) {
		return EINVAL;
	}
	num_parsed = name_in_len - num_unparsed;

	/*
	 * We need to NULL out separators in name_in. Make a copy of
	 * _name_in, which is a const char *.
	 */
	memcpy(name_in, _name_in, sizeof(name_in));

	unparsed = name_in + num_parsed;

	if ((num_unparsed != 0) && (unparsed[0] != separator)) {
		/*
		 * Symlinks in the middle of name_in must end in a separator
		 */
		return EINVAL;
	}

	if (!relative) {
		/*
		 * From [MS-SMB2] 2.2.2.2.1.1:
		 *
		 * If the SYMLINK_FLAG_RELATIVE flag is not set in the Flags
		 * field of the symbolic link error response, the unparsed
		 * portion of the file name MUST be appended to the substitute
		 * name to create the new target path name.
		 */
		target = talloc_asprintf(ctx, "%s%s", substitute, unparsed);
		goto done;
	}

	/*
	 * From [MS-SMB2] 2.2.2.2.1.1:
	 *
	 * If the SYMLINK_FLAG_RELATIVE flag is set in the Flags field
	 * of the symbolic link error response, the symbolic link name
	 * MUST be identified by backing up one path name element from
	 * the unparsed portion of the path name. The symbolic link
	 * MUST be replaced with the substitute name to create the new
	 * target path name.
	 */

	{
		char symlink_end_char = unparsed[0]; /* '\0' or a separator */

		unparsed[0] = '\0';
		syml = strrchr_m(name_in, separator);
		unparsed[0] = symlink_end_char;
	}

	if (syml == NULL) {
		/*
		 * Nothing to back up to, the symlink was the first
		 * path component.
		 */
		name_in[0] = '\0';
	} else {
		/*
		 * Make "name_in" up to the symlink usable for asprintf
		 */
		syml[1] = '\0';
	}

	target = talloc_asprintf(ctx, "%s%s%s", name_in, substitute, unparsed);

done:
	if (target == NULL) {
		return ENOMEM;
	}
	*_target = target;
	return 0;
}
