#include "includes.h"
#include "../librpc/ndr/libndr.h"
#include "ndr_dns_utils.h"


/**
  push a dns/nbt string list to the wire
*/
enum ndr_err_code ndr_push_dns_string_list(struct ndr_push *ndr,
					   struct ndr_token_list *string_list,
					   int ndr_flags,
					   const char *s,
					   bool is_nbt)
{
	const char *start = s;
	bool use_compression;
	size_t max_length;
	if (is_nbt) {
		use_compression = true;
		/*
		 * Max length is longer in NBT/Wins, because Windows counts
		 * the semi-decompressed size of the netbios name (16 bytes)
		 * rather than the wire size of 32, which is what you'd expect
		 * if it followed RFC1002 (it uses the short form in
		 * [MS-WINSRA]). In other words the maximum size of the
		 * "scope" is 237, not 221.
		 *
		 * We make the size limit slightly larger than 255 + 16,
		 * because the 237 scope limit is already enforced in the
		 * winsserver code with a specific return value; bailing out
		 * here would muck with that.
		 */
		max_length = 274;
	} else {
		use_compression = !(ndr->flags & LIBNDR_FLAG_NO_COMPRESSION);
		max_length = 255;
	}

	if (!(ndr_flags & NDR_SCALARS)) {
		return NDR_ERR_SUCCESS;
	}

	while (s && *s) {
		enum ndr_err_code ndr_err;
		char *compname;
		size_t complen;
		uint32_t offset;

		if (use_compression) {
			/* see if we have pushed the remaining string already,
			 * if so we use a label pointer to this string
			 */
			ndr_err = ndr_token_retrieve_cmp_fn(string_list, s,
							    &offset,
							    (comparison_fn_t)strcmp,
							    false);
			if (NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				uint8_t b[2];

				if (offset > 0x3FFF) {
					return ndr_push_error(ndr, NDR_ERR_STRING,
							      "offset for dns string " \
							      "label pointer " \
							      "%u[%08X] > 0x00003FFF",
							      offset, offset);
				}

				b[0] = 0xC0 | (offset>>8);
				b[1] = (offset & 0xFF);

				return ndr_push_bytes(ndr, b, 2);
			}
		}

		complen = strcspn(s, ".");

		/* the length must fit into 6 bits (i.e. <= 63) */
		if (complen > 0x3F) {
			return ndr_push_error(ndr, NDR_ERR_STRING,
					      "component length %u[%08X] > " \
					      "0x0000003F",
					      (unsigned)complen,
					      (unsigned)complen);
		}

		if (complen == 0 && s[complen] == '.') {
			return ndr_push_error(ndr, NDR_ERR_STRING,
					      "component length is 0 "
					      "(consecutive dots)");
		}

		if (is_nbt && s[complen] == '.' && s[complen + 1] == '\0') {
			/* nbt names are sometimes usernames, and we need to
			 * keep a trailing dot to ensure it is byte-identical,
			 * (not just semantically identical given DNS
			 * semantics). */
			complen++;
		}

		compname = talloc_asprintf(ndr, "%c%*.*s",
						(unsigned char)complen,
						(unsigned char)complen,
						(unsigned char)complen, s);
		NDR_ERR_HAVE_NO_MEMORY(compname);

		/* remember the current component + the rest of the string
		 * so it can be reused later
		 */
		if (use_compression) {
			NDR_CHECK(ndr_token_store(ndr, string_list, s,
						  ndr->offset));
		}

		/* push just this component into the blob */
		NDR_CHECK(ndr_push_bytes(ndr, (const uint8_t *)compname,
					 complen+1));
		talloc_free(compname);

		s += complen;
		if (*s == '.') {
			s++;
		}
		if (s - start > max_length) {
			return ndr_push_error(ndr, NDR_ERR_STRING,
					      "name > %zu character long",
					      max_length);
		}
	}

	/* if we reach the end of the string and have pushed the last component
	 * without using a label pointer, we need to terminate the string
	 */
	return ndr_push_bytes(ndr, (const uint8_t *)"", 1);
}
