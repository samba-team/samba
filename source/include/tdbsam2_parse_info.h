/* This is an automatically generated file - DO NOT EDIT! */

int gen_dump_struct_domain_sub_structure(TALLOC_CTX *mem_ctx, struct parse_string *, const char *, unsigned);
int gen_parse_struct_domain_sub_structure(TALLOC_CTX *mem_ctx, char *, const char *);
static const struct parse_struct pinfo_domain_sub_structure[] = {
{"next_rid", 0, sizeof(uint32), offsetof(struct domain_sub_structure, next_rid), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{NULL, 0, 0, 0, 0, NULL, 0, NULL, NULL}};

int gen_dump_struct_domain_sub_structure(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent) {
	return gen_dump_struct(mem_ctx, pinfo_domain_sub_structure, p, ptr, indent);
}
int gen_parse_struct_domain_sub_structure(TALLOC_CTX *mem_ctx, char *ptr, const char *str) {
	return gen_parse_struct(mem_ctx, pinfo_domain_sub_structure, ptr, str);
}

int gen_dump_struct_tdbsam2_domain_data(TALLOC_CTX *mem_ctx, struct parse_string *, const char *, unsigned);
int gen_parse_struct_tdbsam2_domain_data(TALLOC_CTX *mem_ctx, char *, const char *);
static const struct parse_struct pinfo_tdbsam2_domain_data[] = {
{"mem_ctx", 1, sizeof(TALLOC_CTX), offsetof(struct tdbsam2_domain_data, mem_ctx), 0, NULL, 0, gen_dump_TALLOC_CTX, gen_parse_TALLOC_CTX},
{"type", 0, sizeof(uint32), offsetof(struct tdbsam2_domain_data, type), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"version", 0, sizeof(uint32), offsetof(struct tdbsam2_domain_data, version), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"xcounter", 0, sizeof(uint32), offsetof(struct tdbsam2_domain_data, xcounter), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"sec_desc", 1, sizeof(SEC_DESC), offsetof(struct tdbsam2_domain_data, sec_desc), 0, NULL, 0, gen_dump_SEC_DESC, gen_parse_SEC_DESC},
{"dom_sid", 1, sizeof(DOM_SID), offsetof(struct tdbsam2_domain_data, dom_sid), 0, NULL, 0, gen_dump_DOM_SID, gen_parse_DOM_SID},
{"name", 1, sizeof(char), offsetof(struct tdbsam2_domain_data, name), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"description", 1, sizeof(char), offsetof(struct tdbsam2_domain_data, description), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"dss", 1, sizeof(struct domain_sub_structure), offsetof(struct tdbsam2_domain_data, dss), 0, NULL, 0, gen_dump_struct_domain_sub_structure, gen_parse_struct_domain_sub_structure},
{NULL, 0, 0, 0, 0, NULL, 0, NULL, NULL}};

int gen_dump_struct_tdbsam2_domain_data(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent) {
	return gen_dump_struct(mem_ctx, pinfo_tdbsam2_domain_data, p, ptr, indent);
}
int gen_parse_struct_tdbsam2_domain_data(TALLOC_CTX *mem_ctx, char *ptr, const char *str) {
	return gen_parse_struct(mem_ctx, pinfo_tdbsam2_domain_data, ptr, str);
}

int gen_dump_struct_user_sub_structure(TALLOC_CTX *mem_ctx, struct parse_string *, const char *, unsigned);
int gen_parse_struct_user_sub_structure(TALLOC_CTX *mem_ctx, char *, const char *);
static const struct parse_struct pinfo_user_sub_structure[] = {
{"group_sid", 1, sizeof(DOM_SID), offsetof(struct user_sub_structure, group_sid), 0, NULL, 0, gen_dump_DOM_SID, gen_parse_DOM_SID},
{"logon_time", 0, sizeof(NTTIME), offsetof(struct user_sub_structure, logon_time), 0, NULL, 0, gen_dump_NTTIME, gen_parse_NTTIME},
{"logoff_time", 0, sizeof(NTTIME), offsetof(struct user_sub_structure, logoff_time), 0, NULL, 0, gen_dump_NTTIME, gen_parse_NTTIME},
{"kickoff_time", 0, sizeof(NTTIME), offsetof(struct user_sub_structure, kickoff_time), 0, NULL, 0, gen_dump_NTTIME, gen_parse_NTTIME},
{"pass_last_set_time", 0, sizeof(NTTIME), offsetof(struct user_sub_structure, pass_last_set_time), 0, NULL, 0, gen_dump_NTTIME, gen_parse_NTTIME},
{"pass_can_change_time", 0, sizeof(NTTIME), offsetof(struct user_sub_structure, pass_can_change_time), 0, NULL, 0, gen_dump_NTTIME, gen_parse_NTTIME},
{"pass_must_change_time", 0, sizeof(NTTIME), offsetof(struct user_sub_structure, pass_must_change_time), 0, NULL, 0, gen_dump_NTTIME, gen_parse_NTTIME},
{"full_name", 1, sizeof(char), offsetof(struct user_sub_structure, full_name), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"home_dir", 1, sizeof(char), offsetof(struct user_sub_structure, home_dir), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"dir_drive", 1, sizeof(char), offsetof(struct user_sub_structure, dir_drive), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"logon_script", 1, sizeof(char), offsetof(struct user_sub_structure, logon_script), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"profile_path", 1, sizeof(char), offsetof(struct user_sub_structure, profile_path), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"workstations", 1, sizeof(char), offsetof(struct user_sub_structure, workstations), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"unknown_str", 1, sizeof(char), offsetof(struct user_sub_structure, unknown_str), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"munged_dial", 1, sizeof(char), offsetof(struct user_sub_structure, munged_dial), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"lm_pw", 0, sizeof(DATA_BLOB), offsetof(struct user_sub_structure, lm_pw), 0, NULL, 0, gen_dump_DATA_BLOB, gen_parse_DATA_BLOB},
{"nt_pw", 0, sizeof(DATA_BLOB), offsetof(struct user_sub_structure, nt_pw), 0, NULL, 0, gen_dump_DATA_BLOB, gen_parse_DATA_BLOB},
{"acct_ctrl", 0, sizeof(uint16), offsetof(struct user_sub_structure, acct_ctrl), 0, NULL, 0, gen_dump_uint16, gen_parse_uint16},
{"logon_divs", 0, sizeof(uint16), offsetof(struct user_sub_structure, logon_divs), 0, NULL, 0, gen_dump_uint16, gen_parse_uint16},
{"hours_len", 0, sizeof(uint32), offsetof(struct user_sub_structure, hours_len), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"hours", 1, sizeof(uint8), offsetof(struct user_sub_structure, hours), 0, "hours_len", 0, gen_dump_uint8, gen_parse_uint8},
{"bad_password_count", 0, sizeof(uint16), offsetof(struct user_sub_structure, bad_password_count), 0, NULL, 0, gen_dump_uint16, gen_parse_uint16},
{"logon_count", 0, sizeof(uint16), offsetof(struct user_sub_structure, logon_count), 0, NULL, 0, gen_dump_uint16, gen_parse_uint16},
{"unknown_3", 0, sizeof(uint32), offsetof(struct user_sub_structure, unknown_3), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"unknown_6", 0, sizeof(uint32), offsetof(struct user_sub_structure, unknown_6), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{NULL, 0, 0, 0, 0, NULL, 0, NULL, NULL}};

int gen_dump_struct_user_sub_structure(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent) {
	return gen_dump_struct(mem_ctx, pinfo_user_sub_structure, p, ptr, indent);
}
int gen_parse_struct_user_sub_structure(TALLOC_CTX *mem_ctx, char *ptr, const char *str) {
	return gen_parse_struct(mem_ctx, pinfo_user_sub_structure, ptr, str);
}

int gen_dump_struct_tdbsam2_user_data(TALLOC_CTX *mem_ctx, struct parse_string *, const char *, unsigned);
int gen_parse_struct_tdbsam2_user_data(TALLOC_CTX *mem_ctx, char *, const char *);
static const struct parse_struct pinfo_tdbsam2_user_data[] = {
{"mem_ctx", 1, sizeof(TALLOC_CTX), offsetof(struct tdbsam2_user_data, mem_ctx), 0, NULL, 0, gen_dump_TALLOC_CTX, gen_parse_TALLOC_CTX},
{"type", 0, sizeof(uint32), offsetof(struct tdbsam2_user_data, type), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"version", 0, sizeof(uint32), offsetof(struct tdbsam2_user_data, version), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"xcounter", 0, sizeof(uint32), offsetof(struct tdbsam2_user_data, xcounter), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"sec_desc", 1, sizeof(SEC_DESC), offsetof(struct tdbsam2_user_data, sec_desc), 0, NULL, 0, gen_dump_SEC_DESC, gen_parse_SEC_DESC},
{"user_sid", 1, sizeof(DOM_SID), offsetof(struct tdbsam2_user_data, user_sid), 0, NULL, 0, gen_dump_DOM_SID, gen_parse_DOM_SID},
{"name", 1, sizeof(char), offsetof(struct tdbsam2_user_data, name), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"description", 1, sizeof(char), offsetof(struct tdbsam2_user_data, description), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"uss", 1, sizeof(struct user_sub_structure), offsetof(struct tdbsam2_user_data, uss), 0, NULL, 0, gen_dump_struct_user_sub_structure, gen_parse_struct_user_sub_structure},
{NULL, 0, 0, 0, 0, NULL, 0, NULL, NULL}};

int gen_dump_struct_tdbsam2_user_data(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent) {
	return gen_dump_struct(mem_ctx, pinfo_tdbsam2_user_data, p, ptr, indent);
}
int gen_parse_struct_tdbsam2_user_data(TALLOC_CTX *mem_ctx, char *ptr, const char *str) {
	return gen_parse_struct(mem_ctx, pinfo_tdbsam2_user_data, ptr, str);
}

int gen_dump_struct_group_sub_structure(TALLOC_CTX *mem_ctx, struct parse_string *, const char *, unsigned);
int gen_parse_struct_group_sub_structure(TALLOC_CTX *mem_ctx, char *, const char *);
static const struct parse_struct pinfo_group_sub_structure[] = {
{"count", 0, sizeof(uint32), offsetof(struct group_sub_structure, count), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"members", 1, sizeof(DOM_SID), offsetof(struct group_sub_structure, members), 0, "count", 0, gen_dump_DOM_SID, gen_parse_DOM_SID},
{NULL, 0, 0, 0, 0, NULL, 0, NULL, NULL}};

int gen_dump_struct_group_sub_structure(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent) {
	return gen_dump_struct(mem_ctx, pinfo_group_sub_structure, p, ptr, indent);
}
int gen_parse_struct_group_sub_structure(TALLOC_CTX *mem_ctx, char *ptr, const char *str) {
	return gen_parse_struct(mem_ctx, pinfo_group_sub_structure, ptr, str);
}

int gen_dump_struct_tdbsam2_group_data(TALLOC_CTX *mem_ctx, struct parse_string *, const char *, unsigned);
int gen_parse_struct_tdbsam2_group_data(TALLOC_CTX *mem_ctx, char *, const char *);
static const struct parse_struct pinfo_tdbsam2_group_data[] = {
{"mem_ctx", 1, sizeof(TALLOC_CTX), offsetof(struct tdbsam2_group_data, mem_ctx), 0, NULL, 0, gen_dump_TALLOC_CTX, gen_parse_TALLOC_CTX},
{"type", 0, sizeof(uint32), offsetof(struct tdbsam2_group_data, type), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"version", 0, sizeof(uint32), offsetof(struct tdbsam2_group_data, version), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"xcounter", 0, sizeof(uint32), offsetof(struct tdbsam2_group_data, xcounter), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"sec_desc", 1, sizeof(SEC_DESC), offsetof(struct tdbsam2_group_data, sec_desc), 0, NULL, 0, gen_dump_SEC_DESC, gen_parse_SEC_DESC},
{"group_sid", 1, sizeof(DOM_SID), offsetof(struct tdbsam2_group_data, group_sid), 0, NULL, 0, gen_dump_DOM_SID, gen_parse_DOM_SID},
{"name", 1, sizeof(char), offsetof(struct tdbsam2_group_data, name), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"description", 1, sizeof(char), offsetof(struct tdbsam2_group_data, description), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"gss", 1, sizeof(struct group_sub_structure), offsetof(struct tdbsam2_group_data, gss), 0, NULL, 0, gen_dump_struct_group_sub_structure, gen_parse_struct_group_sub_structure},
{NULL, 0, 0, 0, 0, NULL, 0, NULL, NULL}};

int gen_dump_struct_tdbsam2_group_data(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent) {
	return gen_dump_struct(mem_ctx, pinfo_tdbsam2_group_data, p, ptr, indent);
}
int gen_parse_struct_tdbsam2_group_data(TALLOC_CTX *mem_ctx, char *ptr, const char *str) {
	return gen_parse_struct(mem_ctx, pinfo_tdbsam2_group_data, ptr, str);
}

int gen_dump_struct_priv_sub_structure(TALLOC_CTX *mem_ctx, struct parse_string *, const char *, unsigned);
int gen_parse_struct_priv_sub_structure(TALLOC_CTX *mem_ctx, char *, const char *);
static const struct parse_struct pinfo_priv_sub_structure[] = {
{"privilege", 1, sizeof(LUID_ATTR), offsetof(struct priv_sub_structure, privilege), 0, NULL, 0, gen_dump_LUID_ATTR, gen_parse_LUID_ATTR},
{"count", 0, sizeof(uint32), offsetof(struct priv_sub_structure, count), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"members", 1, sizeof(DOM_SID), offsetof(struct priv_sub_structure, members), 0, "count", 0, gen_dump_DOM_SID, gen_parse_DOM_SID},
{NULL, 0, 0, 0, 0, NULL, 0, NULL, NULL}};

int gen_dump_struct_priv_sub_structure(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent) {
	return gen_dump_struct(mem_ctx, pinfo_priv_sub_structure, p, ptr, indent);
}
int gen_parse_struct_priv_sub_structure(TALLOC_CTX *mem_ctx, char *ptr, const char *str) {
	return gen_parse_struct(mem_ctx, pinfo_priv_sub_structure, ptr, str);
}

int gen_dump_struct_tdbsam2_priv_data(TALLOC_CTX *mem_ctx, struct parse_string *, const char *, unsigned);
int gen_parse_struct_tdbsam2_priv_data(TALLOC_CTX *mem_ctx, char *, const char *);
static const struct parse_struct pinfo_tdbsam2_priv_data[] = {
{"mem_ctx", 1, sizeof(TALLOC_CTX), offsetof(struct tdbsam2_priv_data, mem_ctx), 0, NULL, 0, gen_dump_TALLOC_CTX, gen_parse_TALLOC_CTX},
{"type", 0, sizeof(uint32), offsetof(struct tdbsam2_priv_data, type), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"version", 0, sizeof(uint32), offsetof(struct tdbsam2_priv_data, version), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"xcounter", 0, sizeof(uint32), offsetof(struct tdbsam2_priv_data, xcounter), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"null_sid", 1, sizeof(DOM_SID), offsetof(struct tdbsam2_priv_data, null_sid), 0, NULL, 0, gen_dump_DOM_SID, gen_parse_DOM_SID},
{"name", 1, sizeof(char), offsetof(struct tdbsam2_priv_data, name), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"description", 1, sizeof(char), offsetof(struct tdbsam2_priv_data, description), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"pss", 1, sizeof(struct priv_sub_structure), offsetof(struct tdbsam2_priv_data, pss), 0, NULL, 0, gen_dump_struct_priv_sub_structure, gen_parse_struct_priv_sub_structure},
{NULL, 0, 0, 0, 0, NULL, 0, NULL, NULL}};

int gen_dump_struct_tdbsam2_priv_data(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent) {
	return gen_dump_struct(mem_ctx, pinfo_tdbsam2_priv_data, p, ptr, indent);
}
int gen_parse_struct_tdbsam2_priv_data(TALLOC_CTX *mem_ctx, char *ptr, const char *str) {
	return gen_parse_struct(mem_ctx, pinfo_tdbsam2_priv_data, ptr, str);
}

