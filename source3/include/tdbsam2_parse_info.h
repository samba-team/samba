/* This is an automatically generated file - DO NOT EDIT! */

int gen_dump_struct_gums_user(TALLOC_CTX *mem_ctx, struct parse_string *, const char *, unsigned);
int gen_parse_struct_gums_user(TALLOC_CTX *mem_ctx, char *, const char *);
static const struct parse_struct pinfo_gums_user[] = {
{"group_sid", 1, sizeof(DOM_SID), offsetof(struct gums_user, group_sid), 0, NULL, 0, gen_dump_DOM_SID, gen_parse_DOM_SID},
{"logon_time", 0, sizeof(NTTIME), offsetof(struct gums_user, logon_time), 0, NULL, 0, gen_dump_NTTIME, gen_parse_NTTIME},
{"logoff_time", 0, sizeof(NTTIME), offsetof(struct gums_user, logoff_time), 0, NULL, 0, gen_dump_NTTIME, gen_parse_NTTIME},
{"kickoff_time", 0, sizeof(NTTIME), offsetof(struct gums_user, kickoff_time), 0, NULL, 0, gen_dump_NTTIME, gen_parse_NTTIME},
{"pass_last_set_time", 0, sizeof(NTTIME), offsetof(struct gums_user, pass_last_set_time), 0, NULL, 0, gen_dump_NTTIME, gen_parse_NTTIME},
{"pass_can_change_time", 0, sizeof(NTTIME), offsetof(struct gums_user, pass_can_change_time), 0, NULL, 0, gen_dump_NTTIME, gen_parse_NTTIME},
{"pass_must_change_time", 0, sizeof(NTTIME), offsetof(struct gums_user, pass_must_change_time), 0, NULL, 0, gen_dump_NTTIME, gen_parse_NTTIME},
{"full_name", 1, sizeof(char), offsetof(struct gums_user, full_name), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"home_dir", 1, sizeof(char), offsetof(struct gums_user, home_dir), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"dir_drive", 1, sizeof(char), offsetof(struct gums_user, dir_drive), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"logon_script", 1, sizeof(char), offsetof(struct gums_user, logon_script), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"profile_path", 1, sizeof(char), offsetof(struct gums_user, profile_path), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"workstations", 1, sizeof(char), offsetof(struct gums_user, workstations), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"unknown_str", 1, sizeof(char), offsetof(struct gums_user, unknown_str), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"munged_dial", 1, sizeof(char), offsetof(struct gums_user, munged_dial), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"lm_pw", 0, sizeof(DATA_BLOB), offsetof(struct gums_user, lm_pw), 0, NULL, 0, gen_dump_DATA_BLOB, gen_parse_DATA_BLOB},
{"nt_pw", 0, sizeof(DATA_BLOB), offsetof(struct gums_user, nt_pw), 0, NULL, 0, gen_dump_DATA_BLOB, gen_parse_DATA_BLOB},
{"acct_ctrl", 0, sizeof(uint16), offsetof(struct gums_user, acct_ctrl), 0, NULL, 0, gen_dump_uint16, gen_parse_uint16},
{"logon_divs", 0, sizeof(uint16), offsetof(struct gums_user, logon_divs), 0, NULL, 0, gen_dump_uint16, gen_parse_uint16},
{"hours_len", 0, sizeof(uint32), offsetof(struct gums_user, hours_len), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"hours", 1, sizeof(uint8), offsetof(struct gums_user, hours), 0, "hours_len", 0, gen_dump_uint8, gen_parse_uint8},
{"bad_password_count", 0, sizeof(uint16), offsetof(struct gums_user, bad_password_count), 0, NULL, 0, gen_dump_uint16, gen_parse_uint16},
{"logon_count", 0, sizeof(uint16), offsetof(struct gums_user, logon_count), 0, NULL, 0, gen_dump_uint16, gen_parse_uint16},
{"unknown_3", 0, sizeof(uint32), offsetof(struct gums_user, unknown_3), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"unknown_6", 0, sizeof(uint32), offsetof(struct gums_user, unknown_6), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{NULL, 0, 0, 0, 0, NULL, 0, NULL, NULL}};

int gen_dump_struct_gums_user(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent) {
	return gen_dump_struct(mem_ctx, pinfo_gums_user, p, ptr, indent);
}
int gen_parse_struct_gums_user(TALLOC_CTX *mem_ctx, char *ptr, const char *str) {
	return gen_parse_struct(mem_ctx, pinfo_gums_user, ptr, str);
}

int gen_dump_struct_gums_group(TALLOC_CTX *mem_ctx, struct parse_string *, const char *, unsigned);
int gen_parse_struct_gums_group(TALLOC_CTX *mem_ctx, char *, const char *);
static const struct parse_struct pinfo_gums_group[] = {
{"count", 0, sizeof(uint32), offsetof(struct gums_group, count), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"members", 1, sizeof(DOM_SID), offsetof(struct gums_group, members), 0, "count", 0, gen_dump_DOM_SID, gen_parse_DOM_SID},
{NULL, 0, 0, 0, 0, NULL, 0, NULL, NULL}};

int gen_dump_struct_gums_group(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent) {
	return gen_dump_struct(mem_ctx, pinfo_gums_group, p, ptr, indent);
}
int gen_parse_struct_gums_group(TALLOC_CTX *mem_ctx, char *ptr, const char *str) {
	return gen_parse_struct(mem_ctx, pinfo_gums_group, ptr, str);
}

int gen_dump_struct_gums_domain(TALLOC_CTX *mem_ctx, struct parse_string *, const char *, unsigned);
int gen_parse_struct_gums_domain(TALLOC_CTX *mem_ctx, char *, const char *);
static const struct parse_struct pinfo_gums_domain[] = {
{"next_rid", 0, sizeof(uint32), offsetof(struct gums_domain, next_rid), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{NULL, 0, 0, 0, 0, NULL, 0, NULL, NULL}};

int gen_dump_struct_gums_domain(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent) {
	return gen_dump_struct(mem_ctx, pinfo_gums_domain, p, ptr, indent);
}
int gen_parse_struct_gums_domain(TALLOC_CTX *mem_ctx, char *ptr, const char *str) {
	return gen_parse_struct(mem_ctx, pinfo_gums_domain, ptr, str);
}

int gen_dump_struct_gums_object(TALLOC_CTX *mem_ctx, struct parse_string *, const char *, unsigned);
int gen_parse_struct_gums_object(TALLOC_CTX *mem_ctx, char *, const char *);
static const struct parse_struct pinfo_gums_object[] = {
{"mem_ctx", 1, sizeof(TALLOC_CTX), offsetof(struct gums_object, mem_ctx), 0, NULL, 0, gen_dump_TALLOC_CTX, gen_parse_TALLOC_CTX},
{"type", 0, sizeof(uint32), offsetof(struct gums_object, type), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"version", 0, sizeof(uint32), offsetof(struct gums_object, version), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"seq_num", 0, sizeof(uint32), offsetof(struct gums_object, seq_num), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"sec_desc", 1, sizeof(SEC_DESC), offsetof(struct gums_object, sec_desc), 0, NULL, 0, gen_dump_SEC_DESC, gen_parse_SEC_DESC},
{"sid", 1, sizeof(DOM_SID), offsetof(struct gums_object, sid), 0, NULL, 0, gen_dump_DOM_SID, gen_parse_DOM_SID},
{"name", 1, sizeof(char), offsetof(struct gums_object, name), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"description", 1, sizeof(char), offsetof(struct gums_object, description), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"user", 1, sizeof(struct gums_user), offsetof(struct gums_object, user), 0, NULL, 0, gen_dump_struct_gums_user, gen_parse_struct_gums_user},
{"group", 1, sizeof(struct gums_group), offsetof(struct gums_object, group), 0, NULL, 0, gen_dump_struct_gums_group, gen_parse_struct_gums_group},
{"domain", 1, sizeof(struct gums_domain), offsetof(struct gums_object, domain), 0, NULL, 0, gen_dump_struct_gums_domain, gen_parse_struct_gums_domain},
{NULL, 0, 0, 0, 0, NULL, 0, NULL, NULL}};

int gen_dump_struct_gums_object(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent) {
	return gen_dump_struct(mem_ctx, pinfo_gums_object, p, ptr, indent);
}
int gen_parse_struct_gums_object(TALLOC_CTX *mem_ctx, char *ptr, const char *str) {
	return gen_parse_struct(mem_ctx, pinfo_gums_object, ptr, str);
}

int gen_dump_struct_gums_privilege(TALLOC_CTX *mem_ctx, struct parse_string *, const char *, unsigned);
int gen_parse_struct_gums_privilege(TALLOC_CTX *mem_ctx, char *, const char *);
static const struct parse_struct pinfo_gums_privilege[] = {
{"mem_ctx", 1, sizeof(TALLOC_CTX), offsetof(struct gums_privilege, mem_ctx), 0, NULL, 0, gen_dump_TALLOC_CTX, gen_parse_TALLOC_CTX},
{"version", 0, sizeof(uint32), offsetof(struct gums_privilege, version), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"seq_num", 0, sizeof(uint32), offsetof(struct gums_privilege, seq_num), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"name", 1, sizeof(char), offsetof(struct gums_privilege, name), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"description", 1, sizeof(char), offsetof(struct gums_privilege, description), 0, NULL, FLAG_NULLTERM, gen_dump_char, gen_parse_char},
{"privilege", 1, sizeof(LUID_ATTR), offsetof(struct gums_privilege, privilege), 0, NULL, 0, gen_dump_LUID_ATTR, gen_parse_LUID_ATTR},
{"count", 0, sizeof(uint32), offsetof(struct gums_privilege, count), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"members", 1, sizeof(DOM_SID), offsetof(struct gums_privilege, members), 0, "count", 0, gen_dump_DOM_SID, gen_parse_DOM_SID},
{NULL, 0, 0, 0, 0, NULL, 0, NULL, NULL}};

int gen_dump_struct_gums_privilege(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent) {
	return gen_dump_struct(mem_ctx, pinfo_gums_privilege, p, ptr, indent);
}
int gen_parse_struct_gums_privilege(TALLOC_CTX *mem_ctx, char *ptr, const char *str) {
	return gen_parse_struct(mem_ctx, pinfo_gums_privilege, ptr, str);
}

