


#define SECRETS_MACHINE_ACCT_PASS "SECRETS/$MACHINE.ACC"
#define SECRETS_DOMAIN_SID    "SECRETS/SID"
#define SECRETS_SAM_SID       "SAM/SID"

struct machine_acct_pass {
	uint8 hash[16];
	time_t mod_time;
};

