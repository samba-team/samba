
enum form_code { form_code_N, form_code_T, form_code_C };
enum type_code { type_code_A, type_code_E, type_code_I, type_code_L };
enum structure_code { structure_code_F, structure_code_R, structure_code_P };
enum mode_code { mode_code_S, mode_code_B, mode_code_C };

enum prot_code { prot_code_C, prot_code_S, prot_code_E, prot_code_P };

struct ftp_commands{
  char *name;
  int (*user)(char *username);
  int (*pass)(char *password);
  int (*acct)(char *account);
  int (*cwd)(char *pathname);
  
  int (*auth)(char *mechanism_name);
  int (*adat)(char *base64data);
  int (*pbsz)(int buffer_size);
  int (*prot)(int protection_code);
  int (*ccc)(void);
  int (*mic)(char *command);
  int (*conf)(char *command);
  int (*enc)(char *command);

  int (*cdup)(void);
  int (*smnt)(char *pathname);
  int (*quit)(void);
  int (*rein)(void);
  int (*port)(char *host_port);
  int (*pasv)(void);
  int (*type)(int type_code, int form_code);
  int (*stru)(int structure_code);
  int (*mode)(int mode_code);
  int (*retr)(char *pathname);
  int (*stor)(char *pathname);
  int (*stou)(void);
  int (*appe)(char *pathname);
  int (*allo)(int decimal_integer, char r, int decimal_integer);
  int (*rest)(char *marker);
  int (*rnfr)(char *pathname);
  int (*rnto)(char *pathname);
  int (*abor)(void);
  int (*dele)(char *pathname);
  int (*rmd)(char *pathname);
  int (*mkd)(char *pathname);
  int (*pwd)(void);
  int (*list)(char *pathname);
  int (*nlst)(char *pathname);
  int (*site)(char *string);
  int (*syst)(void);
  int (*stat)(char *pathname);
  int (*help)(char *string);
  int (*noop)(void);

  int (*reply)(int code, char *msg);
  int (*lreply)(int code, char *msg);
};


struct ftp_commands commands [] = {
  {
    "noauth",

    user, pass, acct, cwd,  

    NULL, /* AUTH */
    NULL, /* ADAT */
    NULL, /* PBSZ */
    NULL, /* PROT */
    NULL, /* CCC */
    NULL, /* MIC */
    NULL, /* CONF */
    NULL, /* ENC */

    cdup, smnt, quit, rein, port, pasv, type, stru, mode, retr, stor,
    stou, appe, allo, rest, rnfr, rnto, abor, dele, rmd, mkd, pwd, list,
    nlst, site, syst, stat, help, noop,

    reply, lreply
  }
  {
    "KERBEROS_V4",

    krb4_user, krb4_pass, krb4_acct, NULL, krb4_auth, krb4_adat, 
};


            <username> ::= <string>
            <password> ::= <string>
            <account-information> ::= <string>
            <string> ::= <char> | <char><string>
            <char> ::= any of the 128 ASCII characters except <CR> and
            <LF>
            <marker> ::= <pr-string>
            <pr-string> ::= <pr-char> | <pr-char><pr-string>
            <pr-char> ::= printable characters, any
                          ASCII code 33 through 126
            <byte-size> ::= <number>
            <host-port> ::= <host-number>,<port-number>
            <host-number> ::= <number>,<number>,<number>,<number>
            <port-number> ::= <number>,<number>
            <number> ::= any decimal integer 1 through 255
            <form-code> ::= N | T | C
            <type-code> ::= A [<sp> <form-code>]
                          | E [<sp> <form-code>]
                          | I
                          | L <sp> <byte-size>
            <structure-code> ::= F | R | P
            <mode-code> ::= S | B | C
            <pathname> ::= <string>
            <decimal-integer> ::= any decimal integer




