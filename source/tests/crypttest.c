#include <unistd.h>
#include <sys/types.h>

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

main()
{
	char passwd[9];
	char salt[9];
	char c_out1[256];
	char c_out2[256];

	strcpy(passwd, "12345678");
	strcpy(salt, "12345678");

	strcpy(c_out1, crypt(passwd, salt));

	salt[2] = '\0';
	strcpy(c_out2, crypt(passwd, salt));

	exit(strcmp(c_out1, c_out2) == 0 ? 0 : 1);
}
