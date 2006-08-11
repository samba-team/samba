/*
 This file contains the reference implementation of SHA-1
 from http://www.ietf.org/rfc/rfc3174.txt
*/
/*
 *  sha1test.c
 *
 *  Description:
 *      This file will exercise the SHA-1 code performing the three
 *      tests documented in FIPS PUB 180-1 plus one which calls
 *      SHA1Input with an exact multiple of 512 bits, plus a few
 *      error test checks.
 *
 *  Portability Issues:
 *      None.
 *
 */

#include "includes.h"

#include "lib/crypto/crypto.h"

struct torture_context;

/*
 *  Define patterns for testing
 */
#define TEST1   "abc"
#define TEST2a  "abcdbcdecdefdefgefghfghighijhi"
#define TEST2b  "jkijkljklmklmnlmnomnopnopq"
#define TEST2   TEST2a TEST2b
#define TEST3   "a"
#define TEST4a  "01234567012345670123456701234567"
#define TEST4b  "01234567012345670123456701234567"
    /* an exact multiple of 512 bits */
#define TEST4   TEST4a TEST4b
static const char *testarray[4] =
{
    TEST1,
    TEST2,
    TEST3,
    TEST4
};
static int repeatcount[4] = { 1, 1, 1000000, 10 };
static const char *resultarray[4] =
{
    "A9 99 3E 36 47 06 81 6A BA 3E 25 71 78 50 C2 6C 9C D0 D8 9D ",
    "84 98 3E 44 1C 3B D2 6E BA AE 4A A1 F9 51 29 E5 E5 46 70 F1 ",
    "34 AA 97 3C D4 C4 DA A4 F6 1E EB 2B DB AD 27 31 65 34 01 6F ",
    "DE A3 56 A2 CD DD 90 C7 A7 EC ED C5 EB B5 63 93 4F 46 04 52 "
};

BOOL torture_local_crypto_sha1(struct torture_context *torture) 
{
    struct SHA1Context sha;
    int i, j, err;
    uint8_t Message_Digest[20];
    BOOL ret = True;
    char tmp[60 + 10];

    /*
     *  Perform SHA-1 tests
     */
    for(j = 0; j < 4; ++j)
    {
    	ZERO_STRUCT(tmp);
        printf( "\nTest %d: %d, '%s'\n",
                j+1,
                repeatcount[j],
                testarray[j]);

        err = SHA1Init(&sha);
        if (err)
        {
            fprintf(stderr, "SHA1Init Error %d.\n", err );
	    ret = False;
            break;    /* out of for j loop */
        }

        for(i = 0; i < repeatcount[j]; ++i)
        {
            err = SHA1Update(&sha,
                  (const unsigned char *) testarray[j],
                  strlen(testarray[j]));
            if (err)
            {
                fprintf(stderr, "SHA1Update Error %d.\n", err );
		ret = False;
                break;    /* out of for i loop */
            }
        }

        err = SHA1Final(Message_Digest, &sha);
        if (err)
        {
            fprintf(stderr,
            "SHA1Result Error %d, could not compute message digest.\n",
            err );
	    ret = False;
        }
        else
        {
            printf("\t");
            for(i = 0; i < 20 ; ++i)
            {
	    	snprintf(tmp+(i*3), sizeof(tmp) - (i*3),"%02X ", Message_Digest[i]);
                printf("%02X ", Message_Digest[i]);
            }
            printf("\n");
        }
        printf("Should match:\n");
        printf("\t%s\n", resultarray[j]);
	if (strcmp(resultarray[j], tmp) != 0) {
	    ret = False;	
	}
    }

    /* Test some error returns */
    err = SHA1Update(&sha,(const unsigned char *) testarray[1], 1);
    if (err != shaStateError) ret = False;
    printf ("\nError %d. Should be %d.\n", err, shaStateError );
    err = SHA1Init(0);
    if (err != shaNull) ret = False;
    printf ("\nError %d. Should be %d.\n", err, shaNull );
    return ret;
}
