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
#include "torture/ui.h"

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


bool torture_local_crypto_sha1(struct torture_context *tctx)
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
        torture_comment(tctx, "Test %d: %d, '%s'\n",
                j+1,
                repeatcount[j],
                testarray[j]);

        err = SHA1Init(&sha);
        torture_assert_int_equal(tctx, err, 0, "SHA1Init Error");

        for(i = 0; i < repeatcount[j]; ++i)
        {
            err = SHA1Update(&sha,
                  (const unsigned char *) testarray[j],
                  strlen(testarray[j]));
			torture_assert_int_equal(tctx, err, 0, "SHA1Update Error");
        }

        err = SHA1Final(Message_Digest, &sha);
		torture_assert_int_equal(tctx, err, 0, 
            "SHA1Result Error, could not compute message digest.");
        torture_comment(tctx, "\t");
        for(i = 0; i < 20 ; ++i)
        {
	    	snprintf(tmp+(i*3), sizeof(tmp) - (i*3),"%02X ", Message_Digest[i]);
            torture_comment(tctx, "%02X ", Message_Digest[i]);
        }
        torture_comment(tctx, "\n");
        torture_comment(tctx, "Should match:\n\t%s\n", resultarray[j]);
	if (strcmp(resultarray[j], tmp) != 0) {
	    ret = False;	
	}
    }

    /* Test some error returns */
    err = SHA1Update(&sha,(const unsigned char *) testarray[1], 1);
    torture_assert_int_equal(tctx, err, shaStateError, "SHA1Update failed");
    err = SHA1Init(0);
    torture_assert_int_equal(tctx, err, shaNull, "SHA1Init failed");

	return true;
}


