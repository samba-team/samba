/*
	This code is based on work from 
	L0phtcrack 1.5 06.02.97 mudge@l0pht.com

	The code also contains sources from:
                . routines from the samba code source
		  md4.c smbdes.c

	Anton Roeckseisen (anton@genua.de)

*/

/*
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "mkntpwd.h"

void str_to_key(unsigned char *,unsigned char *);
void usage(char *);
int PutUniCode(char *dst,char *src);
void printlanhash(char *tmp);
void mdfour(unsigned char *out, unsigned char *in, int n);
void E_P16(unsigned char *p14,unsigned char *p16);


void main(int argc, char **argv) {
	extern char *optarg;
	int c;

	int printlan = 0;
	char lanpwd[LMPASSWDLEN+1];
	int printnt = 0;
	char inputfile[FILENAMEBUFFER+1] = "";
	FILE* InputFilePtr;
	int just_pwd = 0;
	int i;
	char hashout[17];

	char ntpasswd[NTPASSWDLEN+1]; 
	char *hold;
	unsigned char *p16;
	int uni_len;
	char passwd[NTPASSWDLEN+1];

	if (argc==1)
		usage(argv[0]);

	if (argc==2)
		just_pwd=1;
	else
		just_pwd=0;

	lanpwd[0] = '\0';
	ntpasswd[0] = '\0';

	while ( (c = getopt(argc, argv, "L:N:f:")) != EOF){
		switch(c) {
		case 'L':
			printlan++;
			strncpy(lanpwd,optarg,LMPASSWDLEN);
			lanpwd[LMPASSWDLEN]='\0';
			for (i=0;i<LMPASSWDLEN;i++)
				lanpwd[i]=toupper(lanpwd[i]);
			break;
		case 'N':
			printnt++;
			strncpy(passwd,optarg,NTPASSWDLEN);
			passwd[NTPASSWDLEN]='\0';
			break;
		case 'f': 
			strncpy(inputfile,optarg,FILENAMEBUFFER);
			inputfile[FILENAMEBUFFER]='\0';
			break;
		default:
			usage(argv[0]);
		}
	}

	/* Get password from file or STDIN */
	if (inputfile[0]!='\0') {

		just_pwd=0; /* make sure no shit is happening... */

		/* get NT-password (longer) */
		if (strcmp(inputfile,"-")==0) {
			fgets(passwd,NTPASSWDLEN,stdin);
		} else {
			if ((InputFilePtr=fopen(inputfile,"r")) == NULL)
				fprintf(stderr,"Couldn't open passwordfile: %s",inputfile) ;
			fgets(passwd,NTPASSWDLEN,InputFilePtr);
			fclose(InputFilePtr);
		}
		while (strlen(passwd)>0 && passwd[strlen(passwd)-1]=='\n')
			passwd[strlen(passwd)-1]='\0';

		/* create LANMAN-password (shorter) */
		strncpy(lanpwd,passwd,LMPASSWDLEN);
		lanpwd[LMPASSWDLEN]='\0';
		for (i=0;i<LMPASSWDLEN;i++)
			lanpwd[i]=toupper(lanpwd[i]);
		printlan++;
		printnt++;

	}


	/* Assume the one and only Arg is the new password! */

	if (argc>1 && just_pwd==1) { 
                strncpy(lanpwd,argv[1],LMPASSWDLEN);
		lanpwd[LMPASSWDLEN]='\0';
		for (i=0;i<LMPASSWDLEN;i++)
			lanpwd[i]=toupper(lanpwd[i]);
		printlan++;

		strncpy(passwd,argv[1],NTPASSWDLEN);
		passwd[NTPASSWDLEN]='\0';
		printnt++;
	}

	if (printlan >0) {
		memset(hashout,'\0',17);
		E_P16((uchar *)lanpwd,hashout);
		printlanhash(hashout);
	}

	if (printnt >0) {

		if (printlan>0) printf(":");

		memset(ntpasswd, '\0', sizeof(ntpasswd));

		if (passwd[strlen(passwd)-1] == '\n') /* strip the \n - this 
					is done in LowerString for the case sensitive
					check */
		passwd[strlen(passwd)-1] = '\0';

		hold = (char *)malloc(NTPASSWDLEN * 2); /* grab space for 
						       unicode */
		if (hold == NULL){
			fprintf(stderr, "out of memory...crackntdialog hold\n");
			exit(1);
		}

		uni_len = PutUniCode(hold, passwd); /* convert to 
						   unicode and return correct 
						   unicode length for md4 */

		p16 = (unsigned char*)malloc(17); /* grab space for md4 hash */
		if (p16 == NULL){
		      fprintf(stderr, "out of memory...crackntdialect p16\n");
		      exit(1);
		}
		
		memset(p16,'\0',17);
		mdfour(p16,hold, uni_len);

		printlanhash(p16);
		    
		free(p16);
		free(hold);
	}

	printf("\n");

	exit(0);

}

/*****************************************************************************/
/*****************************************************************************/
/*****************************************************************************/

void usage(char *progname){
   char *p;

   p = strrchr(progname, '\\');
   if (p == NULL)
        p = progname;
   else
        p++;

   fprintf(stderr, "Usage: %s [-L lanmgrpwd] [-N ntpasswd]\n",p);
   fprintf(stderr, "       %s password\n",p);
   fprintf(stderr, "       %s -f [-] [filename]\n\n",p);
   fprintf(stderr, "     -L lanmgrpasswd  LanManager cleartextpwd <= 14 chars\n");
   fprintf(stderr, "     -N ntpasswd      NT cleartextpwd <=128 chars (usually <=14)\n\n");
   fprintf(stderr, "     with both options present the encrypted LanManager-Pwd is \n");
   fprintf(stderr, "     printed first, followed by a ':' and the encrypted NT-Pwd.\n\n");
   fprintf(stderr, "     The second usage behaves like %s -L pwd -N pwd\n\n",p);
   fprintf(stderr, "     The third usage reads the password from STDIN or a File. Printout\n");
   fprintf(stderr, "     is the same as second.\n\n");
   fprintf(stderr, "anton@genua.de\n\n");
   exit(1);
}


/*******************************************************************
write a string in unicoode format
********************************************************************/
int PutUniCode(char *dst,char *src) 
{                       
  int ret = 0;  
  while (*src) {
    dst[ret++] = src[0];
    dst[ret++] = 0;
    src++;
  }
  dst[ret++]=0; 
  dst[ret++]=0; 
  return(ret-2); /* the way they do the md4 hash they don't represent
                    the last null. ie 'A' becomes just 0x41 0x00 - not
                    0x41 0x00 0x00 0x00 */
}

/*
  print binary buffer as hex-string
*/
void printlanhash(char *tmp) {

	int i;
	unsigned char c;
	char outbuffer[33];


	/* build string from binary hash */
	for(i=0;i<16;i++) {
		c=tmp[i];
		sprintf(outbuffer+2*i,"%x",(c>>4) & 0x0f);
		sprintf(outbuffer+2*i+1,"%x",c & 0x0f);
	}

	/* convert to uppercase */
	for(i=0;i<32;i++)
		outbuffer[i] = toupper(outbuffer[i]);
	outbuffer[32]='\0';

	/* print out hex-string */
	printf("%s",outbuffer);
}


