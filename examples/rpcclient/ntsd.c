/* This is an experiemental programme to shutdown a  group of NTws in a 
   Samba domain via rpcclient.

   Copyright (c) David Bannon 1999
   David Bannon, D.Bannon@latrobe.edu.au, 4th November, 1999 

   Full permission is granted to use this code (for what that is worth) in
   any way you wish, strictly at your own risk.

   I use it from a cron a job to close a computer lab down at 5:00 pm.
 
   It has some serious security implications, make sure you understand 
   them before using this code !

   If you find a way to make this 'power down' a machine that is set up to 
   do power down correctly please let me know !!   

    Machines to be shutdown must be members of a samba (or NT) domain.
    You are going to have to offer your domain admin user name/password
    (see below).

    As you probably don't want your domain admin password appearing in the 
    crontab file or popping up in a 'ps' list, it can be encrypted and the 
    programme will tell you what it should look like. i.e :

        [root@bclab shutdown]# ./ntsd -e
        Domain Admin User name :dbannon
        Domain Admin Password
        Use the string between [] after a -p : [1HCeTcXqOfo7R[hg]
        [root@bclab shutdown]#

    Now a crontab entry would look like this :

        00 17 * * 1-5 /usr/local/sbin/ntsd -p'1HCeTcXqOfo7R[hg' -a

        The -p indicates passwd (actually user name and password) and the
        -a says shutdown all machines. Note that the password string must
        have inverted commas around it so the shell does not try and expand
        any special charachers that it is likely to contain.
        
    Security Alert !!
        The encryption is pretty weak and its reversable ! Change the key
        strings, compile and change the key strings again ! You don't need
        to remember the key but if you leave the unchanged source around 
        someone may use it to reverse the encryption. The Keys are in lumps
        to stop someone doing a 'cat ntsd' and seeing the key string. 
	   (yeah, I know its not very clever, but they should not be able to
	    read the binary or your crontab anyway) 

    Ping
        I ping the target machines before trying to shut them down, you
        dont't need to, just let rpcclient time out. If you want to ping
        first (because its nicer !) you need :
        1. First element of IP name should be the netbios name. (makes sense)
        2. If the server you will run the cron job from does not have the
           same default domain name as machines being shutdown then you will
           need to define USE_DOMAIN and put in appropriate ip domain info.
        This code does ping, get busy with vi if you don't want to.

    Machine Names
        For this system to be practical, the machine names must be in some 
        sort of sequence, ie bclab1, bclab2, bclab3, not more creative like
        grumpy, dopey, sneezy. See the code in main() to see how the names
        are built.

    Configuration

      Machine Names
        If you have used a naming scheme like mine then you may need to 
        change only LASTMACHINE and PREFIX, otherwise look at main(). 

      Binary locations.
        We need to find the rpcclient and ping binaries. The values below
        are typical. Better check first. 

      Compile
        Known to compile cleanly on linux (RH5.0 - RH6.1) and DEC 4.0. Does
        not do anything fancy so should compile on most systems easily 
        enough.

      Install
        Rename the binary (ie ntsd) and put it somewhere safe. It should 
        be rwx root only. Comes up with basic help if run without command
        line switch, prompts for admin user name and password if used 
        without the -p switch.
        (Typically)Put entry in your crontab (crontab -e) and watch the
        fun. Remember, it does not keep them shutdown, try an entry every
        5 minutes for a while (or until door is locked).
*/
                 

#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<pwd.h>

#define PING "/bin/ping"
#define RPCCLIENT "/usr/local/samba/bin/rpcclient" 


#define LASTMACHINE 14               /* ie, scans bclab1 through to bclab14 */
#define PREFIX "bclab"

/*    #define USE_DOMAIN    Only if you need full ip name to ping machines */

#ifdef USE_DOMAIN
#define DOMAIN ".biochem.latrobe.edu.au"     /* required by ping, possibly.
 */
#endif

#define KEY1 "Please"
#define KEY2 "don't leave"
#define KEY3 "this"
#define KEY4 "as it is"
#define KEY5 "here"
#define KEY6 "silly."


int Shutdown(char *machine, char *PassWord) {
    char Buff[128], *Ptr;
    int Res;
    /* printf("Shutting down %s\n", machine); */
    sprintf(Buff, "/bin/ping -c 1 -q %s > /dev/null", machine);
    Res = system(Buff);
    if (Res == 0) {             /* its turned on */
        Ptr = machine;
         /* first 'word' in ip name = netbios name, get rid of rest */
        while (*++Ptr != 0) if (*Ptr == '.') *Ptr = 0; 
        printf("Shutting down %s\n", machine); 
        sprintf(Buff, "%s -c shutdown -U%s -S %s", RPCCLIENT, PassWord,
machine);
        system(Buff);
    }   
}

int Usage(char *prog) {
    printf("Programme to shutdown NTs in domain.\n");
    printf("Normally called from cron (using encrypted passwd, see -e and
-p).\n");
    printf("Usage    \n");
    printf("    -a             shutdown all machines %s1 to %s%d. \n", 
                                                PREFIX, PREFIX, LASTMACHINE);
    printf("    -m machine     shutdown [machine] (might need full ip
name).\n");
    printf("    -e             tell me my encrypted name and password to
use with -p.\n");
    printf("    -p'pw_string'  use encrypted name & password as given by
-e.\n");
    printf("                   You must have single inverted commas around
the pw string !");
    printf("    -h             help, give this message.\n");
    printf("Typical cron line :  00 17 * * 1-5 /usr/local/sbin/ntsd
-p1HCeTcXqOfo7R[hg -a\n");
    printf("                                                  David Bannon,
Nov 1999\n");
    exit(0);
}	

int GetPassWord(char *Passwd) {
    char *ptr, *p;
    char User[128];
    printf("Domain Admin User name :");
    fgets(User, 127, stdin);
    if (strlen(User) < 3) {
        printf("Short user name, exiting.\n");
        exit(1);
    }
    p = User;
    while (*p != '\n') p++;     /* get rid of newline */
    *p = 0;
    ptr = getpass("Domain Admin Password ");
    if (strlen(ptr) < 3) {
        printf("Short password, exiting.\n");
        exit(1);
    }
    strcpy(Passwd, User);       /* do this with sprintf */
    strcat(Passwd, "%");
    strcat(Passwd, ptr);
    *ptr = 0;                   /* clean up system buffer */
    return 0;
}

int Encrypt(char *InPass) {
    char Pass[128], Enc[128];
    int Temp;
    char *Hash;
    int Offset = 0;
    Hash = malloc(256);
                        /* so it a bit harder than just 'cat ntsd'  */
    sprintf(Hash, "%s%s%s%s%s%s", KEY4, KEY3, KEY2, KEY5, KEY1, KEY6);
    if (InPass == 0) {
        GetPassWord(Pass);          /* may not return */
        while (*(Pass + Offset) != 0) {
            Temp = *(Pass + Offset) + *(Hash + Offset) - ' ';
            if (Temp > '~') Temp = Temp - 95;
            *(Pass+Offset++) = Temp;
        }
        printf("Use the string between [] after a -p : ['%s']\n", Pass);
        exit(0);
    } else {
        while (*(InPass + Offset) != 0) {
            Temp = *(InPass + Offset) - *(Hash + Offset) + ' ';
            if (Temp < ' ') Temp = Temp + 95;
            *(InPass+Offset++) = Temp;
        }
    }
    free(Hash);
    return 0;
}

int main(int argc, char **argv) {
  	extern char *optarg;
  	extern int optind;
	int Ch;
    static char *prog_name;
    int MachineNo = 0, AllMachines = 0;
    char Machine[128], PassWord[128];
    uid_t UID = getuid();
    prog_name = argv[0];
    if (UID != 0) {
        printf("Sorry, this programme can only be run as root.\n");
        exit(1);
    }
    *Machine = 0;
    *PassWord = 0;
    if (argc < 2) Usage(prog_name);
    while ((Ch = getopt(argc, argv, "haem:p:")) != EOF) {
    	switch(Ch) {
    		case 'e': Encrypt(NULL); break;             /* Does not return */
  		    case 'a': AllMachines = 1; break;
   		    case 'm': strcpy(Machine, optarg); break;
		    case 'p': strcpy(PassWord, optarg); break;
		    case 'h': Usage(prog_name); 
		    default: Usage(prog_name);
		}
    }
    if (*PassWord == 0) GetPassWord(PassWord);      /* may not return */
    else Encrypt(PassWord);
    if (*Machine != 0) {
        Shutdown(Machine, PassWord);
        exit(0);
    }
 /* printf("exit for safety = %s.\n", PassWord);
exit(0);  */
    while (++MachineNo < LASTMACHINE+1) {
        pid_t Proc;
#ifdef USE_DOMAIN
        sprintf(Machine, "%s%d%s", PREFIX, MachineNo, DOMAIN);
#else
        sprintf(Machine, "%s%d", PREFIX, MachineNo);
#endif
        Proc = fork();
        if (Proc == 0) {    /* in child process */
            Shutdown(Machine, PassWord);
            exit(0);
        }
    }
    printf("Shutdowns initiated.\n");
}
