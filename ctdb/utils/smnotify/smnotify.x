
const SM_MAXSTRLEN = 1024;

struct status {
	string mon_name<SM_MAXSTRLEN>;
	int state;
};


program SMNOTIFY {
	version SMVERSION {
		void SM_NOTIFY(struct status) = 6;
	} = 1;	
} = 100024;


