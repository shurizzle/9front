typedef struct Wkey Wkey;
typedef struct Wnode Wnode;
typedef struct Wifi Wifi;
typedef struct Wifipkt Wifipkt;

enum {
	Essidlen = 32,
};

/* cipher */
enum {
	TKIP	= 1,
	CCMP	= 2,
};

struct Wkey
{
	int		cipher;
	int		len;
	uvlong		tsc;
	uchar		key[];
};

struct Wnode
{
	uchar	bssid[Eaddrlen];
	char	ssid[Essidlen+2];

	char	*status;

	int	rsnelen;
	uchar	rsne[258];
	Wkey	*txkey[1];
	Wkey	*rxkey[5];

	int	aid;		/* association id */
	ulong	lastsend;
	ulong	lastseen;

	uchar	*minrate;	/* pointers into wifi->rates */
	uchar	*maxrate;
	uchar	*actrate;

	ulong	validrates;	/* bitmap on wifi->rates */
	ulong	basicrates;

	ulong	txcount;	/* statistics for rate adaption */
	ulong	txerror;

	/* stuff from beacon */
	uvlong	rs;
	uvlong	ts;
	uchar	dtimcount;
	uchar	dtimperiod;
	int	ival;
	int	cap;
	int	channel;
	int	brsnelen;
	uchar	brsne[258];

	/* HT (802.11n) */
	uchar	htcap[26];	/* HT Capabilities IE body */
	int	htcapvalid;
	uchar	mcsvalid[13];	/* bitmap MCS 0-76 */
	uchar	mcsbasic[13];
	int	mcsact;		/* current MCS index (-1 = legacy) */
	int	mcsmin;
	int	mcsmax;
	int	htchanwidth;	/* 0=20MHz, 1=40MHz */
	int	htextchan;	/* 0=none, 1=above, 3=below */
	int	htsgi;		/* short guard interval supported */
	ulong	mcstxcount;
	ulong	mcstxerror;
};

struct Wifi
{
	Ether	*ether;

	int	debug;

	RWLock	crypt;
	Queue	*iq;
	ulong	watchdog;
	ulong	lastauth;
	Ref	txseq;
	void	(*transmit)(Wifi*, Wnode*, Block*);

	/* for searching */
	uchar	bssid[Eaddrlen];
	char	essid[Essidlen+2];

	/* supported data rates by hardware */
	uchar	*rates;

	/* HT (802.11n) driver capabilities */
	uchar	htcap[26];	/* HT Capabilities IE to advertise */
	int	htcapvalid;

	/* effective base station */
	Wnode	*bss;

	Wnode	node[32];
};

struct Wifipkt
{
	uchar	fc[2];
	uchar	dur[2];
	uchar	a1[Eaddrlen];
	uchar	a2[Eaddrlen];
	uchar	a3[Eaddrlen];
	uchar	seq[2];
	uchar	a4[Eaddrlen];
};

enum {
	Btimestamp = 1<<15,
};

Wifi *wifiattach(Ether *ether, void (*transmit)(Wifi*, Wnode*, Block*));
void wifiiq(Wifi*, Block*);
int wifihdrlen(Wifipkt*);
void wifitxfail(Wifi*, Block*);

char *wifistat(Wifi*, char*, char*);
long wifictl(Wifi*, void*, long);
void wificfg(Wifi*, char*);
