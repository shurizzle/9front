/*
 * tls13.c — TLS 1.3 client handshake (X25519 + AES-128-GCM / ChaCha20-Poly1305)
 *
 * Compile: 6c -o tls13.6 tls13.c && 6l -o tls13 tls13.6
 * Usage:   tls13 [-d] [-k] proto!host!port
 */
#include <u.h>
#include <libc.h>
#include <mp.h>
#include <libsec.h>

enum {
	TLS12Version		= 0x0303,
	TLS13Version		= 0x0304,
	MaxRecLen		= 16384,
	RecHdrLen		= 5,
	SHA256dlen		= SHA2_256dlen,

	RTChangeCipherSpec	= 20,
	RTAlert			= 21,
	RTHandshake		= 22,
	RTAppdata		= 23,

	HTClientHello		= 1,
	HTServerHello		= 2,
	HTEncryptedExtensions	= 8,
	HTCertificate		= 11,
	HTCertificateVerify	= 15,
	HTFinished		= 20,
	HTMessageHash		= 254,

	TLS13_AES_128_GCM	= 0x1301,
	TLS13_CHACHA20_POLY1305	= 0x1303,

	SigRsaPssSha256		= 0x0804,
	SigEcdsaSecp256r1Sha256	= 0x0403,

	ExtServerName		= 0x0000,
	ExtSupportedVersions	= 43,
	ExtKeyShare		= 51,
	ExtSigAlgs		= 13,
	ExtSupportedGroups	= 0x000a,
	ExtCookie		= 44,

	GroupX25519		= 0x001d,
	GroupSecp256r1		= 0x0017,
	GroupSecp384r1		= 0x0018,
};

enum {	/* key sizes (bytes) */
	X25519Pub	= 32,
	X25519Priv	= 32,
	X25519Sec	= 32,
	X25519KeyShare	= 36,	/* group(2) + keylen(2) + 32 */
	P256Pub		= 65,	/* uncompressed: 0x04 || x || y */
	P256Coord	= 32,
	P256KeyShare	= 69,	/* group(2) + keylen(2) + 65 */
	P384Pub		= 97,	/* uncompressed: 0x04 || x(48) || y(48) */
	P384Coord	= 48,
	P384KeyShare	= 101,	/* group(2) + keylen(2) + 97 */
	MaxKeyShare	= 101,	/* max key share size */
};

static uchar hrrRandom[32] = {	/* RFC 8446 §4.1.3, SHA256("HelloRetryRequest") */
	0xCF,0x21,0xAD,0x74,0xE5,0x9A,0x61,0x11,
	0xBE,0x1D,0x8C,0x02,0x1E,0x65,0xB8,0x91,
	0xC2,0xA2,0x11,0x16,0x7A,0xBB,0x8C,0x5E,
	0x07,0x9E,0x09,0xE2,0xC8,0xA8,0x33,0x9C,
};

typedef struct Tls13Keys Tls13Keys;
struct Tls13Keys {
	int	cipher;
	uchar	clientKey[32];
	uchar	serverKey[32];
	uchar	clientIV[12];
	uchar	serverIV[12];
	int	keyLen;
	int	ivLen;
	uchar	*serverCert;
	int	serverCertLen;
};

static void put2(uchar *p, int x) { p[0]=x>>8; p[1]=x; }
static void put3(uchar *p, int x) { p[0]=x>>16; p[1]=x>>8; p[2]=x; }
static int get2(uchar *p) { return (p[0]<<8)|p[1]; }
static int get3(uchar *p) { return (p[0]<<16)|(p[1]<<8)|p[2]; }

static int
readN(int fd, uchar *buf, int n)
{
	int tot, r;
	for(tot = 0; tot < n; tot += r){
		r = read(fd, buf+tot, n-tot);
		if(r <= 0) return -1;
	}
	return 0;
}

static int
recvRecord(int fd, uchar *buf, int *typ)
{
	uchar hdr[RecHdrLen];
	int n;
	if(readN(fd, hdr, RecHdrLen) < 0) return -1;
	*typ = hdr[0];
	n = get2(hdr+3);
	if(n > MaxRecLen + 256) return -1;
	if(readN(fd, buf, n) < 0) return -1;
	buf[n] = 0;
	return n;
}

static int
sendRecord(int fd, int typ, uchar *data, int n)
{
	uchar hdr[RecHdrLen];
	hdr[0] = typ;
	put2(hdr+1, TLS12Version);
	put2(hdr+3, n);
	if(write(fd, hdr, RecHdrLen) < 0) return -1;
	if(write(fd, data, n) < 0) return -1;
	return n;
}

static int
recvHandshake(int fd, uchar *buf)
{
	int n, typ;
	for(;;){
		n = recvRecord(fd, buf, &typ);
		if(n < 0) return -1;
		if(typ == RTChangeCipherSpec) continue;
		if(typ == RTHandshake) return n;
		return -1;
	}
}

static void
mkNonce(uchar *baseIV, u64int seq, uchar *nonce, int ivLen)
{
	uchar seqb[12];
	int i;
	memset(seqb, 0, ivLen);
	seqb[ivLen-8] = seq>>56; seqb[ivLen-7] = seq>>48;
	seqb[ivLen-6] = seq>>40; seqb[ivLen-5] = seq>>32;
	seqb[ivLen-4] = seq>>24; seqb[ivLen-3] = seq>>16;
	seqb[ivLen-2] = seq>>8;  seqb[ivLen-1] = seq;
	for(i = 0; i < ivLen; i++) nonce[i] = baseIV[i] ^ seqb[i];
}

static void
packAAD(uchar *aad, int n)
{
	aad[0] = RTAppdata;
	put2(aad+1, TLS12Version);
	put2(aad+3, n);
}

static int
aesgcmProtect(uchar *key, int keyLen, uchar *baseIV,
	u64int *seq, uchar *data, int n)
{
	AESGCMstate as;
	uchar nonce[12], aad[5];
	int plen;

	plen = n + 1;
	mkNonce(baseIV, *seq, nonce, sizeof(nonce));
	packAAD(aad, plen + 16);
	setupAESGCMstate(&as, key, keyLen, nil, 0);
	aesgcm_setiv(&as, nonce, sizeof(nonce));
	aesgcm_encrypt(data, plen, aad, sizeof(aad), data+plen, &as);
	(*seq)++;
	return plen + 16;
}

static int
aesgcmUnprotect(uchar *key, int keyLen, uchar *baseIV,
	u64int *seq, uchar *buf, int n)
{
	AESGCMstate as;
	uchar nonce[12], aad[5];
	int plen;

	plen = n - 16;
	if(plen < 1) return -1;
	mkNonce(baseIV, *seq, nonce, sizeof(nonce));
	packAAD(aad, n);
	setupAESGCMstate(&as, key, keyLen, nil, 0);
	aesgcm_setiv(&as, nonce, sizeof(nonce));
	if(aesgcm_decrypt(buf, plen, aad, sizeof(aad), buf+plen, &as) < 0)
		return -1;
	(*seq)++;
	return plen;
}

static int
chachaProtect(uchar *key, int keyLen, uchar *baseIV,
	u64int *seq, uchar *data, int n)
{
	Chachastate cs;
	uchar nonce[12], aad[5];
	int plen, tagLen;

	tagLen = Poly1305dlen;
	plen = n + 1;
	mkNonce(baseIV, *seq, nonce, sizeof(nonce));
	packAAD(aad, plen + tagLen);
	memset(&cs, 0, sizeof(cs));
	setupChachastate(&cs, key, keyLen, baseIV, sizeof(nonce), 20);
	chacha_setiv(&cs, nonce);
	ccpoly_encrypt(data, plen, aad, sizeof(aad), data+plen, &cs);
	(*seq)++;
	return plen + tagLen;
}

static int
chachaUnprotect(uchar *key, int keyLen, uchar *baseIV,
	u64int *seq, uchar *buf, int n)
{
	Chachastate cs;
	uchar nonce[12], aad[5];
	int plen, tagLen;

	tagLen = Poly1305dlen;
	plen = n - tagLen;
	if(plen < 1) return -1;
	mkNonce(baseIV, *seq, nonce, sizeof(nonce));
	packAAD(aad, n);
	memset(&cs, 0, sizeof(cs));
	setupChachastate(&cs, key, keyLen, baseIV, sizeof(nonce), 20);
	chacha_setiv(&cs, nonce);
	if(ccpoly_decrypt(buf, plen, aad, sizeof(aad), buf+plen, &cs) < 0)
		return -1;
	(*seq)++;
	return plen;
}

static void
hkdfExpandLabel(uchar *secret, char *label, uchar *ctx, int ctxlen,
	uchar *out, int outlen,
	DigestState* (*h)(uchar*, ulong, uchar*, ulong, uchar*, DigestState*),
	int hlen)
{
	uchar info[512], *p;
	DigestState *ds;
	uchar cnt, tmp[32];
	int llen, off, ncopy;

	llen = strlen(label);
	p = info;
	put2(p, outlen); p += 2;
	*p++ = 6 + llen;
	memmove(p, "tls13 ", 6); p += 6;
	memmove(p, label, llen); p += llen;
	*p++ = ctxlen;
	if(ctxlen > 0 && ctx != nil)
		memmove(p, ctx, ctxlen);
	p += ctxlen;

	ds = nil;
	off = 0;
	for(cnt=1; off < outlen; cnt++){
		if(p - info > 0)
			ds = (*h)(info, p-info, secret, hlen, nil, ds);
		(*h)(&cnt, 1, secret, hlen, tmp, ds);
		ncopy = hlen;
		if(ncopy > outlen - off)
			ncopy = outlen - off;
		memmove(out+off, tmp, ncopy);
		off += ncopy;
		if(off >= outlen)
			break;
		ds = (*h)(tmp, hlen, secret, hlen, nil, nil);
	}
}

static char derlab[]	= "derived";
static char c2slab[]	= "c hs traffic";
static char s2clab[]	= "s hs traffic";
static char c2sapp[]	= "c ap traffic";
static char s2capp[]	= "s ap traffic";
static char keylab[]	= "key";
static char ivlab[]	= "iv";
static char finlab[]	= "finished";

static void
xthashClone(DigestState *ds, uchar *digest)
{
	DigestState copy;
	memmove(&copy, ds, sizeof(copy));
	copy.malloced = 0;
	sha2_256(nil, 0, digest, &copy);
}

static void
tls13ContextString(int isServer, uchar *buf, int *n)
{
	char *s;
	int l;
	s = isServer ? "TLS 1.3, server CertificateVerify"
	             : "TLS 1.3, client CertificateVerify";
	l = strlen(s);
	memset(buf, 0x20, 64);
	memmove(buf+64, s, l);
	buf[64+l] = 0;
	*n = 64 + l + 1;
}

static void
signedData(DigestState *transcript, int isServer, uchar *digest)
{
	uchar th[32];
	uchar ctx[128];
	int ctxLen;

	tls13ContextString(isServer, ctx, &ctxLen);
	xthashClone(transcript, th);
	memmove(ctx+ctxLen, th, SHA256dlen);
	sha2_256(ctx, ctxLen+SHA256dlen, digest, nil);
}

static void
mgf1(uchar *seed, int seedLen, uchar *out, int outLen)
{
	uchar buf[260];
	int hLen, c, off;

	hLen = SHA256dlen;
	memmove(buf, seed, seedLen);
	memset(buf+seedLen, 0, 4);
	off = 0;
	for(c = 0; off < outLen; c++){
		buf[seedLen+3] = c;
		sha2_256(buf, seedLen+4, out+off, nil);
		off += hLen;
	}
}

static char*
rsaPssVerify(uchar *sig, int sigLen, uchar *digest, int hashLen, RSApub *pk)
{
	mpint *m, *e;
	uchar *em, *db;
	int emLen, modBits, i, slen;

	modBits = mpsignif(pk->n);
	emLen = (modBits + 7) / 8;
	if(sigLen != emLen) return "signature length mismatch";

	em = malloc(emLen);
	if(em == nil) return "out of memory";
	m = betomp(sig, sigLen, nil);
	e = rsaencrypt(pk, m, nil);
	mptober(e, em, emLen);
	mpfree(m); mpfree(e);

	if(em[emLen-1] != 0xbc) goto Bad;

	{
		uchar *h, dbMask[256];
		h = em + emLen - hashLen - 1;
		mgf1(h, hashLen, dbMask, emLen - hashLen - 1);
		db = malloc(emLen - hashLen - 1);
		if(db == nil){ free(em); return "out of memory"; }
		for(i = 0; i < emLen - hashLen - 1; i++)
			db[i] = em[i] ^ dbMask[i];
		db[0] &= 0xff >> ((8*emLen - modBits + 1) & 7);
		if(db[0] != 0) goto Bad2;
		i = 1;
		while(i < emLen - hashLen - 1 && db[i] != 0x01) i++;
		if(i >= emLen - hashLen - 1) goto Bad2;
		i++;
		slen = emLen - hashLen - 1 - i;
		{
			uchar mhash[128], h2[32];
			uchar *mp = mhash;
			memset(mp, 0, 8); mp += 8;
			memmove(mp, digest, hashLen); mp += hashLen;
			memmove(mp, db+i, slen); mp += slen;
			sha2_256(mhash, mp-mhash, h2, nil);
			if(tsmemcmp(h2, h, hashLen) != 0) goto Bad2;
		}
		free(db); free(em);
		return nil;
	Bad2:
		free(db);
	}
Bad:
	free(em);
	return "rsa-pss verify failed";
}

static char*
verifyCertVerify(DigestState *transcript, int isServer,
	int sigalg, uchar *sig, int sigLen,
	uchar *cert, int certLen)
{
	uchar digest[SHA256dlen];
	signedData(transcript, isServer, digest);
	switch(sigalg){
	case SigEcdsaSecp256r1Sha256:
	{
		ECdomain dom;
		ECpub *ecpk;
		char *err;
		ecpk = X509toECpub(cert, certLen, nil, 0, &dom);
		if(ecpk == nil) return "bad ec certificate";
		err = X509ecdsaverifydigest(sig, sigLen, digest, SHA256dlen, &dom, ecpk);
		ecdomfree(&dom);
		ecpubfree(ecpk);
		return err;
	}
	case SigRsaPssSha256:
	{
		RSApub *rsapk;
		char *err;
		rsapk = X509toRSApub(cert, certLen, nil, 0);
		if(rsapk == nil) return "bad rsa certificate";
		err = rsaPssVerify(sig, sigLen, digest, SHA256dlen, rsapk);
		rsapubfree(rsapk);
		return err;
	}
	default:
		return "unsupported signature algorithm";
	}
}

static int
buildClientHello(uchar *buf, uchar *x25519pub, uchar *p256pub,
	uchar *p384pub, uchar *random, uchar *sid, int sidLen,
	char *sni, int isHRR, uchar *cookie, int cookieLen)
{
	uchar *p, *plen;
	int n, snilen, sharesLen;

	p = buf;
	*p++ = HTClientHello;
	plen = p;
	put3(p, 0); p += 3;
	put2(p, TLS12Version); p += 2;
	memmove(p, random, 32); p += 32;

	if(isHRR && sidLen > 0){
		*p++ = sidLen;
		memmove(p, sid, sidLen); p += sidLen;
	}else{
		*p++ = 32;
		genrandom(p, 32); p += 32;
	}

	put2(p, 4); p += 2;
	put2(p, TLS13_AES_128_GCM); p += 2;
	put2(p, TLS13_CHACHA20_POLY1305); p += 2;

	*p++ = 1;
	*p++ = 0;

	/* extensions — 2-byte length before first extension */
	{
		uchar *extl = p;
		put2(p, 0); p += 2;

		put2(p, ExtSupportedVersions); p += 2;
		put2(p, 3); p += 2;
		*p++ = 2;
		put2(p, TLS13Version); p += 2;

		put2(p, ExtSupportedGroups); p += 2;
		put2(p, 2 + 2+2+2); p += 2;
		put2(p, 2+2+2); p += 2;
		put2(p, GroupX25519); p += 2;
		put2(p, GroupSecp256r1); p += 2;
		put2(p, GroupSecp384r1); p += 2;

		if(isHRR && p384pub != nil){
			sharesLen = P384KeyShare;
			put2(p, ExtKeyShare); p += 2;
			put2(p, 2 + sharesLen); p += 2;
			put2(p, sharesLen); p += 2;
			put2(p, GroupSecp384r1); p += 2;
			put2(p, P384Pub); p += 2;
			memmove(p, p384pub, P384Pub); p += P384Pub;
		}else{
			sharesLen = X25519KeyShare + P256KeyShare;
			put2(p, ExtKeyShare); p += 2;
			put2(p, 2 + sharesLen); p += 2;
			put2(p, sharesLen); p += 2;
			put2(p, GroupX25519); p += 2;
			put2(p, X25519Pub); p += 2;
			memmove(p, x25519pub, X25519Pub); p += X25519Pub;
			put2(p, GroupSecp256r1); p += 2;
			put2(p, P256Pub); p += 2;
			memmove(p, p256pub, P256Pub); p += P256Pub;
		}

		if(cookieLen > 0){
			put2(p, ExtCookie); p += 2;
			put2(p, 2 + cookieLen); p += 2;
			put2(p, cookieLen); p += 2;
			memmove(p, cookie, cookieLen); p += cookieLen;
		}

		put2(p, ExtSigAlgs); p += 2;
		put2(p, 2+2+2); p += 2;
		put2(p, 2+2); p += 2;
		put2(p, SigRsaPssSha256); p += 2;
		put2(p, SigEcdsaSecp256r1Sha256); p += 2;

		if(sni != nil && (snilen = strlen(sni)) > 0){
			put2(p, ExtServerName); p += 2;
			put2(p, 2+1+2+snilen); p += 2;
			put2(p, 1+2+snilen); p += 2;
			*p++ = 0;
			put2(p, snilen); p += 2;
			memmove(p, sni, snilen); p += snilen;
		}
		put2(extl, p - extl - 2);
	}

	n = p - buf;
	put3(plen, n-4);
	return n;
}

static int
parseServerHello(uchar *data, int n,
	int *version, uchar *random, int *cipher,
	int *curve, uchar *share, int *shareLen,
	uchar *cookie, int *cookieLen)
{
	int i, extLen, legacyVer;
	uchar *p;

	if(n < 38) return -1;
	p = data;
	if(*p++ != HTServerHello) return -1;
	if(get3(p) != n-4) return -1;
	p += 3;
	legacyVer = get2(p); p += 2;
	if(legacyVer < TLS12Version) return -1;
	*version = legacyVer;
	memmove(random, p, 32); p += 32;
	i = *p++; p += i;
	*cipher = get2(p); p += 2;
	p++;
	if(p - data >= n) return -1;
	extLen = get2(p); p += 2;
	*cookieLen = 0;
	while(p - data + 4 <= n){
		int t, l;
		t = get2(p); p += 2;
		l = get2(p); p += 2;
		if(p + l > data + n) return -1;
		if(t == ExtKeyShare){
			int cur;
			if(l < 2) return -1;
			cur = get2(p);
			if(cur != GroupX25519 && cur != GroupSecp256r1
			&& cur != GroupSecp384r1)
				return -1;
			*curve = cur;
			if(l == 2){
				*shareLen = 0;
			}else{
				if(l < 4) return -1;
				*shareLen = get2(p+2);
				if(*shareLen > P384Pub) return -1;
				memmove(share, p+4, *shareLen);
			}
		}
		if(t == ExtCookie){
			if(l < 2) return -1;
			*cookieLen = get2(p);
			if(*cookieLen > 512) return -1;
			memmove(cookie, p+2, *cookieLen);
		}
		if(t == ExtSupportedVersions){
			if(l < 2) return -1;
			*version = get2(p);
		}
		p += l;
	}
	return 0;
}

static int
parseCertificate(uchar *data, int n, uchar **cert, int *certLen)
{
	uchar *p, *end;
	int total, clen;

	p = data;
	if(*p != HTCertificate) return -1;
	p++;
	total = get3(p); p += 3;
	end = p + total;
	if(end > data + n) return -1;
	if(p >= end) return -1;
	clen = *p++; p += clen;
	while(p < end){
		if(p + 3 > end) return -1;
		clen = get3(p); p += 3;
		if(p + clen > end) return -1;
		if(*cert == nil){
			*cert = p;
			*certLen = clen;
		}
		p += clen;
		if(p + 2 > end) return -1;
		p += get2(p) + 2;
	}
	return 0;
}

static int
recvEncrypted(int fd, uchar *buf, int *innerTyp,
	uchar *key, uchar *iv, u64int *seq, int isChaCha)
{
	int n, rt;
	for(;;){
		n = recvRecord(fd, buf, &rt);
		if(n < 0) return -1;
		if(rt == RTChangeCipherSpec) continue;
		if(rt == RTAppdata) break;
		return -1;
	}
	if(isChaCha)
		n = chachaUnprotect(key, 32, iv, seq, buf, n);
	else
		n = aesgcmUnprotect(key, 16, iv, seq, buf, n);
	if(n < 0) return -1;
	*innerTyp = buf[n-1];
	return n - 1;
}

static int
sendProtected(int fd, uchar *data, int n,
	uchar *key, uchar *iv, u64int *seq, int isChaCha)
{
	int outLen;

	data[n] = RTHandshake;
	if(isChaCha)
		outLen = chachaProtect(key, 32, iv, seq, data, n);
	else
		outLen = aesgcmProtect(key, 16, iv, seq, data, n);
	return sendRecord(fd, RTAppdata, data, outLen);
}

int
tls13Client(int fd, Tls13Keys *keys, int skipVerify, char *sni)
{
	uchar *buf;
	uchar random[32];
	uchar x25519pub[X25519Pub], x25519priv[X25519Priv];
	uchar p256pub[P256Pub], p384pub[P384Pub];
	int selectedCurve, shareLen, ecdheLen;
	uchar srandom[32], share[MaxKeyShare];
	int n, version, cipher;
	uchar *cert = nil;
	int certLen = 0;
	uchar emptyHash[32];
	uchar ecdheSecret[P384Coord], earlySecret[32], derived[32];
	uchar hsSecret[32];
	uchar cHsTraffic[32], sHsTraffic[32];
	uchar cApTraffic[32], sApTraffic[32];
	uchar cHsKey[32], sHsKey[32], cHsIV[12], sHsIV[12];
	u64int rseq, wseq;
	DigestState *transcript;
	int isChaCha;
	int innerTyp;
	ECdomain ecDom;	/* per il gruppo selezionato (P-256 o P-384) */
	ECpriv ecQ;
	ECdomain ecDom384;	/* P-384 keypair da usare se server lo sceglie */
	ECpriv ecQ384;
		ECpoint ecK;
	uchar sid[32];
	int sidLen = 0;
	uchar cookie[512];
	int cookieLen;

	buf = malloc(MaxRecLen+256);
	if(buf == nil) return -1;
	memset(keys, 0, sizeof(*keys));
	genrandom(random, 32);
	transcript = nil;

	genrandom(x25519priv, X25519Priv);
	curve25519_dh_new(x25519priv, x25519pub);

	memset(&ecQ, 0, sizeof(ecQ));
	ecQ.x = mpnew(0); ecQ.y = mpnew(0); ecQ.d = mpnew(0);
	ecdominit(&ecDom, secp256r1);
	ecgen(&ecDom, &ecQ);
	ecencodepub(&ecDom, (ECpub*)&ecQ, p256pub, P256Pub);

	memset(&ecQ384, 0, sizeof(ecQ384));
	ecQ384.x = mpnew(0); ecQ384.y = mpnew(0); ecQ384.d = mpnew(0);
	ecdominit(&ecDom384, secp384r1);
	ecgen(&ecDom384, &ecQ384);
	ecencodepub(&ecDom384, (ECpub*)&ecQ384, p384pub, P384Pub);

	{
		uchar ch1hash[32];

		n = buildClientHello(buf, x25519pub, p256pub, p384pub,
			random, sid, 0, sni, 0, nil, 0);
		sidLen = buf[38];
		if(sidLen > 32) sidLen = 32;
		memmove(sid, buf+39, sidLen);
		sha2_256(buf, n, ch1hash, nil);
		if(sendRecord(fd, RTHandshake, buf, n) < 0) goto err;
		transcript = sha2_256(buf, n, nil, nil);

		n = recvHandshake(fd, buf);
		if(n < 0) goto err;
		memset(share, 0, sizeof(share));
		shareLen = 0;
		selectedCurve = 0;
		cookieLen = 0;
		if(parseServerHello(buf, n, &version, srandom, &cipher,
				&selectedCurve, share, &shareLen,
				cookie, &cookieLen) < 0) goto err;
		if(version != TLS13Version) goto err;

		/* HelloRetryRequest */
		if(tsmemcmp(srandom, hrrRandom, 32) == 0){
			if(selectedCurve != GroupSecp384r1) goto err;

			/* transcript reset: message_hash(CH1) + HRR (RFC 8446 §4.4.1) */
			{
				uchar mh[4+SHA256dlen];
				transcript = nil;
				mh[0] = HTMessageHash;
				put3(mh+1, SHA256dlen);
				memmove(mh+4, ch1hash, SHA256dlen);
				transcript = sha2_256(mh, 4+SHA256dlen, nil, transcript);
			}
			transcript = sha2_256(buf, n, nil, transcript);

			n = buildClientHello(buf, x25519pub, p256pub, p384pub,
				random, sid, sidLen, sni, 1, cookie, cookieLen);
			if(sendRecord(fd, RTHandshake, buf, n) < 0) goto err;
			transcript = sha2_256(buf, n, nil, transcript);

			n = recvHandshake(fd, buf);
			if(n < 0) goto err;
			memset(share, 0, sizeof(share));
			shareLen = 0;
			selectedCurve = 0;
			cookieLen = 0;
			if(parseServerHello(buf, n, &version, srandom, &cipher,
					&selectedCurve, share, &shareLen,
					cookie, &cookieLen) < 0) goto err;
			if(version != TLS13Version) goto err;
		}
		transcript = sha2_256(buf, n, nil, transcript);
	}

	/* ECDHE */
	isChaCha = (cipher == TLS13_CHACHA20_POLY1305);
	memset(ecdheSecret, 0, sizeof(ecdheSecret));
	if(selectedCurve == GroupX25519){
		ecdheLen = X25519Sec;
		if(shareLen != ecdheLen) goto err;
		if(!curve25519_dh_finish(x25519priv, share, ecdheSecret)) goto err;
	} else if(selectedCurve == GroupSecp256r1 || selectedCurve == GroupSecp384r1){
		ECdomain *d;
		ECpriv *q;
		ECpub *spub;
		ecdheLen = (selectedCurve == GroupSecp256r1) ? P256Coord : P384Coord;
		if(selectedCurve == GroupSecp256r1){ d = &ecDom; q = &ecQ; }
		else { d = &ecDom384; q = &ecQ384; }
		if(q->d == nil) goto err;
		spub = ecdecodepub(d, share, shareLen);
		if(spub == nil) goto err;
		memset(&ecK, 0, sizeof(ecK));
		ecK.x = mpnew(0); ecK.y = mpnew(0);
		ecmul(d, spub, q->d, &ecK);
		mptober(ecK.x, ecdheSecret, ecdheLen);
		mpfree(ecK.x); mpfree(ecK.y);
		ecpubfree(spub);
	} else
		goto err;

	/* Handshake key derivation */
	sha2_256(nil, 0, emptyHash, nil);
	{
		uchar z[32];
		memset(z, 0, 32);
		hmac_sha2_256(z, 32, z, 32, earlySecret, nil);
	}
	hkdfExpandLabel(earlySecret, derlab, emptyHash, SHA256dlen,
		derived, SHA256dlen, hmac_sha2_256, SHA256dlen);
	hmac_sha2_256(ecdheSecret, ecdheLen, derived, SHA256dlen, hsSecret, nil);
	{
		uchar th[32];
		xthashClone(transcript, th);
		hkdfExpandLabel(hsSecret, c2slab, th, SHA256dlen,
			cHsTraffic, SHA256dlen, hmac_sha2_256, SHA256dlen);
		hkdfExpandLabel(hsSecret, s2clab, th, SHA256dlen,
			sHsTraffic, SHA256dlen, hmac_sha2_256, SHA256dlen);
	}
	{
		int hk = isChaCha ? 32 : 16;
		hkdfExpandLabel(cHsTraffic, keylab, nil, 0, cHsKey, hk, hmac_sha2_256, SHA256dlen);
		hkdfExpandLabel(cHsTraffic, ivlab, nil, 0, cHsIV, 12, hmac_sha2_256, SHA256dlen);
		hkdfExpandLabel(sHsTraffic, keylab, nil, 0, sHsKey, hk, hmac_sha2_256, SHA256dlen);
		hkdfExpandLabel(sHsTraffic, ivlab, nil, 0, sHsIV, 12, hmac_sha2_256, SHA256dlen);
	}

	/* 5. read & decrypt server flight */
	rseq = 0; wseq = 0;
	n = recvEncrypted(fd, buf, &innerTyp, sHsKey, sHsIV, &rseq, isChaCha);
	if(n < 0) goto err;
	if(innerTyp != RTHandshake) goto err;

	/* 6. process encrypted handshake messages */
	for(;;){
		uchar *p = buf;
		int remain = n;
		while(remain > 0){
			int htype, hlen;
			if(remain < 4) goto err;
			htype = p[0];
			hlen = get3(p+1);
			p += 4; remain -= 4;
			if(remain < hlen) goto err;
			switch(htype){
			case HTEncryptedExtensions:
				transcript = sha2_256(p-4, hlen+4, nil, transcript);
				break;
			case HTCertificate:
				transcript = sha2_256(p-4, hlen+4, nil, transcript);
				if(!skipVerify) parseCertificate(p, hlen, &cert, &certLen);
				break;
			case HTCertificateVerify:
			{
				int sigalg, sigLen;
				uchar *sig;
				char *err;
				if(hlen < 4) goto err;
				sigalg = get2(p);
				sigLen = get2(p+2);
				sig = p+4;
				if(sigLen + 4 > hlen) goto err;
				if(!skipVerify && cert != nil){
					err = verifyCertVerify(transcript, 1, sigalg, sig, sigLen, cert, certLen);
					if(err != nil){ werrstr("cert ver: %s", err); goto err; }
				}
				transcript = sha2_256(p-4, hlen+4, nil, transcript);
				break;
			}
			case HTFinished:
			{
				uchar fkey[32], fdata[32];
				hkdfExpandLabel(sHsTraffic, finlab, nil, 0, fkey, SHA256dlen, hmac_sha2_256, SHA256dlen);
				{
					uchar th[32];
					xthashClone(transcript, th);
					hmac_sha2_256(th, SHA256dlen, fkey, SHA256dlen, fdata, nil);
				}
				if(hlen < SHA256dlen) goto err;
				if(tsmemcmp(fdata, p, SHA256dlen) != 0) goto err;
				transcript = sha2_256(p-4, hlen+4, nil, transcript);
				goto ServerDone;
			}
			default:
				transcript = sha2_256(p-4, hlen+4, nil, transcript);
				break;
			}
			p += hlen; remain -= hlen;
		}
		n = recvEncrypted(fd, buf, &innerTyp, sHsKey, sHsIV, &rseq, isChaCha);
		if(n < 0) goto err;
		if(innerTyp != RTHandshake) goto err;
	}
ServerDone:

	/* 7. Client Finished */
	{
		uchar fkey[32], fdata[32];
		uchar out[4+SHA256dlen+1+32];
		hkdfExpandLabel(cHsTraffic, finlab, nil, 0, fkey, SHA256dlen, hmac_sha2_256, SHA256dlen);
		{
			uchar th[32];
			xthashClone(transcript, th);
			hmac_sha2_256(th, SHA256dlen, fkey, SHA256dlen, fdata, nil);
		}
		out[0] = HTFinished;
		put3(out+1, SHA256dlen);
		memmove(out+4, fdata, SHA256dlen);
		transcript = sha2_256(out, 4+SHA256dlen, nil, transcript);
		if(sendProtected(fd, out, 4+SHA256dlen,
			cHsKey, cHsIV, &wseq, isChaCha) < 0) goto err;
	}

	/* 8. derive application keys */
	{
		uchar th[32], masterSecret[32];
		hkdfExpandLabel(hsSecret, derlab, emptyHash, SHA256dlen,
			derived, SHA256dlen, hmac_sha2_256, SHA256dlen);
		{
			uchar z[32];
			memset(z, 0, 32);
			hmac_sha2_256(z, 32, derived, SHA256dlen, masterSecret, nil);
		}
		xthashClone(transcript, th);
		hkdfExpandLabel(masterSecret, c2sapp, th, SHA256dlen,
			cApTraffic, SHA256dlen, hmac_sha2_256, SHA256dlen);
		hkdfExpandLabel(masterSecret, s2capp, th, SHA256dlen,
			sApTraffic, SHA256dlen, hmac_sha2_256, SHA256dlen);
		{
			int hk = isChaCha ? 32 : 16;
			hkdfExpandLabel(cApTraffic, keylab, nil, 0, keys->clientKey, hk, hmac_sha2_256, SHA256dlen);
			hkdfExpandLabel(cApTraffic, ivlab, nil, 0, keys->clientIV, 12, hmac_sha2_256, SHA256dlen);
			hkdfExpandLabel(sApTraffic, keylab, nil, 0, keys->serverKey, hk, hmac_sha2_256, SHA256dlen);
			hkdfExpandLabel(sApTraffic, ivlab, nil, 0, keys->serverIV, 12, hmac_sha2_256, SHA256dlen);
		}
	}

	keys->cipher = cipher;
	keys->keyLen = isChaCha ? 32 : 16;
	keys->ivLen = 12;
	if(!skipVerify && cert != nil && certLen > 0){
		keys->serverCert = malloc(certLen);
		if(keys->serverCert != nil){
			memmove(keys->serverCert, cert, certLen);
			keys->serverCertLen = certLen;
		}
	}
	ecdomfree(&ecDom384);
	mpfree(ecQ384.x); mpfree(ecQ384.y); mpfree(ecQ384.d);
	ecdomfree(&ecDom);
	mpfree(ecQ.x); mpfree(ecQ.y); mpfree(ecQ.d);
	free(buf);
	return 0;
err:
	ecdomfree(&ecDom384);
	mpfree(ecQ384.x); mpfree(ecQ384.y); mpfree(ecQ384.d);
	ecdomfree(&ecDom);
	mpfree(ecQ.x); mpfree(ecQ.y); mpfree(ecQ.d);
	free(buf);
	return -1;
}

static char*
sniFromAddr(const char *addr)
{
  const char *s = strchr(addr, '!');
  if(!s) return nil;
  s = &s[1];
  const char *e = strchr(s, '!');
  if(!e) return nil;
  usize len = (usize)(((uintptr)e) - ((uintptr)s));
  char *res = malloc(len + 1);
  if (!res) return nil;
  memcpy(res, s, len);
  res[len] = 0;
  return res;
}

static void
usage(void)
{
	fprint(2, "usage: tls13 [-d] [-k] proto!host!port\n");
	exits("usage");
}

void
main(int argc, char **argv)
{
	int fd, i, skipVerify, printkeys;
	char *host, *sni;
	Tls13Keys keys;

	skipVerify = 0;
	printkeys = 0;
	ARGBEGIN{
	case 'd':
		skipVerify = 1;
		break;
	case 'k':
		printkeys = 1;
		break;
	default:
		usage();
	}ARGEND
	if(argc != 1) usage();
	host = argv[0];

	fd = dial(host, nil, nil, nil);
	if(fd < 0){
		fprint(2, "dial %s: %r\n", host);
		exits("dial");
	}
	sni = sniFromAddr(host);
	if(tls13Client(fd, &keys, skipVerify, sni) < 0){
		fprint(2, "tls13: %r\n");
		close(fd);
		exits("tls");
	}
	free(sni);
	print("TLS 1.3 handshake OK\n");
	print("Cipher: %#x\n", keys.cipher);
	if(printkeys){
		print("keylen %d ivlen %d\n", keys.keyLen, keys.ivLen);
		print("client_key: ");
		for(i = 0; i < keys.keyLen; i++) print("%.2x", keys.clientKey[i]);
		print("\nserver_key: ");
		for(i = 0; i < keys.keyLen; i++) print("%.2x", keys.serverKey[i]);
		print("\nclient_iv: ");
		for(i = 0; i < keys.ivLen; i++) print("%.2x", keys.clientIV[i]);
		print("\nserver_iv: ");
		for(i = 0; i < keys.ivLen; i++) print("%.2x", keys.serverIV[i]);
		print("\n");
		print("echo the above to set ctl: secret <hash> <enc> <isclient> <base64>\n");
	}
	if(keys.serverCert != nil){
		print("Server cert (%d bytes):\n", keys.serverCertLen);
		X509dump(keys.serverCert, keys.serverCertLen);
		free(keys.serverCert);
	}
	close(fd);
	exits(nil);
}
