#include <stdio.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ocsp.h>
#include <openssl/rand.h>
#include "ssl_locl.h"


/* SETUP */
#define VULN

#define ORIG 1
#define EXPT 2
#define RUST 3
#define MODE EXPT


#if MODE == ORIG

int tls1_process_heartbeat(SSL *s)
{
	unsigned char *p = &s->s3->rrec.data[0], *pl;
	unsigned short hbtype;
	unsigned int payload;
	unsigned int padding = 16; /* Use minimum padding */

	fprintf(stderr, "%s: I AM HERE!\n", __func__);

	if (s->msg_callback)
		fprintf(stderr, "%s: CALLBACK PRESENT!\n", __func__);
	else
		fprintf(stderr, "%s: CALLBACK NOT! PRESENT!\n", __func__);


#ifdef VULN
	/* Read type and payload length first */
	hbtype = *p++;
	n2s(p, payload);
	pl = p;
#endif

	if (s->msg_callback)
		s->msg_callback(0, s->version, TLS1_RT_HEARTBEAT,
			&s->s3->rrec.data[0], s->s3->rrec.length,
			s, s->msg_callback_arg);


#ifndef VULN
	/* Read type and payload length first */
	if (1 + 2 + 16 > s->s3->rrec.length)
		return 0; /* silently discard */
	hbtype = *p++;
	n2s(p, payload);
	if (1 + 2 + payload + 16 > s->s3->rrec.length)
		return 0; /* silently discard per RFC 6520 sec. 4 */
	pl = p;
#endif

	if (hbtype == TLS1_HB_REQUEST)
	{
		unsigned char *buffer, *bp;
		int r;

		fprintf(stderr, "%s [TLS1_HB_REQUEST]: I AM HERE!\n", __func__);


		/* Allocate memory for the response, size is 1 bytes
		 * message type, plus 2 bytes payload length, plus
		 * payload, plus padding
		 */
		buffer = OPENSSL_malloc(1 + 2 + payload + padding);
		bp = buffer;

		/* Enter response type, length and copy payload */
		*bp++ = TLS1_HB_RESPONSE;
		s2n(payload, bp);
		memcpy(bp, pl, payload);
		bp += payload;
		/* Random padding */
		RAND_pseudo_bytes(bp, padding);

		r = ssl3_write_bytes(s, TLS1_RT_HEARTBEAT, buffer, 3 + payload + padding);

		if (r >= 0 && s->msg_callback)
			s->msg_callback(1, s->version, TLS1_RT_HEARTBEAT,
				buffer, 3 + payload + padding,
				s, s->msg_callback_arg);

		OPENSSL_free(buffer);

		if (r < 0)
			return r;
	}
	else if (hbtype == TLS1_HB_RESPONSE)
		{
		unsigned int seq;

		fprintf(stderr, "%s [TLS1_HB_RESPONSE]: I AM HERE!\n", __func__);

		/* We only send sequence numbers (2 bytes unsigned int),
		 * and 16 random bytes, so we just try to read the
		 * sequence number */
		n2s(pl, seq);

		if (payload == 18 && seq == s->tlsext_hb_seq)
			{
			s->tlsext_hb_seq++;
			s->tlsext_hb_pending = 0;
			}
		}

	return 0;
}


#endif

#if MODE == EXPT

int __tls1_process_heartbeat(void *s, unsigned char *p, unsigned int msg_len)
{
	unsigned char *pl;
	unsigned short hbtype;
	unsigned int payload;
	unsigned int padding = 16; /* Use minimum padding */

	/* Read type and payload length first */
	if (1 + 2 + 16 > msg_len)
		return 0; /* silently discard */
	hbtype = *p++;
	n2s(p, payload);
	if (1 + 2 + payload + 16 > msg_len)
		return 0; /* silently discard per RFC 6520 sec. 4 */
	pl = p;

	if (hbtype == TLS1_HB_REQUEST)
	{
		unsigned char *buffer, *bp;
		int r;

		fprintf(stderr, "%s [TLS1_HB_REQUEST]: I AM HERE!\n", __func__);


		/* Allocate memory for the response, size is 1 bytes
		 * message type, plus 2 bytes payload length, plus
		 * payload, plus padding
		 */
		buffer = OPENSSL_malloc(1 + 2 + payload + padding);
		bp = buffer;

		/* Enter response type, length and copy payload */
		*bp++ = TLS1_HB_RESPONSE;
		s2n(payload, bp);
		memcpy(bp, pl, payload);
		bp += payload;
		/* Random padding */
		RAND_pseudo_bytes(bp, padding);

		r = ssl3_write_bytes(s, TLS1_RT_HEARTBEAT, buffer, 3 + payload + padding); // only native func call that is required

		OPENSSL_free(buffer);

		if (r < 0)
			return r;
	}

	return 0;
}

/* simple wrapper to avoid having to reinplement the very complex struct SSL */
int tls1_process_heartbeat(SSL *s)
{
	unsigned char *p = &s->s3->rrec.data[0];
	unsigned int msg_len = s->s3->rrec.length;

	return __tls1_process_heartbeat(s, p, msg_len);
}


#endif