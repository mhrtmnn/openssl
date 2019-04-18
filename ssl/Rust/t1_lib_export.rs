/*******************************************************************************
 * Exported Function
 *******************************************************************************/
#[no_mangle]
pub extern "C" fn __tls1_process_heartbeat(ssl: *const u8, p: *const u8, msg_len: u32) -> i32
{
	println!("=== Rust: We are in! ===");
	println!("Got a msg of len {}", msg_len);
	println!("=== leaving Rust! ===");
	0
}

/*
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
*/