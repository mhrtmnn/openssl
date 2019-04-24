use rand::Rng;

/*******************************************************************************
 * Constants
 *******************************************************************************/
const TLS1_HB_REQUEST: u8 = 1;
const TLS1_HB_RESPONSE: u8 = 2;
const TLS1_RT_HEARTBEAT: i32 = 24;

const FIELD_TYPE_LEN: usize = 1;
const FIELD_LENG_LEN: usize = 2;
const FIELD_PADD_LEN: usize = 16;

/*******************************************************************************
 * Prototypes of C functions
 *******************************************************************************/
extern "C" {
	fn ssl3_write_bytes(s: *const u8, msg_type: i32, buf: *const u8, len: i32) -> i32;
	// int ssl3_write_bytes(SSL *s, int type, const void *buf, int len);
}

/*******************************************************************************
 * Exported Function
 *******************************************************************************/
#[no_mangle]
pub extern "C" fn __tls1_process_heartbeat(ssl: *const u8, data: *const u8, msg_len: u32) -> i32
{
	let mut r: i32 = 0;
	let p: &[u8];

	println!("=== Entering Rust section ===");

	/* unsafe pointer deref */
	unsafe {
		p = std::slice::from_raw_parts(data, msg_len as usize);
	}

	let hbtype: u8 = p[0];
	let payload: u16 = ((p[1] as u16) << 8) | (p[2] as u16);
	let mut buffer: Vec<u8> = Vec::with_capacity(msg_len as usize);

	if hbtype == TLS1_HB_REQUEST {
		buffer.push(TLS1_HB_RESPONSE);
		buffer.extend_from_slice(&p[1..1 + FIELD_LENG_LEN]);
		buffer.extend_from_slice(&p[3..3 + payload as usize]);
		buffer.extend_from_slice(&rand::thread_rng().gen::<[u8; FIELD_PADD_LEN]>());

		println!("Payload claims to be of len {}, actual len {}", payload, msg_len);

		unsafe {
			r = ssl3_write_bytes(ssl, TLS1_RT_HEARTBEAT, buffer.as_mut_ptr(), (FIELD_TYPE_LEN + FIELD_LENG_LEN + FIELD_PADD_LEN) as i32 + payload as i32);
		}

		// prevent Rust from freeing the buffer on function / scope end
		std::mem::forget(buffer);
	}

	println!("=== Leaving Rust Section (code={}) ===", r);
	r
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