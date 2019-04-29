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
	// int ssl3_write_bytes(SSL *s, int type, const void *buf, int len);
	fn ssl3_write_bytes(s: *const u8, msg_type: i32, buf: *const u8, len: i32) -> i32;
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

	// unsafe pointer deref
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

		println!("Payload claims to be of len {}, message len {}", payload, msg_len);

		// unsafe function call via FFI
		unsafe {
			r = ssl3_write_bytes(ssl, TLS1_RT_HEARTBEAT, buffer.as_mut_ptr(), (FIELD_TYPE_LEN + FIELD_LENG_LEN + FIELD_PADD_LEN) as i32 + payload as i32);
		}
	}

	println!("=== Leaving Rust Section (code={}) ===", r);
	r
}

#[no_mangle]
pub extern "C" fn __tls1_process_heartbeat_no_bounds_check(ssl: *const u8, data: *const u8, msg_len: u32) -> i32
{
	let mut r: i32 = 0;
	let p: &[u8];

	println!("=== Entering (unsafe) Rust section ===");

	// unsafe pointer deref
	unsafe {
		p = std::slice::from_raw_parts(data, msg_len as usize);
	}

	let hbtype: u8 = p[0];
	let payload: u16 = ((p[1] as u16) << 8) | (p[2] as u16);
	let mut buffer: Vec<u8> = Vec::with_capacity(msg_len as usize);

	if hbtype == TLS1_HB_REQUEST {
		buffer.push(TLS1_HB_RESPONSE);
		buffer.extend_from_slice(&p[1..1 + FIELD_LENG_LEN]);

		// unsafe array access without bound checking
		unsafe {
			buffer.extend_from_slice(&p.get_unchecked(3..3 + payload as usize));
		}
		buffer.extend_from_slice(&rand::thread_rng().gen::<[u8; FIELD_PADD_LEN]>());

		println!("Payload claims to be of len {}, message len {}", payload, msg_len);

		// unsafe function call via FFI
		unsafe {
			r = ssl3_write_bytes(ssl, TLS1_RT_HEARTBEAT, buffer.as_mut_ptr(), (FIELD_TYPE_LEN + FIELD_LENG_LEN + FIELD_PADD_LEN) as i32 + payload as i32);
		}
	}

	println!("=== Leaving (unsafe) Rust Section (code={}) ===", r);
	r
}
