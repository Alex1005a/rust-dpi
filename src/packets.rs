use core::str;
use memchr::memmem;

pub fn is_tls_hello(buffer: &[u8]) -> Option<usize> {
    if buffer.len() > 5
        && buffer.starts_with(&[0x16, 0x03])
        && buffer[5] == 0x01 {
        let server_name_extension = memmem::find(buffer, &[0, 0]);
        return server_name_extension.map(|idx| idx + 9);
    }
    None
}

pub fn is_http(buffer: &[u8]) -> Option<usize> {
    const METHODS: [&str; 9] = [
        "HEAD", "GET", "POST", "PUT", "DELETE",
        "OPTIONS", "CONNECT", "TRACE", "PATCH"
    ];
    for method in METHODS {
        if buffer.starts_with(method.as_bytes()) {
            let str = str::from_utf8(buffer).unwrap();
            if let Some(idx) = str.to_lowercase()
                .find("\nhost:")
                .map(|idx| idx + 6) {
                let mut offset = 0;
                for ch in str[idx..].chars() {
                    if ch != ' ' {
                        return Some(idx + offset);
                    }
                    offset += 1;
                }
            }
            return None;
        }
    }
    None
}

pub fn part_tls(buffer: &mut Vec<u8>, pos: usize) {
    let r_sz = ((buffer[3] as u16) << 8) | buffer[4] as u16;
    let mut vec1 = Vec::new();
    buffer[..3].clone_into(&mut vec1);

    let mut v = buffer.split_off(5 + pos);
    buffer.extend_from_slice(&vec1);
    buffer.append(&mut v);

    let mut v = buffer.split_off(8 + pos);
    buffer.extend_from_slice(&convert_u16_to_two_u8s_be(htons(r_sz - pos as u16)));
    buffer.append(&mut v);

    let vec2 = convert_u16_to_two_u8s_be(htons( pos as u16));
    buffer[3] = vec2[0];
    buffer[4] = vec2[1];
}

fn htons(val: u16) -> u16 {
    return ((val & 0x00FF) << 8) | ((val & 0xFF00) >> 8)
}

fn convert_u16_to_two_u8s_be(integer: u16) -> [u8; 2] {
    [integer as u8, (integer >> 8) as u8]
}