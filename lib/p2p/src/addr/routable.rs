pub fn is_routable(ip: &[u8; 16]) -> bool {
    match v4_of(ip) {
        Some(o) => routable_v4(&o),
        None => routable_v6(ip),
    }
}

pub fn v4_of(ip: &[u8; 16]) -> Option<[u8; 4]> {
    let mapped = ip[..10].iter().all(|b| *b == 0) && ip[10] == 0xff && ip[11] == 0xff;
    if mapped {
        Some([ip[12], ip[13], ip[14], ip[15]])
    } else {
        None
    }
}

fn routable_v4(o: &[u8; 4]) -> bool {
    !(

        o[0] == 0

        || o[0] == 127

        || o[0] == 10
        || (o[0] == 172 && (o[1] & 0xf0) == 16)
        || (o[0] == 192 && o[1] == 168)

        || (o[0] == 169 && o[1] == 254)

        || (o[0] & 0xf0) == 224

        || *o == [255, 255, 255, 255]

        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)

        || (o[0] == 100 && (o[1] & 0xc0) == 64)

        || (o[0] == 192 && o[1] == 0 && o[2] == 0)

        || (o[0] == 192 && o[1] == 88 && o[2] == 99)

        || (o[0] == 198 && (o[1] & 0xfe) == 18)

        || o[0] >= 240
    )
}

fn routable_v6(ip: &[u8; 16]) -> bool {
    let s = |i: usize| u16::from_be_bytes([ip[2 * i], ip[2 * i + 1]]);
    !(

        ip.iter().all(|b| *b == 0)

        || (ip[..15].iter().all(|b| *b == 0) && ip[15] == 1)

        || ip[0] == 0xff

        || (s(0) & 0xfe00) == 0xfc00

        || (s(0) & 0xffc0) == 0xfe80

        || (s(0) == 0x2001 && s(1) == 0x0db8)

        || (s(0) == 0x2001 && s(1) == 0x0002 && s(2) == 0)

        || (s(0) == 0x2001 && (s(1) & 0xfff0) == 0x0010)

        || (s(0) == 0x0064 && s(1) == 0xff9b)
    )
}

pub fn admissible(ip: &[u8; 16], port: u16, allow_local: bool) -> bool {
    if port == 0 {
        return false;
    }
    if allow_local {
        let unspecified = match v4_of(ip) {
            Some(o) => o == [0, 0, 0, 0],
            None => ip.iter().all(|b| *b == 0),
        };
        return !unspecified;
    }
    is_routable(ip)
}
