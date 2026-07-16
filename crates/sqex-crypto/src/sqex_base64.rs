//! SE's mangled base64: standard base64 with `+`/`/`/`=` swapped for `-`/`_`/`*`. Padding is kept
//! (SE parses the `*` chars). Hand-rolled so the mangled alphabet is unambiguous and dependency-free.

/// Standard base64 alphabet with `+`->`-` and `/`->`_` already applied. Index 62 is `-`, 63 is `_`.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const PAD: char = '*';

/// Encode `input` to mangled base64 with padding retained.
#[must_use]
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 0x3f] as char
        } else {
            PAD
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 0x3f] as char
        } else {
            PAD
        });
    }
    out
}

/// Decode mangled base64. Returns `None` on any malformed input (never panics).
#[must_use]
pub fn decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let groups = bytes.len() / 4;
    let mut out = Vec::with_capacity(groups * 3);
    for (gi, group) in bytes.chunks(4).enumerate() {
        let is_last = gi + 1 == groups;
        let mut n: u32 = 0;
        let mut pads = 0u32;
        for &c in group {
            if c == b'*' {
                pads += 1;
                n <<= 6;
            } else {
                if pads > 0 {
                    return None; // a real char after padding within a group
                }
                n = (n << 6) | sextet(c)?;
            }
        }
        if pads > 0 && !is_last {
            return None; // padding only allowed in the final group
        }
        match pads {
            0 => {
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
                out.push(n as u8);
            }
            1 => {
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
            }
            2 => out.push((n >> 16) as u8),
            _ => return None,
        }
    }
    Some(out)
}

/// Map one mangled-alphabet char to its 6-bit value.
fn sextet(c: u8) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn known_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"Hello, world"), "SGVsbG8sIHdvcmxk"); // no mangled chars
        assert_eq!(encode(&[0xff, 0xff, 0xff]), "____"); // standard "////"
        assert_eq!(encode(&[0xfb]), "-w**"); // standard "+w==" -> exercises '-' and '*'
    }

    #[test]
    fn decodes_known_vectors() {
        assert_eq!(decode("").as_deref(), Some(&b""[..]));
        assert_eq!(decode("____").as_deref(), Some(&[0xff, 0xff, 0xff][..]));
        assert_eq!(decode("-w**").as_deref(), Some(&[0xfb][..]));
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(decode("abc"), None); // not a multiple of 4
        assert_eq!(decode("****"), None); // 4 pads -> no data
        assert_eq!(decode("A*AA"), None); // real char after pad within a group
        assert_eq!(decode("**AA"), None); // pad before data
        assert_eq!(decode("AA**AAAA"), None); // padding outside the final group
        assert_eq!(decode("=AAA"), None); // standard-base64 pad char is not the mangled alphabet
    }

    proptest! {
        #[test]
        fn round_trips(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
            let decoded = decode(&encode(&bytes));
            prop_assert_eq!(decoded.as_deref(), Some(bytes.as_slice()));
        }

        #[test]
        fn decode_never_panics(s in ".{0,64}") {
            let _ = decode(&s);
        }
    }
}
