//! Shared Blowfish machinery: the P-array/S-box state, the key schedule, the 16-round Feistel
//! network, and zero-padded ECB. The two public variants differ only in how the key schedule folds
//! in key bytes and in block-word endianness.

mod legacy;
mod standard;
mod tables;

#[cfg(test)]
mod tests;

pub use legacy::LegacyBlowfish;
pub use standard::Blowfish;

/// Block-word byte order. The launcher variant reads/writes little-endian; the standard variant
/// big-endian.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Endian {
    Little,
    Big,
}

/// The keyed cipher state: 18 subkeys plus four 256-entry S-boxes.
#[derive(Clone)]
pub(crate) struct BlowfishCore {
    p: [u32; 18],
    s: [[u32; 256]; 4],
}

impl BlowfishCore {
    /// Run the key schedule. `sign_extend` selects the launcher variant's signed-byte folding.
    pub(crate) fn new(key: &[u8], sign_extend: bool) -> Self {
        let mut core = Self {
            p: tables::P_INIT,
            s: tables::S_INIT,
        };
        core.mix_key(key, sign_extend);
        core.expand();
        core
    }

    /// XOR the key into the P-array, cycling the key bytes. Each 32-bit fragment is assembled
    /// big-endian; the launcher variant sign-extends each byte first (see [`legacy`]).
    fn mix_key(&mut self, key: &[u8], sign_extend: bool) {
        if key.is_empty() {
            return;
        }
        let mut j = 0usize;
        for slot in &mut self.p {
            let mut data: u32 = 0;
            for _ in 0..4 {
                let byte = key[j];
                let contrib = if sign_extend {
                    // Fold the byte in as signed: values >= 0x80 sign-extend into the high bits.
                    (byte as i8) as i32 as u32
                } else {
                    byte as u32
                };
                data = (data << 8) | contrib;
                j = (j + 1) % key.len();
            }
            *slot ^= data;
        }
    }

    /// Fill P and the S-boxes by encrypting the running all-zero block through the freshly-keyed
    /// state.
    fn expand(&mut self) {
        let mut l = 0u32;
        let mut r = 0u32;
        let mut i = 0usize;
        while i < 18 {
            let (nl, nr) = self.encrypt_words(l, r);
            l = nl;
            r = nr;
            self.p[i] = l;
            self.p[i + 1] = r;
            i += 2;
        }
        for box_idx in 0..4 {
            let mut k = 0usize;
            while k < 256 {
                let (nl, nr) = self.encrypt_words(l, r);
                l = nl;
                r = nr;
                self.s[box_idx][k] = l;
                self.s[box_idx][k + 1] = r;
                k += 2;
            }
        }
    }

    /// The Feistel round function: `((S0[a] + S1[b]) XOR S2[c]) + S3[d]`, additions mod 2^32.
    fn f(&self, x: u32) -> u32 {
        let a = self.s[0][(x >> 24) as usize & 0xff];
        let b = self.s[1][(x >> 16) as usize & 0xff];
        let c = self.s[2][(x >> 8) as usize & 0xff];
        let d = self.s[3][x as usize & 0xff];
        (a.wrapping_add(b) ^ c).wrapping_add(d)
    }

    fn encrypt_words(&self, mut l: u32, mut r: u32) -> (u32, u32) {
        for i in 0..16 {
            l ^= self.p[i];
            r ^= self.f(l);
            std::mem::swap(&mut l, &mut r);
        }
        std::mem::swap(&mut l, &mut r);
        r ^= self.p[16];
        l ^= self.p[17];
        (l, r)
    }

    fn decrypt_words(&self, mut l: u32, mut r: u32) -> (u32, u32) {
        for i in (2..18).rev() {
            l ^= self.p[i];
            r ^= self.f(l);
            std::mem::swap(&mut l, &mut r);
        }
        std::mem::swap(&mut l, &mut r);
        r ^= self.p[1];
        l ^= self.p[0];
        (l, r)
    }

    /// Zero-pad to an 8-byte multiple and ECB-encrypt each block in `endian` word order.
    fn encrypt_ecb(&self, data: &[u8], endian: Endian) -> Vec<u8> {
        let mut buf = pad8(data);
        for block in buf.chunks_exact_mut(8) {
            let (l, r) = self.encrypt_words(word_in(block, 0, endian), word_in(block, 4, endian));
            word_out(block, 0, l, endian);
            word_out(block, 4, r, endian);
        }
        buf
    }

    /// ECB-decrypt each 8-byte block in `endian` word order. Trailing partial input is zero-padded
    /// first so the call never panics; well-formed ciphertext is always a multiple of 8.
    fn decrypt_ecb(&self, data: &[u8], endian: Endian) -> Vec<u8> {
        let mut buf = pad8(data);
        for block in buf.chunks_exact_mut(8) {
            let (l, r) = self.decrypt_words(word_in(block, 0, endian), word_in(block, 4, endian));
            word_out(block, 0, l, endian);
            word_out(block, 4, r, endian);
        }
        buf
    }

    #[cfg(test)]
    pub(crate) fn state_dump(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        out.push_str("P:\n");
        for (i, v) in self.p.iter().enumerate() {
            let _ = write!(out, "{v:08x}");
            out.push(if i % 6 == 5 { '\n' } else { ' ' });
        }
        for (bi, sbox) in self.s.iter().enumerate() {
            let _ = write!(out, "\nS{bi}:\n");
            for (i, v) in sbox.iter().enumerate() {
                let _ = write!(out, "{v:08x}");
                out.push(if i % 8 == 7 { '\n' } else { ' ' });
            }
        }
        out
    }
}

fn pad8(data: &[u8]) -> Vec<u8> {
    let mut buf = data.to_vec();
    let rem = buf.len() % 8;
    if rem != 0 {
        buf.resize(buf.len() + (8 - rem), 0);
    }
    buf
}

fn word_in(block: &[u8], off: usize, endian: Endian) -> u32 {
    let a = [block[off], block[off + 1], block[off + 2], block[off + 3]];
    match endian {
        Endian::Little => crate::bytes::u32_le(a),
        Endian::Big => crate::bytes::u32_be(a),
    }
}

fn word_out(block: &mut [u8], off: usize, v: u32, endian: Endian) {
    let a = match endian {
        Endian::Little => crate::bytes::write_u32_le(v),
        Endian::Big => crate::bytes::write_u32_be(v),
    };
    block[off..off + 4].copy_from_slice(&a);
}
