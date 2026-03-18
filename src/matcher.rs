use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::Ipv6Addr;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Matcher {
    mask: u128,
    value: u128,
    fixed_bits: u32,
    byte_masks: [u8; 16],
    byte_values: [u8; 16],
    constrained_bytes: [u8; 16],
    constrained_len: u8,
}

impl Matcher {
    #[inline(always)]
    pub fn any() -> Self {
        Self::new(0, 0, 0)
    }

    pub fn from_hex_prefix(prefix: &str) -> Result<Self, MatcherError> {
        let cleaned = prefix
            .trim()
            .trim_start_matches("0x")
            .replace([':', '-', ' ', '_'], "");

        if cleaned.is_empty() {
            return Err(MatcherError::EmptyPattern);
        }

        if cleaned.len() > 32 {
            return Err(MatcherError::HexPrefixTooLong(cleaned.len()));
        }

        let mut value = 0u128;
        for ch in cleaned.chars() {
            let nibble = ch.to_digit(16).ok_or(MatcherError::InvalidHex(ch))? as u128;
            value = (value << 4) | nibble;
        }

        let used_bits = cleaned.len() * 4;
        let shift = 128 - used_bits;
        let mask = if used_bits == 128 {
            u128::MAX
        } else {
            u128::MAX << shift
        };

        Ok(Self::new(mask, value << shift, used_bits as u32))
    }

    pub fn from_cidr(cidr: &str) -> Result<Self, MatcherError> {
        let (addr, prefix_len) = cidr
            .split_once('/')
            .ok_or_else(|| MatcherError::InvalidCidr(cidr.to_owned()))?;

        let addr =
            Ipv6Addr::from_str(addr).map_err(|_| MatcherError::InvalidCidr(cidr.to_owned()))?;
        let prefix_len: u32 = prefix_len
            .parse()
            .map_err(|_| MatcherError::InvalidCidr(cidr.to_owned()))?;

        if prefix_len > 128 {
            return Err(MatcherError::InvalidPrefixLength(prefix_len));
        }

        let shift = 128 - prefix_len;
        let mask = if prefix_len == 0 {
            0
        } else {
            u128::MAX << shift
        };
        let value = u128::from_be_bytes(addr.octets()) & mask;

        Ok(Self::new(mask, value, prefix_len))
    }

    pub fn from_template(template: &str) -> Result<Self, MatcherError> {
        let parts = template.trim().split(':').collect::<Vec<_>>();
        if parts.len() != 8 {
            return Err(MatcherError::InvalidTemplate(template.to_owned()));
        }

        let mut mask = 0u128;
        let mut value = 0u128;
        let mut fixed_bits = 0u32;

        for (index, part) in parts.into_iter().enumerate() {
            if part == "?" {
                continue;
            }

            if part.is_empty() || part.len() > 4 {
                return Err(MatcherError::InvalidTemplate(template.to_owned()));
            }

            let hextet = u16::from_str_radix(part, 16)
                .map_err(|_| MatcherError::InvalidTemplate(template.to_owned()))?;

            // The first hextet in Yggdrasil is treated as a conventional display prefix.
            // We accept it in the template syntax, but it doesn't participate in matching
            // or vanity rarity estimation.
            if index == 0 {
                continue;
            }

            let shift = (7 - index) * 16;
            mask |= 0xffff_u128 << shift;
            value |= u128::from(hextet) << shift;
            fixed_bits += 16;
        }

        Ok(Self::new(mask, value, fixed_bits))
    }

    #[inline(always)]
    pub fn matches(&self, addr: &[u8; 16]) -> bool {
        self.matches_u128(u128::from_be_bytes(*addr))
    }

    #[inline(always)]
    pub fn matches_u128(&self, addr: u128) -> bool {
        (addr & self.mask) == self.value
    }

    #[inline(always)]
    pub fn matches_pubkey(&self, pubkey: &[u8; 32]) -> bool {
        if self.constrained_len == 0 {
            return true;
        }

        let leading_zeros = count_leading_zeros(pubkey);
        let skip_bits = (leading_zeros + 1).min(256);
        let byte_offset = skip_bits / 8;
        let bit_shift = skip_bits % 8;

        for &index in &self.constrained_bytes[..self.constrained_len as usize] {
            let index = index as usize;
            let actual = derive_match_byte(pubkey, leading_zeros, byte_offset, bit_shift, index);

            if (actual & self.byte_masks[index]) != self.byte_values[index] {
                return false;
            }
        }

        true
    }

    #[inline(always)]
    pub fn fixed_bits(&self) -> u32 {
        self.fixed_bits
    }

    #[inline(always)]
    fn new(mask: u128, value: u128, fixed_bits: u32) -> Self {
        let byte_masks = mask.to_be_bytes();
        let byte_values = value.to_be_bytes();
        let mut constrained_bytes = [0u8; 16];
        let mut constrained_len = 0u8;

        for (index, &byte_mask) in byte_masks.iter().enumerate() {
            if byte_mask != 0 {
                constrained_bytes[constrained_len as usize] = index as u8;
                constrained_len += 1;
            }
        }

        Self {
            mask,
            value,
            fixed_bits,
            byte_masks,
            byte_values,
            constrained_bytes,
            constrained_len,
        }
    }
}

#[inline(always)]
fn count_leading_zeros(pubkey: &[u8; 32]) -> usize {
    let mut count = 0usize;

    for &byte in pubkey {
        let zeros = byte.leading_zeros() as usize;
        count += zeros;

        if zeros != 8 {
            break;
        }
    }

    count
}

#[inline(always)]
fn derive_match_byte(
    pubkey: &[u8; 32],
    leading_zeros: usize,
    byte_offset: usize,
    bit_shift: usize,
    addr_index: usize,
) -> u8 {
    match addr_index {
        0 => 0x02,
        1 => leading_zeros as u8,
        _ => {
            let payload_index = addr_index - 2;
            let upper = byte_offset
                .checked_add(payload_index)
                .and_then(|index| pubkey.get(index))
                .map_or(0, |byte| !byte);

            if bit_shift == 0 {
                upper
            } else {
                let lower = byte_offset
                    .checked_add(payload_index + 1)
                    .and_then(|index| pubkey.get(index))
                    .map_or(0, |byte| !byte);
                (upper << bit_shift) | (lower >> (8 - bit_shift))
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MatcherError {
    EmptyPattern,
    HexPrefixTooLong(usize),
    InvalidHex(char),
    InvalidCidr(String),
    InvalidPrefixLength(u32),
    InvalidTemplate(String),
}

impl Display for MatcherError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyPattern => write!(f, "шаблон для поиска не может быть пустым"),
            Self::HexPrefixTooLong(len) => {
                write!(
                    f,
                    "hex-префикс слишком длинный: {len} символов, максимум 32"
                )
            }
            Self::InvalidHex(ch) => write!(f, "некорректный hex-символ: {ch}"),
            Self::InvalidCidr(cidr) => write!(f, "некорректный IPv6 CIDR: {cidr}"),
            Self::InvalidPrefixLength(bits) => {
                write!(f, "некорректная длина IPv6-префикса: {bits}, максимум 128")
            }
            Self::InvalidTemplate(template) => {
                write!(
                    f,
                    "некорректный IPv6-шаблон: {template} (ожидается 8 групп, например 200:?:?:?:dead:beef:?:?)"
                )
            }
        }
    }
}

impl Error for MatcherError {}

#[cfg(test)]
mod tests {
    use super::Matcher;
    use crate::derive::pubkey_to_ipv6;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn matches_hex_prefix() {
        let matcher = Matcher::from_hex_prefix("0202").expect("matcher");
        let good = [0x02, 0x02, 0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let bad = [0x02, 0x03, 0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        assert!(matcher.matches(&good));
        assert!(!matcher.matches(&bad));
    }

    #[test]
    fn matches_ipv6_cidr() {
        let matcher = Matcher::from_cidr("202:fca::/32").expect("matcher");
        let good = [0x02, 0x02, 0x0f, 0xca, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let bad = [0x02, 0x03, 0x0f, 0xca, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        assert!(matcher.matches(&good));
        assert!(!matcher.matches(&bad));
    }

    #[test]
    fn matches_ipv6_template() {
        let matcher = Matcher::from_template("200:abcd:?:?:dead:beef:?:?").expect("matcher");
        let good = [
            0x02, 0x00, 0xab, 0xcd, 0x55, 0xaa, 0x77, 0x88, 0xde, 0xad, 0xbe, 0xef, 0, 1, 0, 2,
        ];
        let bad = [
            0x02, 0x00, 0xaa, 0xaa, 0x55, 0xaa, 0x77, 0x88, 0xde, 0xad, 0xbe, 0xef, 0, 1, 0, 2,
        ];

        assert!(matcher.matches(&good));
        assert!(!matcher.matches(&bad));
    }

    #[test]
    fn template_ignores_first_hextet_for_matching_and_rarity() {
        let matcher = Matcher::from_template("200:200:200:?:?:?:?:?").expect("matcher");
        let addr = [
            0x02, 0x0f, 0x02, 0x00, 0x02, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
            0x11, 0x22,
        ];

        assert!(matcher.matches(&addr));
        assert_eq!(matcher.fixed_bits(), 32);
    }

    #[test]
    fn matches_pubkey_is_equivalent_to_matching_derived_address() {
        let matchers = [
            Matcher::any(),
            Matcher::from_hex_prefix("020").expect("hex matcher"),
            Matcher::from_hex_prefix("02020fca").expect("hex matcher"),
            Matcher::from_cidr("202:fca::/32").expect("cidr matcher"),
            Matcher::from_cidr("200::/7").expect("cidr matcher"),
            Matcher::from_template("200:?:?:?:dead:beef:?:?").expect("template matcher"),
            Matcher::from_template("200:200:200:?:?:?:?:?").expect("template matcher"),
        ];
        let mut rng = ChaCha20Rng::from_seed([0x24; 32]);

        for _ in 0..4096 {
            let mut pubkey = [0u8; 32];
            rng.fill_bytes(&mut pubkey);
            let addr = pubkey_to_ipv6(&pubkey);

            for matcher in matchers {
                assert_eq!(matcher.matches_pubkey(&pubkey), matcher.matches(&addr));
            }
        }
    }
}
