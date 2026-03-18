use std::net::Ipv6Addr;

pub const YGG_ADDRESS_PREFIX: u8 = 0x02;

#[inline(always)]
pub fn pubkey_to_ipv6(pubkey: &[u8; 32]) -> [u8; 16] {
    pubkey_to_ipv6_u128(pubkey).to_be_bytes()
}

#[inline(always)]
pub fn pubkey_to_ipv6_u128(pubkey: &[u8; 32]) -> u128 {
    let leading_zeros = count_leading_zeros(pubkey);
    let skip_bits = (leading_zeros + 1).min(256);
    let byte_offset = skip_bits / 8;
    let bit_shift = skip_bits % 8;
    let mut tail = [0u8; 15];
    let available = 32usize.saturating_sub(byte_offset).min(tail.len());

    let mut out = ((YGG_ADDRESS_PREFIX as u128) << 120) | ((leading_zeros as u128) << 112);

    for (dst, src) in tail
        .iter_mut()
        .zip(&pubkey[byte_offset..byte_offset + available])
    {
        *dst = !src;
    }

    if bit_shift == 0 {
        for (index, &byte) in tail[..14].iter().enumerate() {
            out |= (byte as u128) << (104 - (index * 8));
        }
    } else {
        for index in 0..14 {
            let shifted = (tail[index] << bit_shift) | (tail[index + 1] >> (8 - bit_shift));
            out |= (shifted as u128) << (104 - (index * 8));
        }
    }

    out
}

#[inline(always)]
fn count_leading_zeros(bytes: &[u8; 32]) -> usize {
    let mut count = 0usize;

    for &byte in bytes {
        let zeros = byte.leading_zeros() as usize;
        count += zeros;

        if zeros != 8 {
            break;
        }
    }

    count
}

pub fn format_ipv6(addr: &[u8; 16]) -> Ipv6Addr {
    Ipv6Addr::from(*addr)
}

#[cfg(test)]
mod tests {
    use super::{format_ipv6, pubkey_to_ipv6, pubkey_to_ipv6_u128};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::io::Write;
    use std::net::Ipv6Addr;
    use std::process::{Command, Stdio};
    use std::str::FromStr;

    fn decode_pubkey(hex_pubkey: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex::decode_to_slice(hex_pubkey, &mut out).expect("valid hex pubkey");
        out
    }

    fn run_yggdrasil_with_config(config: &str, flag: &str) -> String {
        let mut child = Command::new("yggdrasil")
            .args(["-useconf", flag])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn yggdrasil");

        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(config.as_bytes())
            .expect("write config");

        let output = child.wait_with_output().expect("wait for yggdrasil");
        assert!(
            output.status.success(),
            "yggdrasil {flag} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        String::from_utf8(output.stdout)
            .expect("utf8 output")
            .trim()
            .to_owned()
    }

    fn read_bit(bytes: &[u8], index: usize) -> u8 {
        if index >= bytes.len() * 8 {
            return 0;
        }

        let byte = bytes[index / 8];
        let shift = 7 - (index % 8);
        (byte >> shift) & 1
    }

    fn write_bit(bytes: &mut [u8], index: usize, bit: u8) {
        if bit == 0 || index >= bytes.len() * 8 {
            return;
        }

        let byte = &mut bytes[index / 8];
        let shift = 7 - (index % 8);
        *byte |= 1 << shift;
    }

    fn reference_pubkey_to_ipv6(pubkey: &[u8; 32]) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0] = super::YGG_ADDRESS_PREFIX;

        let mut leading_zeros = 0usize;
        while leading_zeros < 256 && read_bit(pubkey, leading_zeros) == 0 {
            leading_zeros += 1;
        }

        out[1] = leading_zeros as u8;

        let src_start = (leading_zeros + 1).min(256);
        for bit_index in 0..112 {
            let bit = 1 ^ read_bit(pubkey, src_start + bit_index);
            write_bit(&mut out, 16 + bit_index, bit);
        }

        out
    }

    #[test]
    fn derives_known_vector_from_local_yggdrasil() {
        let pubkey =
            decode_pubkey("3e06bcc898371ffc59fbbe25866838112be13b49c51b75fe240261aaeed71603");
        let derived = pubkey_to_ipv6(&pubkey);

        assert_eq!(
            format_ipv6(&derived).to_string(),
            "202:fca:19bb:3e47:1d:3022:ed3:ccbe"
        );
    }

    #[test]
    fn derive_matches_local_yggdrasil_binary() {
        let probe = Command::new("yggdrasil").arg("-version").output();
        if probe.is_err() {
            return;
        }

        let config_output = Command::new("yggdrasil")
            .args(["-genconf", "-json"])
            .output()
            .expect("generate config");
        assert!(config_output.status.success(), "failed to generate config");

        let config = String::from_utf8(config_output.stdout).expect("utf8 config");
        let pubkey_hex = run_yggdrasil_with_config(&config, "-publickey");
        let addr_text = run_yggdrasil_with_config(&config, "-address");

        let pubkey = decode_pubkey(&pubkey_hex);
        let expected = Ipv6Addr::from_str(&addr_text).expect("valid ipv6").octets();

        assert_eq!(pubkey_to_ipv6(&pubkey), expected);
    }

    #[test]
    fn derive_u128_matches_byte_representation() {
        let pubkey =
            decode_pubkey("3e06bcc898371ffc59fbbe25866838112be13b49c51b75fe240261aaeed71603");
        let bytes = pubkey_to_ipv6(&pubkey);
        let value = pubkey_to_ipv6_u128(&pubkey);

        assert_eq!(value.to_be_bytes(), bytes);
    }

    #[test]
    fn derive_matches_reference_bit_by_bit_implementation() {
        let mut rng = ChaCha20Rng::from_seed([0x42; 32]);

        for _ in 0..4096 {
            let mut pubkey = [0u8; 32];
            rng.fill_bytes(&mut pubkey);

            assert_eq!(pubkey_to_ipv6(&pubkey), reference_pubkey_to_ipv6(&pubkey));
        }
    }

    #[test]
    fn derive_matches_local_yggdrasil_across_multiple_keys() {
        let probe = Command::new("yggdrasil").arg("-version").output();
        if probe.is_err() {
            return;
        }

        for _ in 0..16 {
            let config_output = Command::new("yggdrasil")
                .args(["-genconf", "-json"])
                .output()
                .expect("generate config");
            assert!(config_output.status.success(), "failed to generate config");

            let config = String::from_utf8(config_output.stdout).expect("utf8 config");
            let pubkey_hex = run_yggdrasil_with_config(&config, "-publickey");
            let addr_text = run_yggdrasil_with_config(&config, "-address");

            let pubkey = decode_pubkey(&pubkey_hex);
            let expected = Ipv6Addr::from_str(&addr_text).expect("valid ipv6").octets();

            assert_eq!(pubkey_to_ipv6(&pubkey), expected);
        }
    }
}
