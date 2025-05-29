pub use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_traits::{One, Zero};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};
use base64::prelude::*;

#[derive(Serialize, Deserialize, Debug)]
pub struct RSAPublicKeyExport {
    e: String,
    n: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RSAPrivateKeyExport {
    d: String,
    n: String,
}

pub struct RSA {
    pub public_key: (BigUint, BigUint),  // (e, n)
    pub private_key: (BigUint, BigUint),     // (d, n)
}

impl RSA {
    pub fn export_public_key(&self) -> String {
        let (e, n) = &self.public_key;
        let export = RSAPublicKeyExport {
            e: BASE64_STANDARD.encode(e.to_bytes_be()),
            n: BASE64_STANDARD.encode(n.to_bytes_be()),
        };
        serde_json::to_string(&export).unwrap()
    }

    pub fn export_private_key(&self) -> String {
        let (d, n) = &self.private_key;
        let export = RSAPrivateKeyExport {
            d: BASE64_STANDARD.encode(d.to_bytes_be()),
            n: BASE64_STANDARD.encode(n.to_bytes_be()),
        };
        serde_json::to_string(&export).unwrap()
    }

    pub fn import_public_key(json: &str) -> (BigUint, BigUint) {
        let parsed: RSAPublicKeyExport = serde_json::from_str(json).unwrap();
        let e = BigUint::from_bytes_be(&BASE64_STANDARD.decode(&parsed.e).unwrap());
        let n = BigUint::from_bytes_be(&BASE64_STANDARD.decode(&parsed.n).unwrap());
        (e, n)
    }

    pub fn import_private_key(json: &str) -> (BigUint, BigUint) {
        let parsed: RSAPrivateKeyExport = serde_json::from_str(json).unwrap();
        let d = BigUint::from_bytes_be(&BASE64_STANDARD.decode(&parsed.d).unwrap());
        let n = BigUint::from_bytes_be(&BASE64_STANDARD.decode(&parsed.n).unwrap());
        (d, n)
    }

    pub fn new(bit_len: usize) -> Self {
        let p = generate_prime(bit_len / 2);
        let q = generate_prime(bit_len / 2);

        let n = &p * &q;
        let phi = (&p - BigUint::one()) * (&q - BigUint::one());

        let e = BigUint::from(65537u32);
        let d = ee_modular_inverse(&e, &phi).expect("Failed to compute modular inverse!");

        RSA {
            public_key: (e, n.clone()),
            private_key: (d, n),
        }
    }

    pub fn encrypt(&self, message: &[u8]) -> Vec<u8> {
        let modulus_bytes = ((self.public_key.1.bits() + 7) / 8) as usize;
        let padded = pkcs1_pad(message, modulus_bytes);
        let m = BigUint::from_bytes_be(&padded);
        let (e, n) = &self.public_key;

        let c = m.modpow(e, n);
        let mut ciphertext = c.to_bytes_be();
        while ciphertext.len() < modulus_bytes {
            ciphertext.insert(0, 0);
        }
        ciphertext
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        let (d, n) = &self.private_key;
        let c = BigUint::from_bytes_be(ciphertext);
        let m = c.modpow(d, n);

        let mut padded = m.to_bytes_be();
        let modulus_bytes = ((n.bits() + 7) / 8) as usize;
        while padded.len() < modulus_bytes {
            padded.insert(0, 0);
        }

        pkcs1_unpad(&padded).expect("Invalid padding after decryption")
    }
}

// Miller-Rabin primality test
fn is_prime(n: &BigUint, k: usize) -> bool {
    if n <= &BigUint::one() {
        return false;
    }
    if n <= &BigUint::from(3u32) {
        return true;
    }

    let mut d = n - BigUint::one();
    let mut s = 0;
    while &d % 2u32 == BigUint::zero() {
        d /= 2u32;
        s += 1;
    }

    let mut rng = thread_rng();
    for _ in 0..k {
        let a = rng.gen_biguint_range(&BigUint::from(2u32), &(n - 2u32));
        let mut x = a.modpow(&d, n);
        if x == BigUint::one() || x == n - 1u32 {
            continue;
        }

        let mut is_composite = true;
        for _ in 0..s - 1 {
            x = x.modpow(&BigUint::from(2u32), n);
            if x == n - 1u32 {
                is_composite = false;
                break;
            }
        }

        if is_composite {
            return false;
        }
    }

    true
}

fn generate_prime(bit_length: usize) -> BigUint {
    let mut rng = thread_rng();
    loop {
        let mut num = rng.gen_biguint(bit_length as u64);
        num.set_bit((bit_length as u64) - 1, true); // Garante bit mais alto
        num.set_bit(0, true);              // Garante que é ímpar

        if is_prime(&num, 5) {
            return num;
        }
    }
}

fn ee_modular_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let (mut t, mut new_t) = (BigInt::zero(), BigInt::one());
    let (mut r, mut new_r) = (m.to_bigint().unwrap(), a.to_bigint().unwrap());

    while new_r != BigInt::zero() {
        let quotient = &r / &new_r;

        // Corrigido: calcula antes, depois atualiza
        let temp_t = &t - &quotient * &new_t;
        let temp_r = &r - &quotient * &new_r;

        t = std::mem::replace(&mut new_t, temp_t);
        r = std::mem::replace(&mut new_r, temp_r);
    }

    if r != BigInt::one() {
        return None;
    }

    if t < BigInt::zero() {
        t += m.to_bigint().unwrap();
    }

    Some(t.to_biguint().unwrap())
}


pub fn pkcs1_pad(message: &[u8], modulus_bytes: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    let max_msg_len = modulus_bytes - 11;
    assert!(message.len() <= max_msg_len, "Message too long for RSA modulus");

    let mut padded = vec![0x00, 0x02];
    while padded.len() < modulus_bytes - message.len() - 1 {
        let mut byte = rng.r#gen::<u8>();
        while byte == 0 {
            byte = rng.r#gen();
        }
        padded.push(byte);
    }

    padded.push(0x00);
    padded.extend_from_slice(message);
    padded
}

pub fn pkcs1_unpad(padded: &[u8]) -> Option<Vec<u8>> {
    if padded.len() < 11 || padded[0] != 0x00 || padded[1] != 0x02 {
        return None;
    }

    let mut i = 2;
    while i < padded.len() && padded[i] != 0x00 {
        i += 1;
    }

    if i >= padded.len() {
        return None;
    }

    Some(padded[i + 1..].to_vec())
}
