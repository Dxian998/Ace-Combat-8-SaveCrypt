use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use std::time::{SystemTime, UNIX_EPOCH};

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

pub const MASTER_MASK: [u64; 4] = [
    0xD7C530E7F21A222B,
    0x8427BF01697C154B,
    0x684CA677CE91C9C3,
    0xDED0FA84367C6D7F,
];

pub struct KeyDefinition {
    pub id: [u8; 4],
    pub hex_source: &'static str,
}

pub const REGISTERED_KEYS: &[KeyDefinition] = &[
    KeyDefinition {
        id: *b"MDT1",
        hex_source: "c34c071add6587cfd23f712f0edfb4fce66a3448113ca935d2dcafc379e5cbcf",
    },
    KeyDefinition {
        id: *b"OMS1",
        hex_source: "3f90e67a88e37621cef38a6dbb87a5d27f4b16aa46bb4884b2411d956bc46ce5",
    },
    KeyDefinition {
        id: *b"OMS2",
        hex_source: "6148bc952e860a58c3113f038757e536a53cf97bc66ee470deebd24e5d82642d",
    },
    KeyDefinition {
        id: *b"OMS3",
        hex_source: "adef4805fef7f727938e7829a231bf8db2034033c5a3936d4ba3bbaf00a89081",
    },
];

pub struct UnpackedEnvelope {
    pub key_id: [u8; 4],
    pub iv: [u8; 16],
    pub plaintext: Vec<u8>,
}

pub struct Crypto;

impl Crypto {
    pub fn derive_key(hex_str: &str) -> anyhow::Result<[u8; 32]> {
        if hex_str.len() != 64 {
            return Err(anyhow::anyhow!("Key source string must be exactly 64 hex characters"));
        }

        let q0 = u64::from_str_radix(&hex_str[0..16], 16)?;
        let q1 = u64::from_str_radix(&hex_str[16..32], 16)?;
        let q2 = u64::from_str_radix(&hex_str[32..48], 16)?;
        let q3 = u64::from_str_radix(&hex_str[48..64], 16)?;

        let w0 = q1 ^ MASTER_MASK[0];
        let w1 = q0 ^ MASTER_MASK[1];
        let w2 = q3 ^ MASTER_MASK[2];
        let w3 = q2 ^ MASTER_MASK[3];

        let derived_hex = format!("{:016x}{:016x}{:016x}{:016x}", w0, w1, w2, w3);

        let mut key = [0u8; 32];
        for i in 0..32 {
            key[i] = u8::from_str_radix(&derived_hex[i * 2..i * 2 + 2], 16)?;
        }

        Ok(key)
    }

    pub fn get_key_for_id(key_id: &[u8; 4]) -> Option<[u8; 32]> {
        for def in REGISTERED_KEYS {
            if &def.id == key_id {
                return Self::derive_key(def.hex_source).ok();
            }
        }
        None
    }

    pub fn gen_iv() -> [u8; 16] {
        let mut iv = [0u8; 16];
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut state = (now ^ 0x517CC1B727220A95) as u64;
        for chunk in iv.chunks_exact_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            chunk.copy_from_slice(&state.to_le_bytes());
        }
        iv
    }

    pub fn decrypt_cbc(ciphertext: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> anyhow::Result<Vec<u8>> {
        Aes256CbcDec::new(key.into(), iv.into())
            .decrypt_padded_vec::<Pkcs7>(ciphertext)
            .map_err(|_| anyhow::anyhow!("Invalid ciphertext length or PKCS7 padding"))
    }

    pub fn encrypt_cbc(plaintext: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
        Aes256CbcEnc::new(key.into(), iv.into()).encrypt_padded_vec::<Pkcs7>(plaintext)
    }

    pub fn unpack_envelope(data: &[u8]) -> anyhow::Result<UnpackedEnvelope> {
        if data.len() < 20 {
            return Err(anyhow::anyhow!("Envelope length is less than minimum 20 bytes"));
        }

        let mut key_id = [0u8; 4];
        key_id.copy_from_slice(&data[0..4]);

        let mut iv = [0u8; 16];
        iv.copy_from_slice(&data[4..20]);

        let ciphertext = &data[20..];
        let key = Self::get_key_for_id(&key_id)
            .ok_or_else(|| anyhow::anyhow!("Unsupported or unknown Key ID: {:?}", String::from_utf8_lossy(&key_id)))?;

        let plaintext = Self::decrypt_cbc(ciphertext, &key, &iv)?;

        Ok(UnpackedEnvelope {
            key_id,
            iv,
            plaintext,
        })
    }

    pub fn pack_envelope(plaintext: &[u8], key_id: &[u8; 4], custom_iv: Option<[u8; 16]>) -> anyhow::Result<Vec<u8>> {
        let key = Self::get_key_for_id(key_id)
            .ok_or_else(|| anyhow::anyhow!("Unsupported Key ID: {:?}", String::from_utf8_lossy(key_id)))?;

        let iv = custom_iv.unwrap_or_else(Self::gen_iv);
        let ciphertext = Self::encrypt_cbc(plaintext, &key, &iv);

        let mut envelope = Vec::with_capacity(4 + 16 + ciphertext.len());
        envelope.extend_from_slice(key_id);
        envelope.extend_from_slice(&iv);
        envelope.extend_from_slice(&ciphertext);

        Ok(envelope)
    }
}

pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

pub struct Crc32;

impl Crc32 {
    pub fn compute(data: &[u8]) -> u32 {
        crc32fast::hash(data)
    }
}
