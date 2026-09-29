use base64::prelude::*;
use crate::crypto::{compute_payload_crc, crc32, REGISTERED_KEYS};
use serde::{Deserialize, Serialize};

pub const GVAS_MAGIC: &[u8; 4] = b"GVAS";

const KEY_ID_LEN: usize = 4;
const IV_LEN: usize = 16;
const ENVELOPE_HEADER_LEN: usize = KEY_ID_LEN + IV_LEN;
const AES_BLOCK: usize = 16;
const PROP_SCAN_LIMIT: usize = 128;

#[derive(Debug, Clone, Copy)]
pub struct Span {
    pub offset: usize,
    pub len: usize,
}

impl Span {
    pub fn end(self) -> usize {
        self.offset + self.len
    }
}

#[derive(Debug)]
pub struct SaveDataInfo {
    pub is_gvas: bool,
    pub is_encrypted: bool,
    pub key_id: Option<[u8; KEY_ID_LEN]>,
    pub iv: Option<[u8; IV_LEN]>,
    pub original_length: Option<u32>,
    pub expected_crc32: Option<u32>,
    pub packed: Option<Span>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullSaveJson {
    pub file_type: String,
    pub class_name: String,
    pub header_b64: String,
    pub tail_b64: String,
    pub payload_b64: String,
    pub payload_size: usize,
}

fn find_subslice(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

fn read_u32_le(data: &[u8], at: usize) -> Option<u32> {
    let bytes = data.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn write_u32_le(data: &mut [u8], at: usize, value: u32) {
    if at + 4 <= data.len() {
        data[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
}

fn starts_with_registered_key(data: &[u8]) -> bool {
    data.get(..KEY_ID_LEN)
        .map_or(false, |id| REGISTERED_KEYS.iter().any(|k| id == k.id))
}

pub fn encode_b64(input: &[u8]) -> String {
    BASE64_STANDARD.encode(input)
}

pub fn decode_b64(input: &str) -> anyhow::Result<Vec<u8>> {
    BASE64_STANDARD.decode(input.trim())
        .map_err(|e| anyhow::anyhow!("Invalid base64: {}", e))
}

pub struct GvasParser;

impl GvasParser {
    pub fn is_gvas(data: &[u8]) -> bool {
        data.starts_with(GVAS_MAGIC)
    }

    pub fn is_raw_envelope(data: &[u8]) -> bool {
        data.len() >= ENVELOPE_HEADER_LEN && starts_with_registered_key(data)
    }

    fn validate_envelope_span(data: &[u8], offset: usize) -> Option<Span> {
        if !starts_with_registered_key(data.get(offset..)?) {
            return None;
        }

        if offset >= 4 {
            if let Some(arr_len) = read_u32_le(data, offset - 4).map(|n| n as usize) {
                if arr_len >= ENVELOPE_HEADER_LEN
                    && (arr_len - ENVELOPE_HEADER_LEN) % AES_BLOCK == 0
                    && offset + arr_len <= data.len()
                {
                    return Some(Span { offset, len: arr_len });
                }
            }
        }

        let remaining = data.len().saturating_sub(offset);
        if remaining >= ENVELOPE_HEADER_LEN && (remaining - ENVELOPE_HEADER_LEN) % AES_BLOCK == 0 {
            Some(Span { offset, len: remaining })
        } else {
            None
        }
    }

    pub fn find_packed_data(data: &[u8]) -> Option<Span> {
        if Self::is_raw_envelope(data) {
            return Some(Span {
                offset: 0,
                len: data.len(),
            });
        }

        const TAGS: [&[u8]; 2] = [b"BinaryData\0", b"PackedData\0"];
        for tag in TAGS {
            let mut from = 0;
            while let Some(tag_at) = find_subslice(data, tag, from) {
                from = tag_at + 1;
                let start = tag_at + tag.len();
                let end = (tag_at + PROP_SCAN_LIMIT).min(data.len());
                for k in start..end {
                    if let Some(span) = Self::validate_envelope_span(data, k) {
                        return Some(span);
                    }
                }
            }
        }

        for i in 4..=data.len().saturating_sub(ENVELOPE_HEADER_LEN) {
            if let Some(span) = Self::validate_envelope_span(data, i) {
                return Some(span);
            }
        }

        None
    }

    pub fn find_raw_packed_blob(data: &[u8]) -> Option<Span> {
        let tag_at = find_subslice(data, b"PackedData\0", 0)?;
        let bp = find_subslice(data, b"ByteProperty\0", tag_at)?;
        let after = bp + 13;
        let arr_len = read_u32_le(data, after.checked_add(9)?)? as usize;
        let payload_start = after + 13;

        if payload_start.checked_add(arr_len)? <= data.len() {
            Some(Span {
                offset: payload_start,
                len: arr_len,
            })
        } else {
            None
        }
    }

    pub fn find_u32_property(data: &[u8], name: &[u8]) -> Option<(usize, u32)> {
        let mut name_buf = Vec::with_capacity(name.len() + 1);
        name_buf.extend_from_slice(name);
        name_buf.push(0);

        let mut from = 0;
        while let Some(pos) = find_subslice(data, &name_buf, from) {
            from = pos + 1;
            let scan_end = (pos + 128).min(data.len());
            let Some(prop_pos) = find_subslice(&data[..scan_end], b"Property\0", pos) else {
                continue;
            };

            let type_end = prop_pos + 9;
            let max_k = (type_end + 16).min(data.len().saturating_sub(5));
            for k in type_end..=max_k {
                if data[k..k + 4] != [4, 0, 0, 0] {
                    continue;
                }
                let val_pos = k + 5;
                if let Some(v) = read_u32_le(data, val_pos) {
                    return Some((val_pos, v));
                }
            }
        }
        None
    }

    pub fn find_payload_size(data: &[u8]) -> Option<(usize, u32)> {
        Self::find_u32_property(data, b"BinaryBodySize")
            .or_else(|| Self::find_u32_property(data, b"OriginalLength"))
            .or_else(|| Self::find_u32_property(data, b"UncompressedLength"))
    }

    pub fn find_expected_crc(data: &[u8]) -> Option<(usize, u32)> {
        Self::find_u32_property(data, b"Crc")
            .or_else(|| Self::find_u32_property(data, b"CRC32"))
            .or_else(|| Self::find_u32_property(data, b"Checksum"))
    }

    pub fn inspect(data: &[u8]) -> anyhow::Result<SaveDataInfo> {
        let is_gvas = Self::is_gvas(data);
        let packed_span = Self::find_packed_data(data);

        if let Some(packed) = packed_span {
            let header = &data[packed.offset..packed.offset + ENVELOPE_HEADER_LEN];
            let mut key_id = [0u8; KEY_ID_LEN];
            let mut iv = [0u8; IV_LEN];
            key_id.copy_from_slice(&header[..KEY_ID_LEN]);
            iv.copy_from_slice(&header[KEY_ID_LEN..]);

            Ok(SaveDataInfo {
                is_gvas,
                is_encrypted: true,
                key_id: Some(key_id),
                iv: Some(iv),
                original_length: Self::find_payload_size(data).map(|(_, v)| v),
                expected_crc32: Self::find_expected_crc(data).map(|(_, v)| v),
                packed: Some(packed),
            })
        } else if is_gvas {
            Ok(SaveDataInfo {
                is_gvas: true,
                is_encrypted: false,
                key_id: None,
                iv: None,
                original_length: None,
                expected_crc32: Self::find_expected_crc(data).map(|(_, v)| v),
                packed: Self::find_raw_packed_blob(data),
            })
        } else {
            Err(anyhow::anyhow!("File is neither a recognized GVAS save nor an encrypted save envelope"))
        }
    }

    pub fn export_full_save_json(data: &[u8]) -> anyhow::Result<FullSaveJson> {
        if !Self::is_gvas(data) {
            return Err(anyhow::anyhow!("File is not a GVAS save"));
        }

        let info = Self::inspect(data)?;
        let span = info.packed
            .ok_or_else(|| anyhow::anyhow!("Could not locate PackedData or BinaryData in GVAS file"))?;

        let header_slice = &data[..span.offset];
        let payload_slice = &data[span.offset..span.end()];
        let tail_slice = &data[span.end()..];

        let class_name = if let Some(p) = find_subslice(data, b"/Script/", 0) {
            let end = find_subslice(data, b"\0", p).unwrap_or(p + 32);
            String::from_utf8_lossy(&data[p..end]).to_string()
        } else {
            "UnknownSaveGame".to_string()
        };

        Ok(FullSaveJson {
            file_type: if info.is_encrypted { "EncryptedGVAS".to_string() } else { "PlaintextGVAS".to_string() },
            class_name,
            header_b64: encode_b64(header_slice),
            tail_b64: encode_b64(tail_slice),
            payload_b64: encode_b64(payload_slice),
            payload_size: payload_slice.len(),
        })
    }

    pub fn rebuild_from_header_tail(
        header: &[u8],
        tail: &[u8],
        new_payload: &[u8],
        plaintext: Option<&[u8]>,
    ) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(header.len() + new_payload.len() + tail.len());
        out.extend_from_slice(header);
        let payload_offset = out.len();
        out.extend_from_slice(new_payload);
        let tail_offset = out.len();
        out.extend_from_slice(tail);

        if payload_offset >= 4 {
            write_u32_le(&mut out, payload_offset - 4, new_payload.len() as u32);
        }
        if payload_offset >= 9 {
            write_u32_le(&mut out, payload_offset - 9, (new_payload.len() + 4) as u32);
        }

        if let Some(plain) = plaintext {
            if let Some((pos, _)) = Self::find_payload_size(&out[tail_offset..]) {
                write_u32_le(&mut out, tail_offset + pos, plain.len() as u32);
            }
            if let Some((pos, _)) = Self::find_u32_property(&out[tail_offset..], b"Crc") {
                let computed = compute_payload_crc(plain);
                write_u32_le(&mut out, tail_offset + pos, computed);
            } else if let Some((pos, _)) = Self::find_u32_property(&out[tail_offset..], b"CRC32") {
                let computed = crc32(plain);
                write_u32_le(&mut out, tail_offset + pos, computed);
            }
        }

        Ok(out)
    }

    pub fn rebuild_gvas_from_template(
        template: &[u8],
        new_envelope: &[u8],
        plaintext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        if !Self::is_gvas(template) {
            return Err(anyhow::anyhow!("Template is not a valid GVAS save"));
        }

        let info = Self::inspect(template)?;
        let packed = info.packed
            .ok_or_else(|| anyhow::anyhow!("Template GVAS does not contain an envelope or packed data to replace"))?;

        let header = &template[..packed.offset];
        let tail = &template[packed.end()..];

        Self::rebuild_from_header_tail(header, tail, new_envelope, Some(plaintext))
    }
}
