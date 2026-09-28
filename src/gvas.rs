use crate::crypto::{Crc32, REGISTERED_KEYS};

pub const GVAS_MAGIC: &[u8; 4] = b"GVAS";

const KEY_ID_LEN: usize = 4;
const IV_LEN: usize = 16;
const ENVELOPE_HEADER_LEN: usize = KEY_ID_LEN + IV_LEN;
const AES_BLOCK: usize = 16;
const LEN_PREFIX_LEN: usize = 4;
const PACKED_KEY_SEARCH_WINDOW: usize = 128;
const PROP_TYPE_SEARCH_WINDOW: usize = 64;

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
    pub key_id: [u8; KEY_ID_LEN],
    pub iv: [u8; IV_LEN],
    pub original_length: Option<u32>,
    pub expected_crc32: Option<u32>,
    pub packed: Span,
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
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn starts_with_registered_key(data: &[u8]) -> bool {
    data.get(..KEY_ID_LEN)
        .map_or(false, |id| REGISTERED_KEYS.iter().any(|k| id == k.id))
}

pub struct GvasParser;

impl GvasParser {
    pub fn is_gvas(data: &[u8]) -> bool {
        data.starts_with(GVAS_MAGIC)
    }

    pub fn is_raw_envelope(data: &[u8]) -> bool {
        data.len() >= ENVELOPE_HEADER_LEN && starts_with_registered_key(data)
    }

    pub fn find_packed_data(data: &[u8]) -> Option<Span> {
        if Self::is_raw_envelope(data) {
            return Some(Span {
                offset: 0,
                len: data.len(),
            });
        }
        Self::find_via_packed_data_tag(data).or_else(|| Self::find_via_key_scan(data))
    }

    fn find_via_packed_data_tag(data: &[u8]) -> Option<Span> {
        const TAG: &[u8] = b"PackedData";
        let mut from = 0;

        while let Some(tag_at) = find_subslice(data, TAG, from) {
            let start = tag_at + TAG.len();
            let window_end = (tag_at + PACKED_KEY_SEARCH_WINDOW).min(data.len());

            for k in start..=window_end.saturating_sub(ENVELOPE_HEADER_LEN) {
                if starts_with_registered_key(&data[k..]) {
                    return Some(Self::span_for_envelope_at(data, k));
                }
            }
            from = tag_at + 1;
        }
        None
    }

    fn span_for_envelope_at(data: &[u8], k: usize) -> Span {
        if k >= LEN_PREFIX_LEN {
            if let Some(n) = read_u32_le(data, k - LEN_PREFIX_LEN) {
                let n = n as usize;
                if n >= ENVELOPE_HEADER_LEN && k.saturating_add(n) <= data.len() {
                    return Span { offset: k, len: n };
                }
            }
        }
        let remaining = data.len() - k;
        let rounded = remaining - remaining % AES_BLOCK;
        let len = if rounded >= 2 * AES_BLOCK {
            rounded
        } else {
            remaining
        };
        Span { offset: k, len }
    }

    fn find_via_key_scan(data: &[u8]) -> Option<Span> {
        for i in 0..=data.len().checked_sub(ENVELOPE_HEADER_LEN)? {
            if !starts_with_registered_key(&data[i..]) {
                continue;
            }
            let remaining = data.len() - i;
            if remaining >= ENVELOPE_HEADER_LEN + AES_BLOCK
                && (remaining - ENVELOPE_HEADER_LEN) % AES_BLOCK == 0
            {
                return Some(Span {
                    offset: i,
                    len: remaining,
                });
            }
        }
        None
    }

    pub fn find_u32_property(data: &[u8], name: &[u8]) -> Option<(usize, u32)> {
        const TYPE_TAGS: [&[u8; 8]; 2] = [b"UInt32Pr", b"IntPrope"];
        let mut from = 0;

        while let Some(name_at) = find_subslice(data, name, from) {
            let scan_start = name_at + name.len();
            let scan_end = (name_at + PROP_TYPE_SEARCH_WINDOW).min(data.len());

            for k in scan_start.max(8)..=scan_end.saturating_sub(4) {
                let tag = &data[k - 8..k];
                if TYPE_TAGS.iter().any(|t| tag == &t[..]) {
                    let value_at = k + 17;
                    if let Some(v) = read_u32_le(data, value_at) {
                        return Some((value_at, v));
                    }
                }
            }
            from = name_at + 1;
        }
        None
    }

    fn find_original_length(data: &[u8]) -> Option<(usize, u32)> {
        Self::find_u32_property(data, b"OriginalLength")
            .or_else(|| Self::find_u32_property(data, b"UncompressedLength"))
    }

    pub fn inspect(data: &[u8]) -> anyhow::Result<SaveDataInfo> {
        let packed = Self::find_packed_data(data)
            .ok_or_else(|| anyhow::anyhow!("Could not locate PackedData or a registered key-id signature"))?;
        if packed.len < ENVELOPE_HEADER_LEN {
            return Err(anyhow::anyhow!(
                "PackedData ({} bytes) is shorter than the {}-byte envelope header",
                packed.len,
                ENVELOPE_HEADER_LEN
            ));
        }

        let header = &data[packed.offset..packed.offset + ENVELOPE_HEADER_LEN];
        let mut key_id = [0u8; KEY_ID_LEN];
        let mut iv = [0u8; IV_LEN];
        key_id.copy_from_slice(&header[..KEY_ID_LEN]);
        iv.copy_from_slice(&header[KEY_ID_LEN..]);

        Ok(SaveDataInfo {
            is_gvas: Self::is_gvas(data),
            key_id,
            iv,
            original_length: Self::find_original_length(data).map(|(_, v)| v),
            expected_crc32: Self::find_u32_property(data, b"CRC32").map(|(_, v)| v),
            packed,
        })
    }

    pub fn rebuild_gvas_from_template(
        template: &[u8],
        new_envelope: &[u8],
        plaintext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        if !Self::is_gvas(template) {
            return Err(anyhow::anyhow!("Template is not a valid GVAS save"));
        }

        let packed = Self::inspect(template)?.packed;

        let mut out = Vec::with_capacity(template.len() - packed.len + new_envelope.len());
        out.extend_from_slice(&template[..packed.offset]);
        out.extend_from_slice(new_envelope);
        out.extend_from_slice(&template[packed.end()..]);

        if packed.offset >= LEN_PREFIX_LEN {
            write_u32_le(&mut out, packed.offset - LEN_PREFIX_LEN, new_envelope.len() as u32);
        }

        let (crc_at, _) = Self::find_u32_property(&out, b"CRC32")
            .ok_or_else(|| anyhow::anyhow!("Required property CRC32 not found in template"))?;
        write_u32_le(&mut out, crc_at, Crc32::compute(plaintext));

        let (len_at, _) = Self::find_original_length(&out)
            .ok_or_else(|| anyhow::anyhow!("Required property OriginalLength not found in template"))?;
        write_u32_le(&mut out, len_at, plaintext.len() as u32);

        Ok(out)
    }
}
