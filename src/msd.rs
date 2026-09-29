use base64::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsdManifestFile {
    pub name: String,
    pub version: String,
    pub hash: String,
    pub path: String,
    pub size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsdManifest {
    pub key_id: String,
    pub original_iv_hex: String,
    pub header_b64: Option<String>,
    pub tail_b64: Option<String>,
    pub files: Vec<MsdManifestFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawFileItem {
    pub name: String,
    pub version: String,
    pub hash: String,
    pub path: String,
    pub size: usize,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawPayloadRoot {
    pub files: Vec<RawFileItem>,
}

pub struct MsdManager;

impl MsdManager {
    pub fn is_msd_payload(payload: &[u8]) -> bool {
        if let Ok(text) = std::str::from_utf8(payload) {
            text.contains("\"files\"") && text.contains(".csv")
        } else {
            false
        }
    }

    pub fn unpack(
        payload_bytes: &[u8],
        key_id: [u8; 4],
        iv: [u8; 16],
        header: Option<&[u8]>,
        tail: Option<&[u8]>,
        out_dir: &Path,
    ) -> anyhow::Result<usize> {
        let text = std::str::from_utf8(payload_bytes)?;
        let root: RawPayloadRoot = serde_json::from_str(text)?;

        fs::create_dir_all(out_dir)?;

        let mut manifest_files = Vec::with_capacity(root.files.len());
        for item in &root.files {
            let file_path = out_dir.join(&item.name);
            fs::write(&file_path, item.body.as_bytes())?;

            manifest_files.push(MsdManifestFile {
                name: item.name.clone(),
                version: item.version.clone(),
                hash: item.hash.clone(),
                path: item.path.clone(),
                size: item.size,
            });
        }

        let manifest = MsdManifest {
            key_id: String::from_utf8_lossy(&key_id).to_string(),
            original_iv_hex: iv.iter().map(|b| format!("{:02x}", b)).collect(),
            header_b64: header.map(|h| BASE64_STANDARD.encode(h)),
            tail_b64: tail.map(|t| BASE64_STANDARD.encode(t)),
            files: manifest_files,
        };

        let manifest_json = serde_json::to_string_pretty(&manifest)?;
        fs::write(out_dir.join("manifest.json"), manifest_json)?;

        Ok(root.files.len())
    }

    pub fn pack(
        dir: &Path,
    ) -> anyhow::Result<(Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>, [u8; 4])> {
        let manifest_path = dir.join("manifest.json");
        let manifest_str = fs::read_to_string(&manifest_path)?;
        let manifest: MsdManifest = serde_json::from_str(&manifest_str)?;

        let mut key_id = *b"OMS1";
        let k_bytes = manifest.key_id.as_bytes();
        if k_bytes.len() == 4 {
            key_id.copy_from_slice(k_bytes);
        }

        let header = manifest
            .header_b64
            .as_deref()
            .map(|b64| BASE64_STANDARD.decode(b64.trim()))
            .transpose()?;

        let tail = manifest
            .tail_b64
            .as_deref()
            .map(|b64| BASE64_STANDARD.decode(b64.trim()))
            .transpose()?;

        let mut raw_files = Vec::with_capacity(manifest.files.len());
        for item in &manifest.files {
            let file_path = dir.join(&item.name);
            let body = fs::read_to_string(&file_path)
                .map_err(|e| anyhow::anyhow!("Could not read table file '{}': {}", item.name, e))?;

            let mut hasher = Sha256::new();
            hasher.update(body.as_bytes());
            let hash_bytes = hasher.finalize();
            let hash_hex = format!("{:x}", hash_bytes);

            raw_files.push(RawFileItem {
                name: item.name.clone(),
                version: item.version.clone(),
                hash: hash_hex,
                path: item.path.clone(),
                size: body.as_bytes().len(),
                body,
            });
        }

        let root = RawPayloadRoot { files: raw_files };
        let json_bytes = serde_json::to_vec(&root)?;

        Ok((json_bytes, header, tail, key_id))
    }
}