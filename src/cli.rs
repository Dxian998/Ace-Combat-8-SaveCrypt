use crate::crypto::{compute_payload_crc, Crypto, REGISTERED_KEYS};
use crate::gvas::{decode_b64, FullSaveJson, GvasParser};
use crate::msd::MsdManager;
use std::fs;
use std::path::PathBuf;

pub enum Command {
    Unpack {
        input: PathBuf,
        output: Option<PathBuf>,
    },
    Pack {
        input: PathBuf,
        output: PathBuf,
        template: Option<PathBuf>,
        key_id: [u8; 4],
    },
    Verify {
        input: PathBuf,
    },
    Keys,
    Help,
}

pub struct Cli;

impl Cli {
    pub fn parse() -> Result<Command, String> {
        let args: Vec<String> = std::env::args().collect();
        if args.len() < 2 {
            return Ok(Command::Help);
        }

        match args[1].as_str() {
            "unpack" | "-u" | "--unpack" | "decrypt" | "-d" => {
                if args.len() < 3 {
                    return Err("Usage: ace8-savecrypt unpack <input.sav> [output_dir_or_file]".to_string());
                }
                let input = PathBuf::from(&args[2]);
                let output = if args.len() >= 4 {
                    Some(PathBuf::from(&args[3]))
                } else {
                    None
                };
                Ok(Command::Unpack { input, output })
            }
            "pack" | "-p" | "--pack" | "encrypt" | "-e" => {
                if args.len() < 4 {
                    return Err("Usage: ace8-savecrypt pack <mod_dir_or_json> <output.sav> [--template <template.sav>] [--key <ID>]".to_string());
                }
                let input = PathBuf::from(&args[2]);
                let output = PathBuf::from(&args[3]);
                let mut template = None;
                let mut key_id = *b"OMS1";

                let mut idx = 4;
                while idx < args.len() {
                    match args[idx].as_str() {
                        "--template" | "-t" => {
                            if idx + 1 >= args.len() {
                                return Err("Missing value for --template".to_string());
                            }
                            template = Some(PathBuf::from(&args[idx + 1]));
                            idx += 2;
                        }
                        "--key" | "-k" => {
                            if idx + 1 >= args.len() {
                                return Err("Missing value for --key".to_string());
                            }
                            let k_bytes = args[idx + 1].as_bytes();
                            if k_bytes.len() != 4 {
                                return Err("Key ID must be exactly 4 ASCII characters (e.g. MDT1, OMS1, OMS2, OMS3)".to_string());
                            }
                            key_id.copy_from_slice(k_bytes);
                            idx += 2;
                        }
                        other => {
                            return Err(format!("Unknown option: {}", other));
                        }
                    }
                }

                Ok(Command::Pack {
                    input,
                    output,
                    template,
                    key_id,
                })
            }
            "verify" | "-v" | "--verify" | "info" | "-i" => {
                if args.len() < 3 {
                    return Err("Usage: ace8-savecrypt verify <input.sav>".to_string());
                }
                let input = PathBuf::from(&args[2]);
                Ok(Command::Verify { input })
            }
            "keys" | "--keys" | "-k" => Ok(Command::Keys),
            "help" | "--help" | "-h" => Ok(Command::Help),
            other => Err(format!("Unknown command: '{}'. Run 'ace8-savecrypt help' for usage.", other)),
        }
    }

    pub fn run() -> anyhow::Result<()> {
        let cmd = match Self::parse() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        };

        match cmd {
            Command::Help => {
                println!("ace8-savecrypt - Ace Combat 8 Save Cryptography Toolkit");
                println!();
                println!("Usage:");
                println!("  ace8-savecrypt unpack <input.sav> [output_dir_or_file]");
                println!("  ace8-savecrypt pack <mod_dir_or_json> <output.sav> [--template <template.sav>] [--key <ID>]");
                println!("  ace8-savecrypt verify <input.sav>");
                println!("  ace8-savecrypt keys");
                println!();
                println!("Supported Key IDs: MDT1, OMS1, OMS2, OMS3");
                Ok(())
            }
            Command::Keys => {
                println!("Ace Combat 8 Cryptographic Key Table:");
                println!();
                for def in REGISTERED_KEYS {
                    let id_str = String::from_utf8_lossy(&def.id);
                    let derived = Crypto::derive_key(def.hex_source)?;
                    let hex_derived = derived.iter().map(|b| format!("{:02x}", b)).collect::<String>();
                    println!("Key ID:          {}", id_str);
                    println!("Source Hex:      {}", def.hex_source);
                    println!("Derived AES Key: {}", hex_derived);
                    println!();
                }
                Ok(())
            }
            Command::Verify { input } => {
                let data = fs::read(&input)?;
                println!("File:            {}", input.display());
                println!("File Size:       {} bytes", data.len());

                let info = GvasParser::inspect(&data)?;
                if !info.is_encrypted {
                    println!("Format:          Unreal Engine 5 GVAS");
                    println!("Encryption:      None (Standard Unencrypted UE5 Save)");
                    if let Some(p) = info.packed {
                        println!("PackedData Size: {} bytes (offset 0x{:x})", p.len, p.offset);
                    }
                    if let Some(exp_crc) = info.expected_crc32 {
                        println!("Header Checksum: 0x{:08X}", exp_crc);
                    }
                    println!("Verification:    SUCCESS (Valid unencrypted GVAS container)");
                    return Ok(());
                }

                let packed = info.packed
                    .ok_or_else(|| anyhow::anyhow!("Failed to locate encrypted envelope"))?;
                let key_id = info.key_id.unwrap_or_default();
                let iv = info.iv.unwrap_or_default();

                let id_str = String::from_utf8_lossy(&key_id);
                let iv_str = iv.iter().map(|b| format!("{:02x}", b)).collect::<String>();

                println!("Format:          {}", if info.is_gvas { "Unreal Engine 5 GVAS" } else { "Raw Save Envelope" });
                println!("Key ID:          {}", id_str);
                println!("IV:              {}", iv_str);
                println!("Envelope Size:   {} bytes (offset 0x{:x})", packed.len, packed.offset);

                if let Some(exp_len) = info.original_length {
                    println!("Header Length:   {} bytes", exp_len);
                }
                if let Some(exp_crc) = info.expected_crc32 {
                    println!("Header CRC-32:   0x{:08X}", exp_crc);
                }

                let envelope_slice = &data[packed.offset..packed.end()];
                let unpacked = Crypto::unpack_envelope(envelope_slice)?;
                let computed_crc = compute_payload_crc(&unpacked.plaintext);

                println!("Decrypted Size:  {} bytes", unpacked.plaintext.len());
                println!("Computed CRC-32: 0x{:08X}", computed_crc);

                if let Some(exp_crc) = info.expected_crc32 {
                    let (valid, matched_crc) = Crypto::validate_crc(exp_crc, &unpacked.plaintext);
                    if valid {
                        println!("Verification:    SUCCESS (CRC-32 0x{:08X} matched)", matched_crc);
                    } else {
                        println!("Verification:    MISMATCH (Expected 0x{:08X}, Computed 0x{:08X})", exp_crc, computed_crc);
                    }
                } else {
                    println!("Verification:    SUCCESS (PKCS#7 unpadding valid)");
                }

                Ok(())
            }
            Command::Unpack { input, output } => {
                let data = fs::read(&input)?;
                let info = GvasParser::inspect(&data)?;

                if info.is_encrypted {
                    let packed = info.packed
                        .ok_or_else(|| anyhow::anyhow!("Failed to locate encrypted envelope"))?;
                    let envelope_slice = &data[packed.offset..packed.end()];
                    let unpacked = Crypto::unpack_envelope(envelope_slice)?;

                    if MsdManager::is_msd_payload(&unpacked.plaintext) {
                        let stem = input.file_stem().and_then(|s| s.to_str()).unwrap_or("msd_data");
                        let out_dir = output.unwrap_or_else(|| PathBuf::from(stem));
                        let header_part = Some(&data[..packed.offset]);
                        let tail_part = Some(&data[packed.end()..]);

                        let count = MsdManager::unpack(
                            &unpacked.plaintext,
                            unpacked.key_id,
                            unpacked.iv,
                            header_part,
                            tail_part,
                            &out_dir,
                        )?;

                        let computed_crc = compute_payload_crc(&unpacked.plaintext);
                        println!("Unpacked MSD:    {} CSV data tables", count);
                        println!("Key ID:          {}", String::from_utf8_lossy(&unpacked.key_id));
                        println!("CRC-32:          0x{:08X}", computed_crc);
                        println!("Extracted to:    {}", out_dir.display());
                        println!("Notice:          Header and metadata saved into manifest.json. Can be repacked without template.");
                        return Ok(());
                    }

                    let out_path = output.unwrap_or_else(|| {
                        let mut p = input.clone();
                        p.set_extension("dec.bin");
                        p
                    });

                    fs::write(&out_path, &unpacked.plaintext)?;
                    let computed_crc = compute_payload_crc(&unpacked.plaintext);
                    println!("Unpacked:        {} bytes", unpacked.plaintext.len());
                    println!("Key ID:          {}", String::from_utf8_lossy(&unpacked.key_id));
                    println!("CRC-32:          0x{:08X}", computed_crc);
                    println!("Saved to:        {}", out_path.display());
                    return Ok(());
                }

                let full_json = GvasParser::export_full_save_json(&data)?;
                let out_json_path = output.unwrap_or_else(|| {
                    let mut p = input.clone();
                    p.set_extension("full.json");
                    p
                });

                let json_str = serde_json::to_string_pretty(&full_json)?;
                fs::write(&out_json_path, json_str)?;

                if let Some(span) = info.packed {
                    let mut bin_path = out_json_path.clone();
                    bin_path.set_extension("packed.bin");
                    fs::write(&bin_path, &data[span.offset..span.end()])?;
                    println!("Exported Blob:   {} ({} bytes)", bin_path.display(), span.len);
                }

                println!("Unpacked GVAS:   Preserved full container with headers");
                println!("Save Class:      {}", full_json.class_name);
                println!("Saved to:        {}", out_json_path.display());
                println!("Notice:          Header and metadata preserved. Can be repacked without template.");
                Ok(())
            }
            Command::Pack {
                input,
                output,
                template,
                key_id,
            } => {
                if input.is_dir() {
                    let (payload_bytes, stored_header, stored_tail, msd_key_id) = MsdManager::pack(&input)?;
                    let active_key_id = if key_id != *b"OMS1" { key_id } else { msd_key_id };
                    let new_envelope = Crypto::pack_envelope(&payload_bytes, &active_key_id, None)?;

                    if let Some(tpl_path) = template {
                        let tpl_data = fs::read(&tpl_path)?;
                        let final_sav = GvasParser::rebuild_gvas_from_template(&tpl_data, &new_envelope, &payload_bytes)?;
                        fs::write(&output, final_sav)?;
                        println!("Rebuilt GVAS:    {} (using template {})", output.display(), tpl_path.display());
                    } else if let (Some(h), Some(t)) = (stored_header, stored_tail) {
                        let final_sav = GvasParser::rebuild_from_header_tail(&h, &t, &new_envelope, Some(&payload_bytes))?;
                        fs::write(&output, final_sav)?;
                        println!("Rebuilt GVAS:    {} (direct from manifest, no template needed)", output.display());
                    } else {
                        return Err(anyhow::anyhow!("No template specified and directory manifest has no embedded header. Use --template <save.sav>"));
                    }

                    let computed_crc = compute_payload_crc(&payload_bytes);
                    println!("Key ID:          {}", String::from_utf8_lossy(&active_key_id));
                    println!("CRC-32:          0x{:08X}", computed_crc);
                    println!("Saved to:        {}", output.display());
                    return Ok(());
                }

                if input.extension().map_or(false, |ext| ext == "json") {
                    let content = fs::read_to_string(&input)?;
                    if let Ok(full_json) = serde_json::from_str::<FullSaveJson>(&content) {
                        let header = decode_b64(&full_json.header_b64)?;
                        let tail = decode_b64(&full_json.tail_b64)?;
                        let payload = decode_b64(&full_json.payload_b64)?;

                        let final_sav = GvasParser::rebuild_from_header_tail(&header, &tail, &payload, None)?;
                        fs::write(&output, final_sav)?;
                        println!("Rebuilt GVAS:    {} (direct from full save JSON, no template needed)", output.display());
                        println!("Save Class:      {}", full_json.class_name);
                        return Ok(());
                    }
                }

                let plaintext = fs::read(&input)?;
                let new_envelope = Crypto::pack_envelope(&plaintext, &key_id, None)?;

                if let Some(tpl_path) = template {
                    let tpl_data = fs::read(&tpl_path)?;
                    let final_sav = GvasParser::rebuild_gvas_from_template(&tpl_data, &new_envelope, &plaintext)?;
                    fs::write(&output, final_sav)?;
                    println!("Rebuilt GVAS:    {}", output.display());
                } else {
                    fs::write(&output, &new_envelope)?;
                    println!("Packed Envelope: {}", output.display());
                }

                let computed_crc = compute_payload_crc(&plaintext);
                println!("Key ID:          {}", String::from_utf8_lossy(&key_id));
                println!("CRC-32:          0x{:08X}", computed_crc);
                println!("Saved to:        {}", output.display());
                Ok(())
            }
        }
    }
}
