use crate::crypto::{Crc32, Crypto, REGISTERED_KEYS};
use crate::gvas::GvasParser;
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
                    return Err("Usage: ace8-savecrypt unpack <input.sav> [output.bin]".to_string());
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
                    return Err("Usage: ace8-savecrypt pack <decrypted.bin> <output.sav> [--template <template.sav>] [--key <MDT1|OMS1|OMS2|OMS3>]".to_string());
                }
                let input = PathBuf::from(&args[2]);
                let output = PathBuf::from(&args[3]);
                let mut template = None;
                let mut key_id = *b"MDT1";

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
                println!("  ace8-savecrypt unpack <input.sav> [output.bin]");
                println!("  ace8-savecrypt pack <decrypted.bin> <output.sav> [--template <template.sav>] [--key <ID>]");
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
                    println!("Key ID:         {}", id_str);
                    println!("Source Hex:     {}", def.hex_source);
                    println!("Derived AES Key: {}", hex_derived);
                    println!();
                }
                Ok(())
            }
            Command::Verify { input } => {
                let data = fs::read(&input)?;
                println!("File:           {}", input.display());
                println!("File Size:      {} bytes", data.len());

                let info = GvasParser::inspect(&data)?;
                let id_str = String::from_utf8_lossy(&info.key_id);
                let iv_str = info.iv.iter().map(|b| format!("{:02x}", b)).collect::<String>();

                println!("Format:         {}", if info.is_gvas { "Unreal Engine 5 GVAS" } else { "Raw PackedData Envelope" });
                println!("Key ID:         {}", id_str);
                println!("IV:             {}", iv_str);
                println!("Envelope Size:  {} bytes (offset 0x{:x})", info.packed.len, info.packed.offset);

                if let Some(exp_len) = info.original_length {
                    println!("Header Length:  {} bytes", exp_len);
                }
                if let Some(exp_crc) = info.expected_crc32 {
                    println!("Header CRC-32:  0x{:08X}", exp_crc);
                }

                let envelope_slice = &data[info.packed.offset..info.packed.end()];
                let unpacked = Crypto::unpack_envelope(envelope_slice)?;
                let computed_crc = Crc32::compute(&unpacked.plaintext);

                println!("Decrypted Size: {} bytes", unpacked.plaintext.len());
                println!("Computed CRC-32: 0x{:08X}", computed_crc);

                if let Some(exp_crc) = info.expected_crc32 {
                    if computed_crc == exp_crc {
                        println!("Verification:   SUCCESS (CRC-32 matched)");
                    } else {
                        println!("Verification:   MISMATCH (Expected 0x{:08X}, Computed 0x{:08X})", exp_crc, computed_crc);
                    }
                } else {
                    println!("Verification:   SUCCESS (PKCS#7 unpadding valid)");
                }

                Ok(())
            }
            Command::Unpack { input, output } => {
                let data = fs::read(&input)?;
                let info = GvasParser::inspect(&data)?;
                let envelope_slice = &data[info.packed.offset..info.packed.end()];
                let unpacked = Crypto::unpack_envelope(envelope_slice)?;

                let out_path = output.unwrap_or_else(|| {
                    let mut p = input.clone();
                    p.set_extension("dec.bin");
                    p
                });

                fs::write(&out_path, &unpacked.plaintext)?;

                let computed_crc = Crc32::compute(&unpacked.plaintext);
                println!("Unpacked:       {} bytes", unpacked.plaintext.len());
                println!("Key ID:         {}", String::from_utf8_lossy(&unpacked.key_id));
                println!("CRC-32:         0x{:08X}", computed_crc);
                println!("Saved to:       {}", out_path.display());
                Ok(())
            }
            Command::Pack {
                input,
                output,
                template,
                key_id,
            } => {
                let plaintext = fs::read(&input)?;
                let new_envelope = Crypto::pack_envelope(&plaintext, &key_id, None)?;

                if let Some(tpl_path) = template {
                    let tpl_data = fs::read(&tpl_path)?;
                    let final_sav = GvasParser::rebuild_gvas_from_template(&tpl_data, &new_envelope, &plaintext)?;
                    fs::write(&output, final_sav)?;
                    println!("Rebuilt GVAS:   {} bytes", output.display());
                } else {
                    fs::write(&output, &new_envelope)?;
                    println!("Packed Envelope: {} bytes", output.display());
                }

                let computed_crc = Crc32::compute(&plaintext);
                println!("Key ID:         {}", String::from_utf8_lossy(&key_id));
                println!("CRC-32:         0x{:08X}", computed_crc);
                println!("Saved to:       {}", output.display());
                Ok(())
            }
        }
    }
}
