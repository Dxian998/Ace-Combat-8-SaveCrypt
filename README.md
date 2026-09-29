# ACE-COMBAT-8-savecrypt

Toolkit & reference implementation for inspecting, decrypting, and repacking saves for **Ace Combat 8** (UE5).

---

### Foreword

Coming from Ace Combat 7 (where saves were encrypted with an AES key derived from your SteamID and was under the file `ACE), Ace Combat 8 changed its save architecture:

- **Campaign & System Saves (`Campaign.sav`, `System.sav`, `OnlineAccount.sav`)**:
  Standard UE5 GVAS saves. They have **zero SteamID locking or encryption**. You can share campaign saves directly between different accounts without any tool. Their `PackedData` property is an unencrypted byte blob storing serialized structs (unlocked aircraft tree, skins, medals, emblems, playtime).
- **Online Service Data (`OnlineLocalCacheMSD_0.sav`)**:
  The **only** encrypted file. It is a live-service cache containing 129 data tables (`DT_Ability.csv`, `DT_ItemCatalog.csv`, aircraft upgrade trees, parts, shop parameters). Encrypted with AES-256-CBC using static key `OMS1`, PKCS7 padding, and verified using an internal engine CRC-32 table.

---

### CLI Usage

#### 1. Verify Save Files
Inspect any save file (whether encrypted MSD or plaintext GVAS), validate IVs, ciphertext padding, and verify CRCs:
```bash
ace8-savecrypt verify SaveGames/OnlineLocalCacheMSD_0.sav
ace8-savecrypt verify SaveGames/Campaign.sav
```

Example output:
```text
File:            SaveGames/OnlineLocalCacheMSD_0.sav
File Size:       4917258 bytes
Format:          Unreal Engine 5 GVAS
Key ID:          OMS1
IV:              768142d4b59317c2f1e3e3e6c1323d61
Envelope Size:   4914996 bytes (offset 0x865)
Header Length:   4914963 bytes
Header CRC-32:   0x5FFB4080
Decrypted Size:  4914963 bytes
Computed CRC-32: 0x5FFB4080
Verification:    SUCCESS (CRC-32 0x5FFB4080 matched)
```

#### 2. Unpack Online Master Service Data (All 129 CSV Tables)
Unpack the encrypted master cache into a folder of CSV spreadsheets:
```bash
ace8-savecrypt unpack SaveGames/OnlineLocalCacheMSD_0.sav ModData/
```
This extracts all 129 `.csv` tables (`DT_Ability.csv`, `DT_AircraftLevelup.csv`, `DT_Parts.csv`, etc.) and a `manifest.json`.

#### 3. Repack Modified CSV Data Tables
Edit any CSV, then pack directly from the directory:
```bash
ace8-savecrypt pack ModData/ SaveGames/OnlineLocalCacheMSD_0.sav
```
The tool reads `manifest.json`, recomputes SHA-256 for all modified CSVs, rebuilds the JSON payload, applies AES-256-CBC, and re-signs the save with the engine CRC.

#### 4. Unpack & Repack Campaign Saves
Preserve the entire GVAS header and extract the progression blob:
```bash
ace8-savecrypt unpack SaveGames/Campaign.sav Campaign_Backup.full.json
```
To rebuild the save:
```bash
ace8-savecrypt pack Campaign_Backup.full.json SaveGames/Campaign.sav
```
Which rebuilds an identical `.sav` file.

#### 5. View Key Table
Display all 4 engine keys, source hex strings, and derived AES-256 keys:
```bash
ace8-savecrypt keys
```

---
## This project is licensed under the [MIT](https://github.com/Dxian998/Ace-Combat-8-SaveCrypt/blob/main/LICENSE) license.
## I am not liable for any damages/game bans caused by the use of this project. You use this tool at your own risk.
