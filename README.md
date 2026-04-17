# NYDIX v2.0

> A premium encrypted file system for the terminal — built for Termux on Android.

NYDIX is a personal vault for writing, notes, and documents. Everything is encrypted on disk using **AES-256-GCM** with **Argon2id** key derivation. No cloud. No accounts. No plaintext ever touches storage.

---

## Features

- **AES-256-GCM encryption** — authenticated, tamper-proof
- **Argon2id key derivation** — GPU-resistant, modern KDF
- **Per-file nonce and salt** — no two files share cryptographic material
- **Version history** — up to 5 prior versions stored per file
- **Full-text search** — searches across titles, tags, and content
- **Tag system** — organize and filter files by tag
- **Secure delete** — multi-pass overwrite before unlinking
- **Activity log** — encrypted log of all actions
- **Device binding** — optionally ties the vault to your device
- **Auto-lock** — session locks after configurable inactivity timeout
- **Batch operations** — delete or export multiple files at once
- **4 themes** — `nydix`, `matrix`, `steel`, `ghost`
- **Import / Export** — bring in `.txt` files or export to plaintext
- **Dashboard home screen** — vault stats, recent files, session status

---

## Requirements

- Android with [Termux](https://termux.dev)
- Python 3.8+
- pip

---

## Installation

**1. Clone the repository**
```bash
git clone https://github.com/YOUR_USERNAME/nydix.git
cd nydix
```

**2. Run the installer**
```bash
bash nydix-install.sh
```

The installer will:
- Install Python dependencies (`cryptography`, `rich`, `argon2-cffi`)
- Write `nydix.py` to `~/.config/nydix/`
- Create a launcher at `~/.local/bin/nydix`

**3. Add to PATH** (if not already)
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

**4. Launch**
```bash
nydix
```

On first launch, NYDIX will guide you through vault setup and passphrase creation.

---

## Usage

| Key | Command     | Description                        |
|-----|-------------|------------------------------------|
| `n` | New         | Create a new encrypted file        |
| `o` | Open        | View a file                        |
| `e` | Edit        | Edit a file                        |
| `l` | List        | List all files                     |
| `s` | Search      | Full-text search                   |
| `t` | Tags        | Browse and filter by tag           |
| `i` | Info        | File metadata and word count       |
| `v` | Versions    | View and restore version history   |
| `r` | Rename      | Rename a file                      |
| `m` | Move        | Move to a subfolder                |
| `d` | Delete      | Secure delete with overwrite       |
| `x` | Export      | Export as plaintext `.txt`         |
| `/` | Import      | Import a `.txt` into the vault     |
| `b` | Batch       | Batch delete or export             |
| `S` | Stats       | Vault statistics dashboard         |
| `L` | Log         | View activity log                  |
| `!` | Settings    | Configure NYDIX                    |
| `k` | Lock        | Lock session immediately           |
| `q` | Quit        | Exit                               |

---

## File Format

All files use the `.nyx` format:

```
MAGIC(8) + NONCE(12) + AES-GCM-CIPHERTEXT(n) + TAG(16)
```

- Magic bytes are used as **AAD** (additional authenticated data) — any header tampering fails verification
- Each file has a unique random nonce
- Payload is JSON encrypted in-place — title, content, tags, timestamps, and version history all travel together

---

## Security Notes

- Your passphrase is the **only** key. There is no recovery mechanism.
- Temporary edit files are written to `/dev/shm` (RAM) when available — never to disk.
- Passphrase is overwritten in memory immediately after key derivation.
- Secure delete uses `fsync()` between passes to prevent OS buffering.
- The activity log itself is encrypted with your session key.

---

## Themes

Change theme via `!` → Settings:

| Theme    | Style                        |
|----------|------------------------------|
| `nydix`  | Magenta + cyan (default)     |
| `matrix` | Full green                   |
| `steel`  | White + bright cyan          |
| `ghost`  | Minimal monochrome           |

---

## License

MIT License — see [LICENSE](LICENSE)

---

> Built for Termux. Designed to feel like a real tool.
