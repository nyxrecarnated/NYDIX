#!/data/data/com.termux/files/usr/bin/bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║  NYDIX v2.0  —  Premium Encrypted File System                  ║
# ║  Installer for Termux · Run once · Type `nydix` to launch      ║
# ╚══════════════════════════════════════════════════════════════════╝

set -e

NYDIX_CFG="$HOME/.config/nydix"
NYDIX_LIB="$NYDIX_CFG/nydix.py"
NYDIX_BIN="$HOME/.local/bin/nydix"
NYDIX_DIR="$HOME/nydix"

mkdir -p "$NYDIX_CFG" "$HOME/.local/bin" "$NYDIX_DIR"

# ── Dependencies ──────────────────────────────────────────────────────────────
echo ""
echo "  [nydix] Installing dependencies..."
pip install --quiet cryptography rich argon2-cffi 2>/dev/null || \
  pip3 install --quiet cryptography rich argon2-cffi 2>/dev/null || \
  echo "  [warn] Some installs may have failed — continuing"
echo "  [nydix] Dependencies OK"
echo ""

# ── Write nydix.py ────────────────────────────────────────────────────────────
cat > "$NYDIX_LIB" << 'PYEOF'
#!/usr/bin/env python3
"""
NYDIX v2.0 — Premium Encrypted File System for Termux
Crypto : AES-256-GCM | KDF: Argon2id (fallback: PBKDF2-SHA512-600k)
Format : .nyx  —  MAGIC(8) + NONCE(12) + CIPHERTEXT(+16 tag)
"""

# ─────────────────────────────────────────────────────────────────────────────
#  IMPORTS
# ─────────────────────────────────────────────────────────────────────────────
import os, sys, json, getpass, datetime, tempfile, subprocess
import time, shutil, platform, re, hashlib
from pathlib import Path
from typing import Optional, List, Dict, Any

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidTag
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich.rule import Rule
    from rich.align import Align
    from rich.markup import escape
    from rich.columns import Columns
    from rich.padding import Padding
    from rich import box
except ImportError as _e:
    print(f"\n  [!] Missing library: {_e}")
    print("      pip install cryptography rich argon2-cffi\n")
    sys.exit(1)

try:
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False


# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
APP_VERSION  = "2.0"
MAGIC        = b"NYDIX\x02\x00\x01"   # 8 bytes
NONCE_LEN    = 12
SALT_LEN     = 32
MAX_VERSIONS = 5

ARGON2_TIME  = 3
ARGON2_MEM   = 65536    # 64 MiB
ARGON2_PARA  = 2

PBKDF2_ITER  = 600_000

BASE_DIR      = Path.home() / ".config" / "nydix"
VAULT_DIR     = Path.home() / "nydix"
CONFIG_FILE   = BASE_DIR / "config.json"
IDENTITY_FILE = BASE_DIR / "identity.json"
LOG_FILE      = BASE_DIR / "activity.nyx"

DEFAULT_CONFIG: Dict[str, Any] = {
    "theme":                "nydix",
    "auto_lock_minutes":    15,
    "device_binding":       False,
    "editor":               "nano",
    "secure_delete_passes": 3,
    "show_timestamps":      True,
}

# ─────────────────────────────────────────────────────────────────────────────
#  THEMES
# ─────────────────────────────────────────────────────────────────────────────
THEMES: Dict[str, Dict[str, str]] = {
    "nydix": {
        "brand":   "bold bright_magenta",
        "accent":  "cyan",
        "hi":      "bold cyan",
        "success": "bright_green",
        "warn":    "yellow",
        "error":   "bold red",
        "dim":     "dim",
        "text":    "white",
        "label":   "bold white",
        "border":  "bright_magenta",
        "key":     "bold magenta",
        "tag":     "cyan",
        "index":   "dim",
        "size":    "dim cyan",
        "date":    "dim white",
        "box":     box.ROUNDED,
    },
    "matrix": {
        "brand":   "bold bright_green",
        "accent":  "bright_green",
        "hi":      "bold bright_green",
        "success": "bright_green",
        "warn":    "yellow",
        "error":   "red",
        "dim":     "dim green",
        "text":    "green",
        "label":   "bold bright_green",
        "border":  "green",
        "key":     "bold green",
        "tag":     "bright_green",
        "index":   "dim green",
        "size":    "dim bright_green",
        "date":    "dim green",
        "box":     box.MINIMAL,
    },
    "steel": {
        "brand":   "bold bright_white",
        "accent":  "bright_cyan",
        "hi":      "bold bright_cyan",
        "success": "bright_cyan",
        "warn":    "yellow",
        "error":   "red",
        "dim":     "dim",
        "text":    "bright_white",
        "label":   "bold bright_white",
        "border":  "white",
        "key":     "bold bright_white",
        "tag":     "bright_cyan",
        "index":   "dim",
        "size":    "dim bright_white",
        "date":    "dim white",
        "box":     box.HEAVY_HEAD,
    },
    "ghost": {
        "brand":   "bold white",
        "accent":  "white",
        "hi":      "bold white",
        "success": "bright_white",
        "warn":    "white",
        "error":   "white",
        "dim":     "dim",
        "text":    "white",
        "label":   "bold white",
        "border":  "dim",
        "key":     "bold white",
        "tag":     "white",
        "index":   "dim",
        "size":    "dim white",
        "date":    "dim white",
        "box":     box.SIMPLE,
    },
}


# ─────────────────────────────────────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────────────────────────────────────
class Config:
    def __init__(self) -> None:
        BASE_DIR.mkdir(parents=True, exist_ok=True)
        self._data = dict(DEFAULT_CONFIG)
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    self._data.update(json.load(f))
            except Exception:
                pass

    def __getitem__(self, key: str) -> Any:
        return self._data.get(key, DEFAULT_CONFIG.get(key))

    def __setitem__(self, key: str, value: Any) -> None:
        self._data[key] = value
        self.save()

    def save(self) -> None:
        with open(CONFIG_FILE, "w") as f:
            json.dump(self._data, f, indent=2)
        os.chmod(CONFIG_FILE, 0o600)

    def theme(self) -> Dict[str, Any]:
        return THEMES.get(self._data["theme"], THEMES["nydix"])

    def all(self) -> Dict[str, Any]:
        return dict(self._data)


# ─────────────────────────────────────────────────────────────────────────────
#  CRYPTO ENGINE
# ─────────────────────────────────────────────────────────────────────────────
class CryptoEngine:
    @staticmethod
    def device_fingerprint() -> bytes:
        parts = "|".join([
            platform.node(),
            platform.machine(),
            platform.system(),
            platform.version()[:32],
        ])
        return hashlib.sha256(parts.encode()).digest()

    @staticmethod
    def derive_key(passphrase: str, salt: bytes, device_bound: bool = False) -> bytes:
        raw = passphrase.encode("utf-8")
        s   = salt
        if device_bound:
            fp  = CryptoEngine.device_fingerprint()
            s   = bytes(a ^ b for a, b in zip(salt, fp + fp))[:SALT_LEN]

        if HAS_ARGON2:
            return hash_secret_raw(
                secret=raw, salt=s,
                time_cost=ARGON2_TIME, memory_cost=ARGON2_MEM,
                parallelism=ARGON2_PARA, hash_len=32,
                type=Argon2Type.ID,
            )
        else:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=32, salt=s,
                iterations=PBKDF2_ITER,
            )
            return kdf.derive(raw)

    @staticmethod
    def encrypt(payload: dict, key: bytes) -> bytes:
        nonce     = os.urandom(NONCE_LEN)
        plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        ct        = AESGCM(key).encrypt(nonce, plaintext, MAGIC)
        return MAGIC + nonce + ct

    @staticmethod
    def decrypt(raw: bytes, key: bytes) -> dict:
        if len(raw) < len(MAGIC) + NONCE_LEN + 16:
            raise ValueError("File too small — corrupted or not a .nyx file")
        if not raw.startswith(MAGIC):
            raise ValueError("Invalid .nyx file (bad magic bytes)")
        nonce = raw[len(MAGIC) : len(MAGIC) + NONCE_LEN]
        ct    = raw[len(MAGIC) + NONCE_LEN :]
        plain = AESGCM(key).decrypt(nonce, ct, MAGIC)
        return json.loads(plain.decode("utf-8"))


# ─────────────────────────────────────────────────────────────────────────────
#  IDENTITY MANAGER
# ─────────────────────────────────────────────────────────────────────────────
class IdentityManager:
    def __init__(self, cfg: Config, cx: CryptoEngine, console: Console) -> None:
        self.cfg     = cfg
        self.cx      = cx
        self.console = console

    def _load_salt(self) -> Optional[bytes]:
        if IDENTITY_FILE.exists():
            try:
                with open(IDENTITY_FILE) as f:
                    return bytes.fromhex(json.load(f)["salt"])
            except Exception:
                return None
        return None

    def _save_identity(self, salt: bytes) -> None:
        BASE_DIR.mkdir(parents=True, exist_ok=True)
        data = {
            "salt":    salt.hex(),
            "created": _now(),
            "kdf":     "argon2id" if HAS_ARGON2 else "pbkdf2-sha512",
            "version": APP_VERSION,
        }
        with open(IDENTITY_FILE, "w") as f:
            json.dump(data, f, indent=2)
        os.chmod(IDENTITY_FILE, 0o600)

    def first_run(self) -> bytes:
        t = self.cfg.theme()
        self.console.clear()
        _banner(self.console, t)
        self.console.print(Panel(
            Text.assemble(
                ("First Run — Vault Setup\n\n", t["label"]),
                ("Your passphrase is the only key to all .nyx files.\n", t["dim"]),
                ("There is no recovery option. Choose carefully.", t["dim"]),
            ),
            border_style=t["border"], expand=False, padding=(1, 3),
        ))
        self.console.print()

        kdf_name = "Argon2id" if HAS_ARGON2 else "PBKDF2-SHA512"
        self.console.print(f"  [dim]KDF: {kdf_name} · AES-256-GCM · .nyx v2[/]\n")

        while True:
            p1 = getpass.getpass("  Set passphrase (min 10 chars) : ")
            if len(p1) < 10:
                self.console.print(f"  [{t['error']}]Too short — minimum 10 characters.[/]\n")
                continue
            p2 = getpass.getpass("  Confirm passphrase            : ")
            if p1 != p2:
                self.console.print(f"  [{t['error']}]Passphrases do not match.[/]\n")
                continue
            break

        salt = os.urandom(SALT_LEN)
        self._save_identity(salt)

        if Confirm.ask(f"\n  [{t['accent']}]Enable device binding?[/] [dim](ties vault to this device)[/]", default=False):
            self.cfg["device_binding"] = True

        self.console.print(f"\n  [{t['success']}]✓[/] Vault created")
        self.console.print(f"  [dim]Identity stored at ~/.config/nydix/identity.json[/]\n")
        input("  Press Enter to continue...")

        device_bound = self.cfg["device_binding"]
        with self.console.status(f"  [{t['dim']}]Deriving session key...[/]", spinner="dots"):
            key = self.cx.derive_key(p1, salt, device_bound)

        # Wipe passphrase from memory as best we can
        p1 = "\x00" * len(p1)
        del p1, p2
        return key

    def unlock(self) -> bytes:
        salt = self._load_salt()
        if salt is None:
            return self.first_run()

        t = self.cfg.theme()
        self.console.print()
        phrase = getpass.getpass("  Passphrase: ")
        self.console.print()

        device_bound = self.cfg["device_binding"]
        with self.console.status(f"  [{t['dim']}]Deriving key...[/]", spinner="dots"):
            key = self.cx.derive_key(phrase, salt, device_bound)

        phrase = "\x00" * len(phrase)
        del phrase
        return key


# ─────────────────────────────────────────────────────────────────────────────
#  FILE MANAGER
# ─────────────────────────────────────────────────────────────────────────────
class FileManager:
    def __init__(self, cx: CryptoEngine) -> None:
        self.cx = cx
        VAULT_DIR.mkdir(parents=True, exist_ok=True)

    # ── resolution ───────────────────────────────────────────────────────────
    def resolve(self, name: str, folder: str = "") -> Path:
        p = Path(name)
        if p.suffix.lower() != ".nyx":
            p = p.with_suffix(".nyx")
        if p.parent == Path("."):
            base = VAULT_DIR / folder if folder else VAULT_DIR
            base.mkdir(parents=True, exist_ok=True)
            p = base / p
        return p

    # ── listing ──────────────────────────────────────────────────────────────
    def all_files(self, folder: str = "") -> List[Path]:
        base = VAULT_DIR / folder if folder else VAULT_DIR
        if not base.exists():
            return []
        files = sorted(base.rglob("*.nyx"))
        # exclude the activity log
        return [f for f in files if f.resolve() != LOG_FILE.resolve()]

    def all_folders(self) -> List[str]:
        dirs = [""]
        for d in sorted(VAULT_DIR.rglob("*")):
            if d.is_dir():
                rel = str(d.relative_to(VAULT_DIR))
                dirs.append(rel)
        return dirs

    def all_tags(self, key: bytes) -> Dict[str, int]:
        tags: Dict[str, int] = {}
        for f in self.all_files():
            try:
                p = self.read(f, key)
                for t in p.get("tags", []):
                    tags[t] = tags.get(t, 0) + 1
            except Exception:
                pass
        return tags

    # ── read / write ─────────────────────────────────────────────────────────
    def read(self, path: Path, key: bytes) -> dict:
        with open(path, "rb") as f:
            raw = f.read()
        return self.cx.decrypt(raw, key)

    def write(self, path: Path, payload: dict, key: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = self.cx.encrypt(payload, key)
        with open(path, "wb") as f:
            f.write(data)
        os.chmod(path, 0o600)

    def new_payload(self, title: str, content: str, tags: List[str]) -> dict:
        now = _now()
        return {
            "title":    title,
            "content":  content,
            "tags":     tags,
            "created":  now,
            "modified": now,
            "history":  [],
        }

    def update_content(self, existing: dict, new_content: str, new_tags: Optional[List[str]] = None) -> dict:
        # Push current version to history
        hist = existing.get("history", [])
        hist.append({"content": existing["content"], "modified": existing["modified"]})
        if len(hist) > MAX_VERSIONS:
            hist = hist[-MAX_VERSIONS:]
        existing["history"]  = hist
        existing["content"]  = new_content
        existing["modified"] = _now()
        if new_tags is not None:
            existing["tags"] = new_tags
        return existing

    # ── search ───────────────────────────────────────────────────────────────
    def search(self, query: str, key: bytes) -> List[tuple]:
        q     = query.lower()
        hits  = []
        files = self.all_files()
        for f in files:
            try:
                p = self.read(f, key)
            except Exception:
                continue
            blob = " ".join([
                p.get("title", ""),
                " ".join(p.get("tags", [])),
                p.get("content", ""),
            ]).lower()
            if q in blob:
                # Count occurrences as relevance score
                score = blob.count(q)
                hits.append((score, f, p))
        hits.sort(key=lambda x: x[0], reverse=True)
        return [(f, p) for _, f, p in hits]

    def files_by_tag(self, tag: str, key: bytes) -> List[tuple]:
        results = []
        for f in self.all_files():
            try:
                p = self.read(f, key)
                if tag in p.get("tags", []):
                    results.append((f, p))
            except Exception:
                pass
        return results

    # ── file ops ─────────────────────────────────────────────────────────────
    def secure_delete(self, path: Path, passes: int = 3) -> None:
        try:
            size = path.stat().st_size
            with open(path, "r+b") as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(os.urandom(size))
                    f.flush()
                    os.fsync(f.fileno())
        except Exception:
            pass
        path.unlink()

    def export_plaintext(self, path: Path, key: bytes) -> Path:
        payload = self.read(path, key)
        out     = path.with_suffix(".txt")
        with open(out, "w", encoding="utf-8") as f:
            f.write(f"NYDIX EXPORT — {_now()}\n")
            f.write(f"{'═' * 52}\n")
            f.write(f"Title    : {payload.get('title', '')}\n")
            f.write(f"Tags     : {', '.join(payload.get('tags', []))}\n")
            f.write(f"Created  : {payload.get('created', '')}\n")
            f.write(f"Modified : {payload.get('modified', '')}\n")
            f.write(f"{'─' * 52}\n\n")
            f.write(payload.get("content", ""))
        os.chmod(out, 0o600)
        return out

    def import_text(self, source: Path, key: bytes, title: str, tags: List[str]) -> Path:
        content = source.read_text(encoding="utf-8", errors="replace")
        dest    = self.resolve(title)
        if dest.exists():
            raise FileExistsError(f"{dest.name} already exists")
        payload = self.new_payload(title, content, tags)
        self.write(dest, payload, key)
        return dest

    # ── stats ─────────────────────────────────────────────────────────────────
    def vault_stats(self, key: bytes) -> dict:
        files  = self.all_files()
        total_enc = sum(f.stat().st_size for f in files)
        total_words = 0
        all_tags_set: set = set()
        for f in files:
            try:
                p = self.read(f, key)
                total_words  += len(p.get("content", "").split())
                all_tags_set |= set(p.get("tags", []))
            except Exception:
                pass
        return {
            "file_count":  len(files),
            "total_enc":   total_enc,
            "total_words": total_words,
            "tag_count":   len(all_tags_set),
        }

    def recent_files(self, key: bytes, n: int = 5) -> List[tuple]:
        files = self.all_files()
        with_mtime = [(f.stat().st_mtime, f) for f in files]
        with_mtime.sort(reverse=True)
        results = []
        for _, f in with_mtime[:n]:
            try:
                p = self.read(f, key)
                results.append((f, p))
            except Exception:
                pass
        return results


# ─────────────────────────────────────────────────────────────────────────────
#  ACTIVITY LOGGER
# ─────────────────────────────────────────────────────────────────────────────
class ActivityLogger:
    def __init__(self, cx: CryptoEngine) -> None:
        self.cx = cx

    def _load(self, key: bytes) -> List[dict]:
        if not LOG_FILE.exists():
            return []
        try:
            raw = LOG_FILE.read_bytes()
            return self.cx.decrypt(raw, key).get("entries", [])
        except Exception:
            return []

    def log(self, action: str, detail: str, key: bytes) -> None:
        try:
            entries = self._load(key)
            entries.append({"ts": _now(), "action": action, "detail": detail})
            if len(entries) > 200:
                entries = entries[-200:]
            data = self.cx.encrypt({"entries": entries}, key)
            LOG_FILE.write_bytes(data)
            os.chmod(LOG_FILE, 0o600)
        except Exception:
            pass

    def get_recent(self, key: bytes, n: int = 30) -> List[dict]:
        entries = self._load(key)
        return entries[-n:][::-1]


# ─────────────────────────────────────────────────────────────────────────────
#  SESSION
# ─────────────────────────────────────────────────────────────────────────────
class Session:
    def __init__(self, timeout_minutes: int) -> None:
        self.timeout   = timeout_minutes * 60
        self._last     = time.time()
        self._locked   = False

    def touch(self) -> None:
        self._last   = time.time()
        self._locked = False

    def is_locked(self) -> bool:
        if self._locked:
            return True
        if self.timeout > 0 and (time.time() - self._last) > self.timeout:
            self._locked = True
            return True
        return False

    def lock(self) -> None:
        self._locked = True

    def remaining(self) -> int:
        elapsed = time.time() - self._last
        return max(0, int(self.timeout - elapsed))


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")

def _fmt_size(n: int) -> str:
    if n < 1024:       return f"{n} B"
    if n < 1048576:    return f"{n/1024:.1f} KB"
    return f"{n/1048576:.1f} MB"

def _fmt_words(n: int) -> str:
    if n >= 1000:      return f"{n/1000:.1f}k"
    return str(n)

def _banner(console: Console, t: Dict[str, Any]) -> None:
    console.print()
    top = Text()
    top.append("  N Y D I X  ", style=t["brand"])
    top.append("·", style=t["dim"])
    top.append(f"  v{APP_VERSION}  ", style=t["dim"])
    top.append("·", style=t["dim"])
    top.append("  Encrypted Vault", style=t["dim"])
    console.print(Align.center(top))
    kdf = "Argon2id" if HAS_ARGON2 else "PBKDF2-SHA512"
    console.print(Align.center(
        Text(f"AES-256-GCM  ·  {kdf}  ·  .nyx", style=t["dim"])
    ))
    console.print()

def _rule(console: Console, t: Dict[str, Any], label: str = "") -> None:
    console.print(Rule(label, style=t["border"] if not label else t["dim"], align="left"))

def _pause(console: Console) -> None:
    console.print()
    try:
        input("  Press Enter to continue...")
    except (KeyboardInterrupt, EOFError):
        pass

def _edit_with_editor(content: str, editor: str) -> Optional[str]:
    """Open content in editor, return new content or None on cancel."""
    # Prefer /dev/shm (RAM) for security, fall back to system temp
    tmp_dir = "/dev/shm" if Path("/dev/shm").exists() and os.access("/dev/shm", os.W_OK) else None

    fd, tmp_path = tempfile.mkstemp(suffix=".txt", prefix="nydix_", dir=tmp_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        result = subprocess.run([editor, tmp_path])
        if result.returncode != 0:
            return None
        with open(tmp_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    finally:
        # Securely wipe the temp file
        try:
            sz = Path(tmp_path).stat().st_size
            with open(tmp_path, "r+b") as f:
                f.write(os.urandom(sz))
            os.unlink(tmp_path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

def _pick_tags(console: Console, t: Dict[str, Any], existing: List[str] = None) -> List[str]:
    if existing:
        console.print(f"  Current tags: [{t['tag']}]{', '.join(existing)}[/]")
    raw = Prompt.ask(
        f"  [{t['accent']}]Tags[/] [dim](comma-separated, blank to keep)[/]",
        default="",
    ).strip()
    if not raw and existing is not None:
        return existing
    return [tg.strip() for tg in raw.split(",") if tg.strip()] if raw else []


# ─────────────────────────────────────────────────────────────────────────────
#  UI
# ─────────────────────────────────────────────────────────────────────────────
class UI:
    def __init__(self, console: Console, cfg: Config) -> None:
        self.c   = console
        self.cfg = cfg

    def t(self) -> Dict[str, Any]:
        return self.cfg.theme()

    # ── dashboard ─────────────────────────────────────────────────────────────
    def dashboard(self, key: bytes, fm: FileManager, al: ActivityLogger, sess: Session) -> None:
        t = self.t()
        self.c.clear()
        _banner(self.c, t)

        # Stats row
        try:
            stats  = fm.vault_stats(key)
            recent = fm.recent_files(key, n=5)
            stat_ok = True
        except Exception:
            stat_ok = False
            stats   = {}
            recent  = []

        # Vault status panel
        if stat_ok:
            stat_text = Text()
            stat_text.append(f"  Files  ", style=t["dim"])
            stat_text.append(f"{stats['file_count']}", style=t["hi"])
            stat_text.append(f"     Words  ", style=t["dim"])
            stat_text.append(f"{_fmt_words(stats['total_words'])}", style=t["hi"])
            stat_text.append(f"     Size  ", style=t["dim"])
            stat_text.append(f"{_fmt_size(stats['total_enc'])}", style=t["hi"])
            stat_text.append(f"     Tags  ", style=t["dim"])
            stat_text.append(f"{stats['tag_count']}", style=t["hi"])
            stat_text.append(f"\n\n  Session lock in  ", style=t["dim"])
            mins  = sess.remaining() // 60
            secs  = sess.remaining() % 60
            stat_text.append(f"{mins}m {secs:02d}s", style=t["accent"])
            stat_text.append(f"  ·  KDF  ", style=t["dim"])
            stat_text.append("Argon2id" if HAS_ARGON2 else "PBKDF2-SHA512", style=t["dim"])

            self.c.print(Panel(
                stat_text,
                title=f"[{t['label']}]Vault Status[/]",
                border_style=t["border"],
                padding=(1, 2),
                expand=True,
            ))
        else:
            self.c.print(Panel(
                Text("  Vault ready", style=t["dim"]),
                border_style=t["border"], padding=(0, 2),
            ))

        self.c.print()

        # Recent files
        if recent:
            tbl = Table(
                box=box.SIMPLE, show_header=True,
                header_style=t["label"],
                padding=(0, 2), show_edge=False,
            )
            tbl.add_column("Name",     style=t["accent"],  min_width=18)
            tbl.add_column("Modified", style=t["date"],    min_width=18)
            tbl.add_column("Words",    style=t["size"],    justify="right", width=7)
            tbl.add_column("Tags",     style=t["tag"])

            for f, p in recent:
                words = len(p.get("content", "").split())
                tags  = ", ".join(p.get("tags", [])) or "—"
                tbl.add_row(
                    escape(f.stem),
                    p.get("modified", "—")[:16],
                    str(words),
                    escape(tags),
                )

            self.c.print(Panel(
                tbl,
                title=f"[{t['label']}]Recent Files[/]",
                border_style=t["dim"],
                padding=(0, 1),
            ))
        else:
            self.c.print(Panel(
                Text("  No files yet — press [n] to create your first .nyx file", style=t["dim"]),
                border_style=t["dim"], padding=(0, 2),
            ))

        self.c.print()
        self._print_menu(t)

    # ── menu ──────────────────────────────────────────────────────────────────
    def _print_menu(self, t: Dict[str, Any]) -> None:
        lines: List[Text] = []

        def row(keys: List[tuple]) -> Text:
            line = Text("  ")
            for i, (k, label) in enumerate(keys):
                line.append(f"[{k}]", style=t["key"])
                line.append(f" {label}", style=t["dim"])
                if i < len(keys) - 1:
                    line.append("   ")
            return line

        groups = [
            [("n", "New"),    ("o", "Open"),  ("e", "Edit"),  ("l", "List")],
            [("s", "Search"), ("t", "Tags"),  ("i", "Info"),  ("v", "Versions")],
            [("r", "Rename"), ("m", "Move"),  ("d", "Delete"),("x", "Export")],
            [("b", "Batch"),  ("S", "Stats"), ("L", "Log"),   ("!", "Settings")],
            [("/", "Import"), ("?", "Help"),  ("q", "Quit"),  ("k", "Lock")],
        ]
        for g in groups:
            lines.append(row(g))

        body = Text("\n").join(lines)
        self.c.print(Panel(body, border_style=t["dim"], padding=(0, 1)))

    # ── file table ────────────────────────────────────────────────────────────
    def file_table(self, files: List[Path], key: bytes, fm: FileManager, show_content: bool = False) -> None:
        t = self.t()
        if not files:
            self.c.print(f"\n  [{t['dim']}]No .nyx files found.[/]")
            return

        tbl = Table(
            box=box.SIMPLE, show_header=True,
            header_style=t["label"],
            padding=(0, 2), show_edge=False,
        )
        tbl.add_column("#",        style=t["index"],  width=4,  justify="right")
        tbl.add_column("Name",     style=t["accent"], min_width=18)
        tbl.add_column("Size",     style=t["size"],   justify="right", width=9)
        tbl.add_column("Modified", style=t["date"],   min_width=17)
        tbl.add_column("Words",    style=t["size"],   justify="right", width=7)
        tbl.add_column("Tags",     style=t["tag"])

        for i, f in enumerate(files, 1):
            sz   = _fmt_size(f.stat().st_size)
            try:
                p    = fm.read(f, key)
                mod  = p.get("modified", "—")[:16]
                wds  = str(len(p.get("content", "").split()))
                tags = ", ".join(p.get("tags", [])) or "—"
            except Exception:
                mod, wds, tags = "—", "—", "[decryption failed]"
            tbl.add_row(str(i), escape(f.stem), sz, mod, wds, escape(tags))

        self.c.print()
        self.c.print(tbl)
        total = _fmt_size(sum(f.stat().st_size for f in files))
        self.c.print(f"\n  [{t['dim']}]{len(files)} file{'s' if len(files) != 1 else ''} · {total} encrypted[/]")

    # ── pick file ─────────────────────────────────────────────────────────────
    def pick_file(self, files: List[Path], label: str = "Select") -> Optional[Path]:
        t = self.t()
        if not files:
            return None
        raw = Prompt.ask(f"\n  [{t['accent']}]{label}[/] [{t['dim']}](# or filename)[/]").strip()
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(files):
                return files[idx]
            self.c.print(f"  [{t['error']}]Invalid number.[/]")
            return None
        # match by stem
        for f in files:
            if f.stem.lower() == raw.lower():
                return f
        self.c.print(f"  [{t['error']}]Not found: {raw}[/]")
        return None

    # ── file info panel ───────────────────────────────────────────────────────
    def show_info(self, path: Path, payload: dict) -> None:
        t    = self.t()
        c    = payload.get("content", "")
        hist = payload.get("history", [])

        tbl = Table(box=box.SIMPLE, show_header=False, padding=(0, 3), show_edge=False)
        tbl.add_column(style=t["dim"],   min_width=12)
        tbl.add_column(style=t["text"])

        lines_n = len(c.splitlines())
        words_n = len(c.split())
        chars_n = len(c)

        tbl.add_row("File",     str(path))
        tbl.add_row("Title",    escape(payload.get("title", "—")))
        tbl.add_row("Tags",     escape(", ".join(payload.get("tags", [])) or "—"))
        tbl.add_row("Created",  payload.get("created",  "—"))
        tbl.add_row("Modified", payload.get("modified", "—"))
        tbl.add_row("Enc size", _fmt_size(path.stat().st_size))
        tbl.add_row("Words",    f"{words_n:,}")
        tbl.add_row("Lines",    f"{lines_n:,}")
        tbl.add_row("Chars",    f"{chars_n:,}")
        tbl.add_row("Versions", str(len(hist)))

        self.c.print()
        self.c.print(Panel(
            tbl,
            title=f"[{t['label']}]File Info[/]",
            border_style=t["border"], padding=(0, 1),
        ))

    # ── preview ───────────────────────────────────────────────────────────────
    def preview(self, payload: dict, max_lines: int = 30) -> None:
        t       = self.t()
        content = payload.get("content", "")
        lines   = content.splitlines()
        preview = lines[:max_lines]
        truncated = len(lines) > max_lines

        title_line = Text()
        title_line.append(escape(payload.get("title", "Untitled")), style=t["hi"])
        if payload.get("tags"):
            title_line.append("  ", style=t["dim"])
            title_line.append(escape(" · ".join(payload["tags"])), style=t["tag"])

        body = Text()
        body.append_text(title_line)
        body.append("\n\n")
        body.append(escape("\n".join(preview)), style=t["text"])
        if truncated:
            body.append(f"\n\n  … {len(lines) - max_lines} more lines", style=t["dim"])

        meta = Text()
        meta.append(f"Words: {len(content.split()):,}", style=t["dim"])
        meta.append("  ·  ", style=t["dim"])
        meta.append(f"Lines: {len(lines):,}", style=t["dim"])
        meta.append("  ·  ", style=t["dim"])
        meta.append(f"Modified: {payload.get('modified', '—')[:16]}", style=t["dim"])

        self.c.print()
        self.c.print(Panel(body, border_style=t["border"], padding=(1, 2)))
        self.c.print(Padding(meta, (0, 2)))

    # ── search results ────────────────────────────────────────────────────────
    def search_results(self, query: str, results: List[tuple]) -> None:
        t = self.t()
        self.c.print()
        if not results:
            self.c.print(f"  [{t['dim']}]No matches for '{query}'[/]")
            return

        tbl = Table(
            box=box.SIMPLE, show_header=True,
            header_style=t["label"], padding=(0, 2), show_edge=False,
        )
        tbl.add_column("#",     style=t["index"], width=4, justify="right")
        tbl.add_column("Name",  style=t["accent"], min_width=16)
        tbl.add_column("Title", style=t["text"],   min_width=20)
        tbl.add_column("Tags",  style=t["tag"])

        for i, (f, p) in enumerate(results, 1):
            tbl.add_row(
                str(i),
                escape(f.stem),
                escape(p.get("title", "—")),
                escape(", ".join(p.get("tags", [])) or "—"),
            )

        self.c.print(tbl)
        self.c.print(f"\n  [{t['dim']}]{len(results)} result{'s' if len(results) != 1 else ''} for '{query}'[/]")

    # ── tag browser ───────────────────────────────────────────────────────────
    def tag_browser(self, tags: Dict[str, int]) -> Optional[str]:
        t = self.t()
        self.c.print()
        if not tags:
            self.c.print(f"  [{t['dim']}]No tags found.[/]")
            return None

        sorted_tags = sorted(tags.items(), key=lambda x: x[1], reverse=True)

        tbl = Table(
            box=box.SIMPLE, show_header=True,
            header_style=t["label"], padding=(0, 2), show_edge=False,
        )
        tbl.add_column("#",     style=t["index"], width=4, justify="right")
        tbl.add_column("Tag",   style=t["tag"],   min_width=18)
        tbl.add_column("Files", style=t["size"],  justify="right", width=7)

        for i, (tag, count) in enumerate(sorted_tags, 1):
            tbl.add_row(str(i), escape(tag), str(count))

        self.c.print(tbl)
        raw = Prompt.ask(f"\n  [{t['accent']}]Filter by tag[/] [{t['dim']}](# or name, blank to cancel)[/]", default="").strip()
        if not raw:
            return None
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(sorted_tags):
                return sorted_tags[idx][0]
        return raw if raw else None

    # ── version history ───────────────────────────────────────────────────────
    def show_versions(self, payload: dict) -> Optional[dict]:
        t    = self.t()
        hist = payload.get("history", [])
        self.c.print()
        if not hist:
            self.c.print(f"  [{t['dim']}]No version history for this file.[/]")
            return None

        tbl = Table(
            box=box.SIMPLE, show_header=True,
            header_style=t["label"], padding=(0, 2), show_edge=False,
        )
        tbl.add_column("#",        style=t["index"], width=4, justify="right")
        tbl.add_column("Modified", style=t["date"],  min_width=18)
        tbl.add_column("Words",    style=t["size"],  justify="right", width=7)
        tbl.add_column("Preview",  style=t["dim"],   min_width=30)

        for i, v in enumerate(reversed(hist), 1):
            content = v.get("content", "")
            preview = content[:60].replace("\n", " ")
            if len(content) > 60:
                preview += "…"
            tbl.add_row(
                str(i),
                v.get("modified", "—")[:16],
                str(len(content.split())),
                escape(preview),
            )

        self.c.print(tbl)
        raw = Prompt.ask(
            f"\n  [{t['accent']}]Restore version[/] [{t['dim']}](# or blank to cancel)[/]",
            default="",
        ).strip()
        if raw.isdigit():
            idx = int(raw) - 1
            real_idx = len(hist) - 1 - idx
            if 0 <= real_idx < len(hist):
                return hist[real_idx]
        return None

    # ── stats dashboard ───────────────────────────────────────────────────────
    def stats_dashboard(self, key: bytes, fm: FileManager) -> None:
        t = self.t()
        self.c.print()
        files = fm.all_files()
        if not files:
            self.c.print(f"  [{t['dim']}]No files to analyze.[/]")
            return

        all_words = []
        all_tags: Dict[str, int] = {}
        oldest_date = None
        newest_date = None
        errors = 0

        for f in files:
            try:
                p = fm.read(f, key)
                wc = len(p.get("content", "").split())
                all_words.append((f.stem, wc))
                for tag in p.get("tags", []):
                    all_tags[tag] = all_tags.get(tag, 0) + 1
                mod = p.get("modified", "")
                if mod:
                    if oldest_date is None or mod < oldest_date:
                        oldest_date = mod
                    if newest_date is None or mod > newest_date:
                        newest_date = mod
            except Exception:
                errors += 1

        total_words = sum(w for _, w in all_words)
        avg_words   = total_words // len(all_words) if all_words else 0
        max_file    = max(all_words, key=lambda x: x[1]) if all_words else ("—", 0)
        enc_total   = sum(f.stat().st_size for f in files)

        body = Text()
        body.append(f"  Total files     ", style=t["dim"])
        body.append(f"{len(files)}", style=t["hi"])
        body.append(f"\n  Total words     ", style=t["dim"])
        body.append(f"{total_words:,}", style=t["hi"])
        body.append(f"\n  Average words   ", style=t["dim"])
        body.append(f"{avg_words:,}", style=t["hi"])
        body.append(f"\n  Longest file    ", style=t["dim"])
        body.append(f"{max_file[0]}  ({max_file[1]:,} words)", style=t["hi"])
        body.append(f"\n  Encrypted size  ", style=t["dim"])
        body.append(f"{_fmt_size(enc_total)}", style=t["hi"])
        body.append(f"\n  Unique tags     ", style=t["dim"])
        body.append(f"{len(all_tags)}", style=t["hi"])
        body.append(f"\n  Oldest entry    ", style=t["dim"])
        body.append(f"{(oldest_date or '—')[:16]}", style=t["hi"])
        body.append(f"\n  Newest entry    ", style=t["dim"])
        body.append(f"{(newest_date or '—')[:16]}", style=t["hi"])
        if errors:
            body.append(f"\n  Decrypt errors  ", style=t["dim"])
            body.append(f"{errors}", style=t["error"])

        self.c.print(Panel(
            body,
            title=f"[{t['label']}]Vault Statistics[/]",
            border_style=t["border"], padding=(1, 2),
        ))

        # Top tags
        if all_tags:
            self.c.print()
            tbl = Table(
                box=box.SIMPLE, show_header=True,
                header_style=t["label"], padding=(0, 2), show_edge=False,
            )
            tbl.add_column("Tag",   style=t["tag"])
            tbl.add_column("Files", style=t["size"], justify="right", width=7)
            for tag, count in sorted(all_tags.items(), key=lambda x: x[1], reverse=True)[:10]:
                tbl.add_row(escape(tag), str(count))
            self.c.print(Panel(tbl, title=f"[{t['label']}]Top Tags[/]",
                               border_style=t["dim"], padding=(0, 1)))

    # ── activity log view ─────────────────────────────────────────────────────
    def log_view(self, entries: List[dict]) -> None:
        t = self.t()
        self.c.print()
        if not entries:
            self.c.print(f"  [{t['dim']}]No activity recorded.[/]")
            return

        tbl = Table(
            box=box.SIMPLE, show_header=True,
            header_style=t["label"], padding=(0, 2), show_edge=False,
        )
        tbl.add_column("Time",   style=t["date"],   min_width=18)
        tbl.add_column("Action", style=t["accent"], min_width=10)
        tbl.add_column("Detail", style=t["dim"])

        for entry in entries:
            tbl.add_row(
                entry.get("ts", "—")[:16],
                escape(entry.get("action", "—")),
                escape(entry.get("detail", "")),
            )

        self.c.print(Panel(
            tbl,
            title=f"[{t['label']}]Activity Log[/]",
            border_style=t["dim"], padding=(0, 1),
        ))

    # ── settings ──────────────────────────────────────────────────────────────
    def settings_menu(self, cfg: Config) -> None:
        t = self.t()
        self.c.print()
        data = cfg.all()

        tbl = Table(
            box=box.SIMPLE, show_header=False, padding=(0, 3), show_edge=False,
        )
        tbl.add_column(style=t["dim"],  min_width=22)
        tbl.add_column(style=t["text"])

        tbl.add_row("[1] Theme",               data["theme"])
        tbl.add_row("[2] Auto-lock (minutes)",  str(data["auto_lock_minutes"]))
        tbl.add_row("[3] Editor",               data["editor"])
        tbl.add_row("[4] Secure delete passes", str(data["secure_delete_passes"]))
        tbl.add_row("[5] Device binding",       "on" if data["device_binding"] else "off")

        self.c.print(Panel(
            tbl,
            title=f"[{t['label']}]Settings[/]",
            border_style=t["border"], padding=(0, 1),
        ))
        self.c.print()

        choice = Prompt.ask(f"  [{t['accent']}]Setting to change[/] [{t['dim']}](1-5, blank to exit)[/]", default="").strip()
        if not choice:
            return

        if choice == "1":
            names = list(THEMES.keys())
            self.c.print(f"  Themes: {', '.join(names)}")
            v = Prompt.ask(f"  [{t['accent']}]Theme[/]", default=data["theme"]).strip()
            if v in THEMES:
                cfg["theme"] = v
        elif choice == "2":
            v = Prompt.ask(f"  [{t['accent']}]Minutes (0 = disabled)[/]", default=str(data["auto_lock_minutes"])).strip()
            if v.isdigit():
                cfg["auto_lock_minutes"] = int(v)
        elif choice == "3":
            v = Prompt.ask(f"  [{t['accent']}]Editor[/]", default=data["editor"]).strip()
            if v:
                cfg["editor"] = v
        elif choice == "4":
            v = Prompt.ask(f"  [{t['accent']}]Passes (1-7)[/]", default=str(data["secure_delete_passes"])).strip()
            if v.isdigit() and 1 <= int(v) <= 7:
                cfg["secure_delete_passes"] = int(v)
        elif choice == "5":
            current = data["device_binding"]
            cfg["device_binding"] = not current
            self.c.print(f"  [{t['success']}]Device binding {'enabled' if not current else 'disabled'}[/]")
            self.c.print(f"  [{t['warn']}]Re-launch nydix to apply key changes.[/]")

        self.c.print(f"\n  [{t['success']}]✓[/] Settings saved.")

    # ── help screen ───────────────────────────────────────────────────────────
    def help_screen(self) -> None:
        t = self.t()
        lines: List[tuple] = [
            ("n", "New",      "Create a new encrypted .nyx file"),
            ("o", "Open",     "View a file (decrypted, read-only)"),
            ("e", "Edit",     "Edit a file in your configured editor"),
            ("l", "List",     "List all files in the vault"),
            ("s", "Search",   "Full-text search across all files"),
            ("t", "Tags",     "Browse and filter by tag"),
            ("i", "Info",     "Show file metadata and statistics"),
            ("v", "Versions", "View and restore version history"),
            ("r", "Rename",   "Rename a .nyx file"),
            ("m", "Move",     "Move file to a subfolder"),
            ("d", "Delete",   "Securely delete a file (multi-pass overwrite)"),
            ("x", "Export",   "Export decrypted content to .txt"),
            ("/", "Import",   "Import a .txt file into the vault"),
            ("b", "Batch",    "Batch delete or export selected files"),
            ("S", "Stats",    "Vault statistics dashboard"),
            ("L", "Log",      "View encrypted activity log"),
            ("!", "Settings", "Configure NYDIX preferences"),
            ("k", "Lock",     "Lock session immediately"),
            ("?", "Help",     "Show this help screen"),
            ("q", "Quit",     "Exit NYDIX"),
        ]

        tbl = Table(
            box=box.SIMPLE, show_header=True,
            header_style=t["label"], padding=(0, 2), show_edge=False,
        )
        tbl.add_column("Key",     style=t["key"],    width=5)
        tbl.add_column("Command", style=t["accent"], min_width=10)
        tbl.add_column("Description", style=t["dim"])

        for k, cmd, desc in lines:
            tbl.add_row(k, cmd, desc)

        self.c.print()
        self.c.print(Panel(
            tbl,
            title=f"[{t['label']}]NYDIX v{APP_VERSION}  ·  Command Reference[/]",
            border_style=t["border"], padding=(0, 1),
        ))

        kdf = "Argon2id" if HAS_ARGON2 else "PBKDF2-SHA512"
        self.c.print(f"\n  [{t['dim']}]Encryption: AES-256-GCM  ·  KDF: {kdf}  ·  Format: .nyx v2[/]")
        self.c.print(f"  [{t['dim']}]Vault: ~/nydix/  ·  Config: ~/.config/nydix/[/]")


# ─────────────────────────────────────────────────────────────────────────────
#  NYDIX — MAIN CONTROLLER
# ─────────────────────────────────────────────────────────────────────────────
class NYDIX:
    def __init__(self) -> None:
        self.console = Console()
        self.cfg     = Config()
        self.cx      = CryptoEngine()
        self.fm      = FileManager(self.cx)
        self.al      = ActivityLogger(self.cx)
        self.ui      = UI(self.console, self.cfg)
        self.key: Optional[bytes] = None
        self.sess: Optional[Session] = None

    def t(self) -> Dict[str, Any]:
        return self.cfg.theme()

    # ── session management ────────────────────────────────────────────────────
    def _require_auth(self) -> None:
        """Prompt for passphrase if session is locked or missing."""
        if self.key is None or (self.sess and self.sess.is_locked()):
            t = self.t()
            self.console.clear()
            _banner(self.console, t)
            if self.key is not None:
                self.console.print(f"  [{t['warn']}]Session locked — re-authenticate[/]\n")
            im   = IdentityManager(self.cfg, self.cx, self.console)
            self.key = im.unlock()
            timeout  = self.cfg["auto_lock_minutes"]
            self.sess = Session(timeout)
            self.al.log("unlock", "Session started", self.key)

    def _touch(self) -> None:
        if self.sess:
            self.sess.touch()

    # ── section header ────────────────────────────────────────────────────────
    def _section(self, title: str) -> None:
        t = self.t()
        self.console.clear()
        _banner(self.console, t)
        _rule(self.console, t, f"  {title}")
        self.console.print()

    # ── cmd: new ──────────────────────────────────────────────────────────────
    def cmd_new(self) -> None:
        t = self.t()
        self._section("New File")

        name = Prompt.ask(f"  [{t['accent']}]Filename[/] [{t['dim']}](no extension)[/]").strip()
        if not name:
            return
        path = self.fm.resolve(name)
        if path.exists():
            self.console.print(f"  [{t['error']}]File already exists: {path.name}[/]")
            return

        title = Prompt.ask(f"  [{t['accent']}]Title[/] [{t['dim']}](blank = same as filename)[/]", default=name).strip()
        tags  = _pick_tags(self.console, t, [])

        self.console.print(f"\n  [{t['dim']}]Opening editor ({self.cfg['editor']})...[/]\n")
        content = _edit_with_editor("", self.cfg["editor"])
        if content is None:
            self.console.print(f"  [{t['dim']}]Cancelled.[/]")
            return

        payload = self.fm.new_payload(title or name, content, tags)
        self.ui.preview(payload)
        self.console.print()

        word_count = len(content.split())
        self.console.print(f"  [{t['dim']}]{word_count:,} words · {len(content):,} chars[/]\n")

        if not Confirm.ask(f"  [{t['accent']}]Save as {path.name}?[/]", default=True):
            self.console.print(f"  [{t['dim']}]Discarded.[/]")
            return

        self.fm.write(path, payload, self.key)
        self.al.log("new", path.stem, self.key)
        self.console.print(f"\n  [{t['success']}]✓[/] Saved → [dim]{path}[/]")
        self._touch()

    # ── cmd: open ─────────────────────────────────────────────────────────────
    def cmd_open(self) -> None:
        t = self.t()
        self._section("Open File")

        files = self.fm.all_files()
        self.ui.file_table(files, self.key, self.fm)
        path  = self.ui.pick_file(files, "Open")
        if not path:
            return

        try:
            payload = self.fm.read(path, self.key)
        except (InvalidTag, ValueError) as e:
            self.console.print(f"\n  [{t['error']}]✗ {e}[/]")
            return

        self.ui.preview(payload, max_lines=60)
        self.al.log("open", path.stem, self.key)
        self._touch()

    # ── cmd: edit ─────────────────────────────────────────────────────────────
    def cmd_edit(self) -> None:
        t = self.t()
        self._section("Edit File")

        files = self.fm.all_files()
        self.ui.file_table(files, self.key, self.fm)
        path  = self.ui.pick_file(files, "Edit")
        if not path:
            return

        try:
            payload = self.fm.read(path, self.key)
        except (InvalidTag, ValueError) as e:
            self.console.print(f"\n  [{t['error']}]✗ {e}[/]")
            return

        # Optionally edit tags first
        edit_tags = Confirm.ask(f"  [{t['accent']}]Update tags?[/]", default=False)
        new_tags  = _pick_tags(self.console, t, payload.get("tags", [])) if edit_tags else None

        self.console.print(f"\n  [{t['dim']}]Opening {path.name} in {self.cfg['editor']}...[/]\n")
        new_content = _edit_with_editor(payload.get("content", ""), self.cfg["editor"])
        if new_content is None:
            self.console.print(f"  [{t['dim']}]Cancelled.[/]")
            return

        if new_content == payload.get("content", "") and new_tags is None:
            self.console.print(f"  [{t['dim']}]No changes.[/]")
            return

        updated = self.fm.update_content(payload, new_content, new_tags)
        self.ui.preview(updated)
        self.console.print()

        word_count = len(new_content.split())
        self.console.print(f"  [{t['dim']}]{word_count:,} words · {len(new_content):,} chars[/]\n")

        if not Confirm.ask(f"  [{t['accent']}]Save changes?[/]", default=True):
            self.console.print(f"  [{t['dim']}]Discarded.[/]")
            return

        self.fm.write(path, updated, self.key)
        self.al.log("edit", path.stem, self.key)
        self.console.print(f"\n  [{t['success']}]✓[/] Saved.")
        self._touch()

    # ── cmd: list ─────────────────────────────────────────────────────────────
    def cmd_list(self) -> None:
        self._section("All Files")
        files = self.fm.all_files()
        self.ui.file_table(files, self.key, self.fm)
        self._touch()

    # ── cmd: info ─────────────────────────────────────────────────────────────
    def cmd_info(self) -> None:
        t = self.t()
        self._section("File Info")

        files = self.fm.all_files()
        self.ui.file_table(files, self.key, self.fm)
        path  = self.ui.pick_file(files, "Info")
        if not path:
            return

        try:
            payload = self.fm.read(path, self.key)
        except (InvalidTag, ValueError) as e:
            self.console.print(f"\n  [{t['error']}]✗ {e}[/]")
            return

        self.ui.show_info(path, payload)
        self._touch()

    # ── cmd: search ───────────────────────────────────────────────────────────
    def cmd_search(self) -> None:
        t = self.t()
        self._section("Search")

        query = Prompt.ask(f"  [{t['accent']}]Query[/] [{t['dim']}](title · tags · content)[/]").strip()
        if not query:
            return

        with self.console.status(f"  [{t['dim']}]Searching {len(self.fm.all_files())} files...[/]", spinner="dots"):
            results = self.fm.search(query, self.key)

        self.ui.search_results(query, results)
        self.al.log("search", query, self.key)
        self._touch()

    # ── cmd: tags ─────────────────────────────────────────────────────────────
    def cmd_tags(self) -> None:
        t = self.t()
        self._section("Tag Browser")

        with self.console.status(f"  [{t['dim']}]Loading tags...[/]", spinner="dots"):
            tags = self.fm.all_tags(self.key)

        selected = self.ui.tag_browser(tags)
        if not selected:
            return

        self.console.print()
        with self.console.status(f"  [{t['dim']}]Filtering by tag: {selected}...[/]", spinner="dots"):
            results = self.fm.files_by_tag(selected, self.key)

        if not results:
            self.console.print(f"  [{t['dim']}]No files with tag '{selected}'.[/]")
            return

        tbl = Table(
            box=box.SIMPLE, show_header=True,
            header_style=t["label"], padding=(0, 2), show_edge=False,
        )
        tbl.add_column("#",    style=t["index"], width=4, justify="right")
        tbl.add_column("Name", style=t["accent"])
        tbl.add_column("Modified", style=t["date"])
        tbl.add_column("Words", style=t["size"], justify="right")

        for i, (f, p) in enumerate(results, 1):
            tbl.add_row(
                str(i), escape(f.stem),
                p.get("modified", "—")[:16],
                str(len(p.get("content", "").split())),
            )
        self.console.print(tbl)
        self.console.print(f"\n  [{t['dim']}]{len(results)} file{'s' if len(results) != 1 else ''} tagged [{t['tag']}]{selected}[/][/{t['dim']}][/]")
        self._touch()

    # ── cmd: versions ─────────────────────────────────────────────────────────
    def cmd_versions(self) -> None:
        t = self.t()
        self._section("Version History")

        files = self.fm.all_files()
        self.ui.file_table(files, self.key, self.fm)
        path  = self.ui.pick_file(files, "Versions")
        if not path:
            return

        try:
            payload = self.fm.read(path, self.key)
        except (InvalidTag, ValueError) as e:
            self.console.print(f"\n  [{t['error']}]✗ {e}[/]")
            return

        version = self.ui.show_versions(payload)
        if version is None:
            return

        self.console.print(f"\n  [{t['dim']}]Restoring version from {version.get('modified', '—')[:16]}...[/]")
        self.ui.preview({"title": payload.get("title", ""), "content": version["content"],
                         "tags": payload.get("tags", []), "modified": version.get("modified", "")})
        self.console.print()

        if Confirm.ask(f"  [{t['warn']}]Restore this version? (current becomes history)[/]", default=False):
            updated = self.fm.update_content(payload, version["content"])
            self.fm.write(path, updated, self.key)
            self.al.log("restore", path.stem, self.key)
            self.console.print(f"  [{t['success']}]✓[/] Version restored.")

        self._touch()

    # ── cmd: rename ───────────────────────────────────────────────────────────
    def cmd_rename(self) -> None:
        t = self.t()
        self._section("Rename File")

        files = self.fm.all_files()
        self.ui.file_table(files, self.key, self.fm)
        path  = self.ui.pick_file(files, "Rename")
        if not path:
            return

        try:
            self.fm.read(path, self.key)   # verify decryptable
        except (InvalidTag, ValueError) as e:
            self.console.print(f"\n  [{t['error']}]✗ {e}[/]")
            return

        new_name = Prompt.ask(f"\n  [{t['accent']}]New filename[/] [{t['dim']}](no extension)[/]").strip()
        if not new_name:
            return

        new_path = self.fm.resolve(new_name, str(path.parent.relative_to(VAULT_DIR)) if path.parent != VAULT_DIR else "")
        if new_path.exists():
            if not Confirm.ask(f"  [{t['warn']}]{new_path.name} exists. Overwrite?[/]", default=False):
                return

        path.rename(new_path)
        os.chmod(new_path, 0o600)
        self.al.log("rename", f"{path.stem} → {new_name}", self.key)
        self.console.print(f"\n  [{t['success']}]✓[/] Renamed  [dim]{path.stem}[/] → [dim]{new_name}[/]")
        self._touch()

    # ── cmd: move ─────────────────────────────────────────────────────────────
    def cmd_move(self) -> None:
        t = self.t()
        self._section("Move File")

        files = self.fm.all_files()
        self.ui.file_table(files, self.key, self.fm)
        path  = self.ui.pick_file(files, "Move")
        if not path:
            return

        folders = self.fm.all_folders()
        self.console.print(f"\n  [{t['dim']}]Folders: {', '.join(f or '(root)' for f in folders)}[/]")
        dest_folder = Prompt.ask(
            f"  [{t['accent']}]Destination folder[/] [{t['dim']}](blank = root)[/]",
            default="",
        ).strip()

        dest_dir = VAULT_DIR / dest_folder if dest_folder else VAULT_DIR
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = dest_dir / path.name

        if dest_path.exists():
            if not Confirm.ask(f"  [{t['warn']}]{dest_path.name} exists here. Overwrite?[/]", default=False):
                return

        shutil.move(str(path), str(dest_path))
        os.chmod(dest_path, 0o600)
        self.al.log("move", f"{path.stem} → {dest_folder or 'root'}", self.key)
        self.console.print(f"\n  [{t['success']}]✓[/] Moved to [dim]{dest_path}[/]")
        self._touch()

    # ── cmd: delete ───────────────────────────────────────────────────────────
    def cmd_delete(self) -> None:
        t = self.t()
        self._section("Secure Delete")

        files = self.fm.all_files()
        self.ui.file_table(files, self.key, self.fm)
        path  = self.ui.pick_file(files, "Delete")
        if not path:
            return

        passes = self.cfg["secure_delete_passes"]
        self.console.print(f"\n  [{t['warn']}]This will[/] permanently destroy [{t['error']}]{path.name}[/]")
        self.console.print(f"  [{t['dim']}]{passes}-pass overwrite. No recovery possible.[/]\n")

        if not Confirm.ask(f"  [{t['error']}]Confirm deletion?[/]", default=False):
            self.console.print(f"  [{t['dim']}]Cancelled.[/]")
            return

        confirm_name = Prompt.ask(f"  [{t['accent']}]Type filename to confirm[/]").strip()
        if confirm_name != path.stem:
            self.console.print(f"  [{t['error']}]Name mismatch. Aborted.[/]")
            return

        with self.console.status(f"  [{t['dim']}]Overwriting {passes}×...[/]", spinner="dots"):
            self.fm.secure_delete(path, passes)

        self.al.log("delete", path.stem, self.key)
        self.console.print(f"\n  [{t['success']}]✓[/] Securely deleted.")
        self._touch()

    # ── cmd: export ───────────────────────────────────────────────────────────
    def cmd_export(self) -> None:
        t = self.t()
        self._section("Export Plaintext")

        files = self.fm.all_files()
        self.ui.file_table(files, self.key, self.fm)
        path  = self.ui.pick_file(files, "Export")
        if not path:
            return

        self.console.print(f"\n  [{t['warn']}]Warning: exported file will be unencrypted plaintext.[/]")
        if not Confirm.ask(f"  [{t['accent']}]Continue?[/]", default=False):
            return

        try:
            out = self.fm.export_plaintext(path, self.key)
        except (InvalidTag, ValueError) as e:
            self.console.print(f"\n  [{t['error']}]✗ {e}[/]")
            return

        self.al.log("export", path.stem, self.key)
        self.console.print(f"\n  [{t['success']}]✓[/] Exported → [dim]{out}[/]")
        self.console.print(f"  [{t['warn']}]⚠  Delete this file after use.[/]")
        self._touch()

    # ── cmd: import ───────────────────────────────────────────────────────────
    def cmd_import(self) -> None:
        t = self.t()
        self._section("Import File")

        src_str = Prompt.ask(f"  [{t['accent']}]Source .txt file path[/]").strip()
        if not src_str:
            return
        src = Path(src_str).expanduser()
        if not src.exists():
            self.console.print(f"  [{t['error']}]File not found: {src}[/]")
            return

        name  = Prompt.ask(f"  [{t['accent']}]Vault filename[/] [{t['dim']}](no extension)[/]", default=src.stem).strip()
        title = Prompt.ask(f"  [{t['accent']}]Title[/]", default=name).strip()
        tags  = _pick_tags(self.console, t, [])

        try:
            dest = self.fm.import_text(src, self.key, name, tags)
        except FileExistsError as e:
            self.console.print(f"\n  [{t['error']}]{e}[/]")
            return

        self.al.log("import", f"{src.name} → {name}", self.key)
        self.console.print(f"\n  [{t['success']}]✓[/] Imported → [dim]{dest}[/]")
        self._touch()

    # ── cmd: batch ────────────────────────────────────────────────────────────
    def cmd_batch(self) -> None:
        t = self.t()
        self._section("Batch Operations")

        files = self.fm.all_files()
        self.ui.file_table(files, self.key, self.fm)
        if not files:
            return

        self.console.print(f"\n  [{t['dim']}]Enter file numbers separated by commas (e.g. 1,3,5)[/]")
        raw = Prompt.ask(f"  [{t['accent']}]Select files[/]").strip()
        if not raw:
            return

        indices = []
        for part in raw.split(","):
            part = part.strip()
            if part.isdigit():
                idx = int(part) - 1
                if 0 <= idx < len(files):
                    indices.append(idx)

        if not indices:
            self.console.print(f"  [{t['error']}]No valid selections.[/]")
            return

        selected = [files[i] for i in indices]
        self.console.print(f"\n  [{t['accent']}]Selected:[/] {', '.join(f.stem for f in selected)}")
        self.console.print()

        action = Prompt.ask(
            f"  [{t['accent']}]Action[/] [{t['dim']}](d=delete, x=export, blank=cancel)[/]",
            default="",
        ).strip().lower()

        if action == "d":
            passes = self.cfg["secure_delete_passes"]
            if not Confirm.ask(f"  [{t['error']}]Securely delete {len(selected)} file(s)?[/]", default=False):
                return
            for f in selected:
                with self.console.status(f"  [{t['dim']}]Deleting {f.stem}...[/]", spinner="dots"):
                    self.fm.secure_delete(f, passes)
                self.al.log("batch-delete", f.stem, self.key)
                self.console.print(f"  [{t['success']}]✓[/] {f.stem}")

        elif action == "x":
            if not Confirm.ask(f"  [{t['warn']}]Export {len(selected)} file(s) as plaintext?[/]", default=False):
                return
            for f in selected:
                try:
                    out = self.fm.export_plaintext(f, self.key)
                    self.al.log("batch-export", f.stem, self.key)
                    self.console.print(f"  [{t['success']}]✓[/] {f.stem} → [dim]{out.name}[/]")
                except Exception as e:
                    self.console.print(f"  [{t['error']}]✗[/] {f.stem}: {e}")
        else:
            self.console.print(f"  [{t['dim']}]Cancelled.[/]")

        self._touch()

    # ── cmd: stats ────────────────────────────────────────────────────────────
    def cmd_stats(self) -> None:
        t = self.t()
        self._section("Vault Statistics")
        with self.console.status(f"  [{t['dim']}]Analyzing vault...[/]", spinner="dots"):
            self.ui.stats_dashboard(self.key, self.fm)
        self._touch()

    # ── cmd: log ──────────────────────────────────────────────────────────────
    def cmd_log(self) -> None:
        t = self.t()
        self._section("Activity Log")
        entries = self.al.get_recent(self.key, n=40)
        self.ui.log_view(entries)
        self._touch()

    # ── cmd: settings ─────────────────────────────────────────────────────────
    def cmd_settings(self) -> None:
        self._section("Settings")
        self.ui.settings_menu(self.cfg)
        self._touch()

    # ── cmd: help ─────────────────────────────────────────────────────────────
    def cmd_help(self) -> None:
        self._section("Help")
        self.ui.help_screen()

    # ── cmd: lock ─────────────────────────────────────────────────────────────
    def cmd_lock(self) -> None:
        if self.sess:
            self.sess.lock()
        t = self.t()
        self.console.print(f"\n  [{t['warn']}]Session locked.[/]")

    # ── cmd dispatch ──────────────────────────────────────────────────────────
    COMMANDS = {
        "n": cmd_new,
        "o": cmd_open,
        "e": cmd_edit,
        "l": cmd_list,
        "s": cmd_search,
        "t": cmd_tags,
        "i": cmd_info,
        "v": cmd_versions,
        "r": cmd_rename,
        "m": cmd_move,
        "d": cmd_delete,
        "x": cmd_export,
        "/": cmd_import,
        "b": cmd_batch,
        "S": cmd_stats,
        "L": cmd_log,
        "!": cmd_settings,
        "?": cmd_help,
        "k": cmd_lock,
    }

    # ── main loop ─────────────────────────────────────────────────────────────
    def run(self) -> None:
        self.console.clear()
        t = self.t()
        _banner(self.console, t)
        _rule(self.console, t)

        # Initial authentication
        im       = IdentityManager(self.cfg, self.cx, self.console)
        self.key = im.unlock()
        timeout  = self.cfg["auto_lock_minutes"]
        self.sess = Session(timeout)
        self.al.log("launch", f"NYDIX v{APP_VERSION}", self.key)

        while True:
            # Check auto-lock
            if self.sess.is_locked():
                self._require_auth()

            # Dashboard
            self.console.clear()
            self.ui.dashboard(self.key, self.fm, self.al, self.sess)

            # Prompt
            try:
                choice = Prompt.ask(
                    f"\n  [{t['key']}]→[/]",
                    default="q",
                ).strip()
            except (KeyboardInterrupt, EOFError):
                choice = "q"

            if choice == "q":
                self.al.log("quit", "", self.key)
                self.console.print(f"\n  [{t['dim']}]Goodbye.[/]\n")
                # Zero key in memory as best we can
                self.key = b"\x00" * len(self.key)
                del self.key
                sys.exit(0)

            fn = self.COMMANDS.get(choice)
            if fn:
                try:
                    fn(self)
                except KeyboardInterrupt:
                    self.console.print(f"\n  [{t['dim']}]Cancelled.[/]")
                except Exception as ex:
                    self.console.print(f"\n  [{t['error']}]Error: {escape(str(ex))}[/]")
                _pause(self.console)
            elif choice:
                self.console.print(f"\n  [{t['dim']}]Unknown command '{choice}' — press [?] for help[/]")
                time.sleep(0.8)


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    try:
        NYDIX().run()
    except KeyboardInterrupt:
        print("\n\n  Interrupted.\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n  [fatal] {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
PYEOF

chmod 600 "$NYDIX_LIB"
echo "  [nydix] nydix.py written ($(wc -l < "$NYDIX_LIB") lines)"

# ── Write launcher ────────────────────────────────────────────────────────────
cat > "$NYDIX_BIN" << SHEOF
#!/data/data/com.termux/files/usr/bin/bash
exec python3 "$NYDIX_LIB" "\$@"
SHEOF
chmod 700 "$NYDIX_BIN"
echo "  [nydix] Launcher → $NYDIX_BIN"

# ── PATH check ────────────────────────────────────────────────────────────────
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo ""
    echo "  ── Add to ~/.bashrc or ~/.zshrc ───────────────────────"
    echo '  export PATH="$HOME/.local/bin:$PATH"'
    echo "  ────────────────────────────────────────────────────────"
    echo "  Then run:  source ~/.bashrc"
fi

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  NYDIX v2.0 installed                    ║"
echo "  ║  Crypto: AES-256-GCM + Argon2id          ║"
echo "  ║  Type: nydix   to launch                 ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""
