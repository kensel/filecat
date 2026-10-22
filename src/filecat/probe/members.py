"""Shared helpers for archive member rows: role by name, and the summary a
document keeps (the rows themselves go to Backend.put_members).

role is what the member is for, in plain words: script, table, texture,
model, image, audio, video, text, document, archive, exe, data, save,
config, font, shader, dir, volume (a partition of a disk image), unknown. It is decided by the member name unless the
caller already sniffed the member's bytes (then pass `kind` from the probe).
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from ..record import suffix_of

_ROLES: dict[str, tuple[str, ...]] = {
    "script": ("lua", "py", "js", "ts", "gd", "gdc", "cs", "sh", "bat",
               "cmd", "ps1", "psm1", "psd1", "vbs", "pl", "rb", "php", "tcl", "x3s", "kscript", "mel", "jass", "j", "galaxy"),
    "table": ("csv", "tsv", "tbl", "dbc", "db2", "sqlite", "db", "mdb", "slk", "2da"),
    "texture": ("dds", "tga", "ktx", "ktx2", "blp", "vtf", "pvr", "astc", "crn", "stex", "ctex", "tex", "jtx"),
    # X3: .bod body text, .bob binary body, .pbd/.pbb their packed forms.
    "model": ("bob", "bod", "pbd", "pbb", "obj", "fbx", "gltf", "glb", "dae", "3ds", "stl", "ply", "m2", "mdx",
              "mdl", "wmo", "nif", "mesh", "x", "blend", "msh", "smd", "md3", "md5mesh", "iqm"),
    "image": ("png", "jpg", "jpeg", "gif", "bmp", "tif", "tiff", "webp", "ico", "psd", "svg", "heic", "pcx"),
    "audio": ("wav", "mp3", "ogg", "flac", "wma", "m4a", "aac", "opus", "mid", "midi", "xm", "it", "s3m",
              "mod", "wem", "bnk", "fsb", "snd"),
    "video": ("mp4", "mkv", "avi", "mov", "wmv", "webm", "bik", "bk2", "smk", "mpg", "mpeg", "m4v", "ogv"),
    "text": ("txt", "md", "log", "nfo", "rtf", "readme"),
    "config": ("ini", "cfg", "conf", "json", "yaml", "yml", "toml", "xml", "plist", "reg", "properties",
               "tres", "tscn", "import", "godot", "inf", "man", "admx", "adml", "xsl", "xslt", "mof"),
    "document": ("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "epub", "chm"),
    "archive": ("zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "xz", "mpq", "pck", "pak", "cab", "cat",
                "iso", "jar", "apk", "wim", "esd", "swm", "msi", "msu", "msp", "rpm", "deb",
                "squashfs", "sfs", "img", "vhd", "vhdx", "vmdk", "sdi", "appx", "msix"),
    "exe": ("exe", "dll", "sys", "so", "dylib", "ocx", "scr", "com", "elf", "efi", "mui", "drv", "cpl",
            "ko"),
    "font": ("ttf", "otf", "fnt", "woff", "woff2", "pf2"),
    "shader": ("hlsl", "glsl", "fx", "fxo", "vert", "frag", "cso", "spv", "shader", "gdshader"),
    "save": ("sav", "save", "xsa"),
}
_BY_SUFFIX = {ext: role for role, exts in _ROLES.items() for ext in exts}

# Probe kinds that map straight onto a role when the bytes were sniffed.
_KIND_ROLE = {"texture": "texture", "mesh": "model", "image": "image", "audio": "audio",
              "video": "video", "document": "document", "archive": "archive", "exe": "exe",
              "data": "table", "save": "save", "text": "text"}


def member_role(path: str, kind: str | None = None) -> str:
    """Role of one member. A sniffed `kind` wins over the name, except that a
    text kind keeps a more specific name role (script, config, table, shader)."""
    if path.endswith(("/", "\\")):
        return "dir"
    by_name = _BY_SUFFIX.get(suffix_of(path.replace("\\", "/").rsplit("/", 1)[-1]), "unknown")
    if kind is None or kind == "unknown":
        return by_name
    if kind == "text" and by_name in ("script", "config", "table", "shader", "text"):
        return by_name
    return _KIND_ROLE.get(kind, by_name)


def summarize(members: list[dict[str, Any]], *, truncated: bool, list_cap: int) -> dict[str, Any]:
    """Probe keys an archive document keeps about its members."""
    roles = Counter(m.get("role") or member_role(m["path"], m.get("kind")) for m in members)
    out: dict[str, Any] = {
        "members_count": len(members),
        "member_roles": dict(roles.most_common()),
        "entries": [m["path"] for m in members[:list_cap]],
    }
    sizes = [m["size"] for m in members if isinstance(m.get("size"), int)]
    if sizes:
        out["members_size"] = sum(sizes)
    if truncated:
        out["members_truncated"] = True
    return out
