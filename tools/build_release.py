"""Build fm-verify's wheel and source archive so that anyone can rebuild them
byte for byte from the same commit, and so check a release without trusting
whoever published it.

    python tools/build_release.py [OUT_DIR]        build both into OUT_DIR (default dist/), print their SHA-256
    python tools/build_release.py --compare A B    compare two wheels or two source archives by what they hold

SOURCE_DATE_EPOCH is the commit's time (``git log -1 --format=%ct``) unless
it is set. The source archive is setuptools' own (pinned in pyproject.toml),
rewritten: entries in path order, every timestamp SOURCE_DATE_EPOCH, owner 0
with no names, modes 0644 and 0755, POSIX ustar headers, and gzip with no
file name or time. The wheel is built by setuptools from that archive,
unpacked with its own modes (as pip would install from it), under umask
022, so the checkout's file times and modes and the builder's umask reach
neither. Needs the ``build`` package
and network access for the pinned setuptools.

Compressed bytes also depend on the zlib that compressed them; on a machine
whose zlib differs, ``--compare`` checks what the archives hold (names,
modes, times and every byte), whatever compressed them.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def epoch() -> int:
    if os.environ.get("SOURCE_DATE_EPOCH"):
        return int(os.environ["SOURCE_DATE_EPOCH"])
    out = subprocess.run(["git", "log", "-1", "--format=%ct"], cwd=ROOT, capture_output=True, text=True, check=True)
    return int(out.stdout.strip())


def normalize_sdist(data: bytes, when: int) -> bytes:
    """setuptools' source archive with its entries in path order and every
    field that depends on the checkout or the clock fixed."""
    entries = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for m in tar.getmembers():
            if not (m.isdir() or m.isfile()):
                raise ValueError(f"{m.name}: only files and directories belong in the source archive")
            entries.append((m.name, m.isdir(), m.mode, tar.extractfile(m).read() if m.isfile() else b""))
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, is_dir, mode, content in sorted(entries):
            info = tarfile.TarInfo(name)
            info.mtime, info.uid, info.gid, info.uname, info.gname = when, 0, 0, "", ""
            if is_dir:
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                tar.addfile(info)
            else:
                info.mode, info.size = (0o755 if mode & 0o111 else 0o644), len(content)
                tar.addfile(info, io.BytesIO(content))
    packed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=packed, compresslevel=9, mtime=0) as gz:
        gz.write(out.getvalue())
    return packed.getvalue()


def _run_build(args: list[str], env: dict) -> None:
    # setuptools copies modules into its build directory without their modes,
    # so the process's umask would reach the wheel; fix it.
    old = os.umask(0o022)
    try:
        done = subprocess.run([sys.executable, "-m", "build", *args], cwd=ROOT, env=env, capture_output=True, text=True)
    finally:
        os.umask(old)
    if done.returncode:
        sys.stderr.write(done.stdout[-4000:] + done.stderr[-4000:])
        raise SystemExit(f"python -m build {' '.join(args)} failed")


def _unpack(data: bytes, into: Path) -> Path:
    """The source archive's files, with the archive's own modes; returns its top directory."""
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        tops = {m.name.split("/", 1)[0] for m in tar.getmembers()}
        if len(tops) != 1:
            raise ValueError("the source archive does not hold one top directory")
        for m in tar.getmembers():
            if m.name.startswith("/") or ".." in m.name.split("/"):
                raise ValueError(f"{m.name}: a path outside the archive")
            target = into / m.name
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(tar.extractfile(m).read())
            target.chmod(m.mode)
    return into / tops.pop()


def build(out_dir: Path) -> list[Path]:
    when = epoch()
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    if dirty:
        print("note: the checkout has changes, so this is not the tree of any commit", file=sys.stderr)
    env = dict(os.environ, SOURCE_DATE_EPOCH=str(when))
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        _run_build(["--sdist", "--outdir", f"{tmp}/sdist", str(ROOT)], env)
        for leftover in ROOT.glob("src/*.egg-info"):
            shutil.rmtree(leftover)
        (raw,) = Path(tmp, "sdist").glob("*.tar.gz")
        sdist = out_dir / raw.name
        sdist.write_bytes(normalize_sdist(raw.read_bytes(), when))
        source = _unpack(sdist.read_bytes(), Path(tmp, "unpacked"))
        _run_build(["--wheel", "--outdir", f"{tmp}/wheel", str(source)], env)
        (wheel,) = Path(tmp, "wheel").glob("*.whl")
        shutil.copyfile(wheel, out_dir / wheel.name)
    return [out_dir / wheel.name, sdist]


def contents(path: Path) -> dict[str, tuple]:
    """What an archive holds: per entry, its kind, mode, time and bytes."""
    if path.name.endswith(".whl"):
        with zipfile.ZipFile(path) as z:
            return {i.filename: ("file", i.external_attr >> 16, i.date_time, z.read(i)) for i in z.infolist()}
    with tarfile.open(path, mode="r:*") as tar:
        return {m.name: ("dir" if m.isdir() else "file", m.mode, m.mtime, tar.extractfile(m).read() if m.isfile() else b"")
                for m in tar.getmembers()}


def compare(a: Path, b: Path) -> list[str]:
    ca, cb = contents(a), contents(b)
    problems = [f"only in {a.name}: {n}" for n in sorted(ca.keys() - cb.keys())]
    problems += [f"only in {b.name}: {n}" for n in sorted(cb.keys() - ca.keys())]
    for n in sorted(ca.keys() & cb.keys()):
        for what, x, y in zip(("kind", "mode", "time", "bytes"), ca[n], cb[n]):
            if x != y:
                problems.append(f"{n}: {what} differs" + ("" if what == "bytes" else f" ({x!r} and {y!r})"))
    return problems


def main(argv: list[str]) -> int:
    if argv[:1] == ["--compare"]:
        if len(argv) != 3:
            print(__doc__, file=sys.stderr)
            return 2
        problems = compare(Path(argv[1]), Path(argv[2]))
        for p in problems:
            print(p)
        print("the archives hold the same entries, byte for byte" if not problems else f"{len(problems)} differences")
        return 1 if problems else 0
    if len(argv) > 1:
        print(__doc__, file=sys.stderr)
        return 2
    for p in build(Path(argv[0]) if argv else ROOT / "dist"):
        print(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
