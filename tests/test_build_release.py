"""The verifier's own release archives (tools/build_release.py): the
rewriting that makes the source archive the same on any checkout, without
building (the full two-build comparison runs in its own CI job)."""

import importlib.util
import io
import tarfile
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("build_release", Path(__file__).resolve().parent.parent / "tools" / "build_release.py")
build_release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_release)


def _sdist(order, mtime: float, mode: int, owner: str) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz", format=tarfile.PAX_FORMAT) as tar:
        for name in order:
            info = tarfile.TarInfo(name)
            info.mtime, info.uname, info.gname, info.uid = mtime, owner, owner, 1000
            if name.endswith("/"):
                info.type, info.mode = tarfile.DIRTYPE, 0o700
                info.name = name.rstrip("/")
                tar.addfile(info)
            else:
                data = name.encode()
                info.size, info.mode = len(data), mode
                tar.addfile(info, io.BytesIO(data))
    return out.getvalue()


def test_the_source_archive_depends_on_neither_checkout_nor_clock():
    a = _sdist(["p-1/", "p-1/b.py", "p-1/a.py"], 1792138048.76, 0o600, "alice")
    b = _sdist(["p-1/", "p-1/a.py", "p-1/b.py"], 1000.5, 0o664, "bob")
    assert a != b
    na, nb = build_release.normalize_sdist(a, 1700000000), build_release.normalize_sdist(b, 1700000000)
    assert na == nb
    with tarfile.open(fileobj=io.BytesIO(na)) as tar:
        members = tar.getmembers()
        assert [m.name for m in members] == ["p-1", "p-1/a.py", "p-1/b.py"]
        assert {(m.mtime, m.uid, m.uname, m.mode) for m in members[1:]} == {(1700000000, 0, "", 0o644)}
        assert members[0].mode == 0o755 and not any(m.pax_headers for m in members)
    assert na[4:8] == b"\0\0\0\0"  # gzip header time
    assert build_release.normalize_sdist(a, 1700000001) != na


def test_unpacking_refuses_paths_outside(tmp_path):
    bad = _sdist(["p-1/", "p-1/../escape.py"], 0, 0o644, "x")
    with pytest.raises(ValueError):
        build_release._unpack(bad, tmp_path)


def test_compare_names_what_differs(tmp_path):
    (tmp_path / "a.tar.gz").write_bytes(build_release.normalize_sdist(_sdist(["p-1/", "p-1/a.py"], 0, 0o644, "x"), 1))
    (tmp_path / "b.tar.gz").write_bytes(build_release.normalize_sdist(_sdist(["p-1/", "p-1/a.py", "p-1/c.py"], 0, 0o644, "x"), 2))
    problems = build_release.compare(tmp_path / "a.tar.gz", tmp_path / "b.tar.gz")
    assert "only in b.tar.gz: p-1/c.py" in problems and "p-1/a.py: time differs (1 and 2)" in problems
