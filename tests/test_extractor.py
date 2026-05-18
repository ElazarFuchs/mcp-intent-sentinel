"""Unit tests for the source extractor."""
from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

import pytest

from mis.extractors import ExtractionError, extract


def test_local_dir(tmp_path: Path) -> None:
    (tmp_path / "x.py").write_text("# hi", encoding="utf-8")
    with extract(str(tmp_path)) as src:
        assert src.root == tmp_path
        assert src.scheme == "file"
        assert (src.root / "x.py").exists()


def test_local_tarball(tmp_path: Path) -> None:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "x.py").write_text("# hi", encoding="utf-8")
    archive = tmp_path / "pkg.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(pkg, arcname="pkg")
    with extract(str(archive)) as src:
        assert (src.root / "x.py").exists()


def test_local_zip(tmp_path: Path) -> None:
    archive = tmp_path / "pkg.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("pkg/x.py", "# hi")
    with extract(str(archive)) as src:
        assert (src.root / "x.py").exists()


def test_missing_local_path() -> None:
    with pytest.raises(ExtractionError):
        extract("/this/path/does/not/exist/probably")


def test_unknown_scheme() -> None:
    with pytest.raises(ExtractionError):
        extract("ftp:something")


def test_bad_github_slug() -> None:
    with pytest.raises(ExtractionError):
        extract("github:noslash")


def test_zip_slip_rejected(tmp_path: Path) -> None:
    """Defense against CVE-2007-4559 / zip-slip."""
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../escape.txt", "got you")
    with pytest.raises(ExtractionError):
        with extract(str(archive)):
            pass


def test_tar_slip_rejected(tmp_path: Path) -> None:
    """Defense against tar member escapes."""
    archive = tmp_path / "evil.tar.gz"
    # Build a tar with an escaping member by writing manually
    with tarfile.open(archive, "w:gz") as tf:
        ti = tarfile.TarInfo(name="../escape.txt")
        data = b"got you"
        ti.size = len(data)
        import io
        tf.addfile(ti, io.BytesIO(data))
    with pytest.raises(ExtractionError):
        with extract(str(archive)):
            pass
