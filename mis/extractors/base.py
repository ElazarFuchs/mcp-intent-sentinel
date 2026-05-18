"""Source-spec parser + dispatch to per-scheme extractors.

A source spec is one of:
- A local path (absolute, relative, or file:// URL) → no extraction
- "github:owner/repo[#ref]"
- "npm:package[@version]"
- "pypi:package[==version]"

The extractor returns an ExtractedSource. The caller is responsible for
calling .cleanup() when done (typically via `with` since ExtractedSource
is a context manager).
"""
from __future__ import annotations

import os
import shutil
import tempfile
import zipfile
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


class ExtractionError(RuntimeError):
    """Raised when source extraction fails for any reason."""


@dataclass
class ExtractedSource:
    """Holds the root directory of an extracted source plus cleanup metadata."""
    root: Path
    source: str          # original spec
    scheme: str          # "file" | "github" | "npm" | "pypi"
    cleanup_dir: Optional[Path] = None  # if set, .cleanup() rmtree's it

    def __enter__(self) -> "ExtractedSource":
        return self

    def __exit__(self, *_exc) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        if self.cleanup_dir and self.cleanup_dir.exists():
            shutil.rmtree(self.cleanup_dir, ignore_errors=True)
            self.cleanup_dir = None


def extract(source: str) -> ExtractedSource:
    """Resolve `source` to a local directory containing the server source.

    The caller MUST call ExtractedSource.cleanup() when done, or use
    `with extract(source) as src: ...`.
    """
    if not source:
        raise ExtractionError("empty source spec")

    # file:// or plain local path
    if source.startswith("file://"):
        path_str = source[len("file://"):]
        return _extract_local(Path(path_str), source)
    if not _looks_like_scheme(source):
        # Treat as local path (absolute or relative)
        return _extract_local(Path(source), source)

    scheme, rest = source.split(":", 1)
    scheme = scheme.lower()

    if scheme == "github":
        return _extract_github(rest, source)
    if scheme == "npm":
        return _extract_npm(rest, source)
    if scheme == "pypi":
        return _extract_pypi(rest, source)

    raise ExtractionError(
        f"unknown source scheme '{scheme}'. Supported: file, github, npm, pypi. "
        f"See LIMITATIONS.md L1 for what is NOT supported in v0.1."
    )


def _looks_like_scheme(source: str) -> bool:
    """Return True iff `source` starts with a supported scheme prefix."""
    if ":" not in source:
        return False
    head = source.split(":", 1)[0].lower()
    return head in {"file", "github", "npm", "pypi"}


def _extract_local(path: Path, source: str) -> ExtractedSource:
    path = path.expanduser().resolve()
    if not path.exists():
        raise ExtractionError(f"local path does not exist: {path}")

    if path.is_dir():
        return ExtractedSource(root=path, source=source, scheme="file")

    # If it's an archive, extract to tempdir
    suffixes = [s.lower() for s in path.suffixes]
    if suffixes[-2:] == [".tar", ".gz"] or suffixes[-1:] == [".tgz"]:
        tmp = Path(tempfile.mkdtemp(prefix="mis_local_tgz_"))
        try:
            with tarfile.open(path, "r:gz") as tf:
                _safe_extract_tar(tf, tmp)
        except (tarfile.TarError, OSError) as e:
            shutil.rmtree(tmp, ignore_errors=True)
            raise ExtractionError(f"failed to extract tarball {path}: {e}") from e
        return ExtractedSource(root=_first_subdir_or(tmp), source=source, scheme="file", cleanup_dir=tmp)

    if suffixes[-1:] == [".zip"]:
        tmp = Path(tempfile.mkdtemp(prefix="mis_local_zip_"))
        try:
            with zipfile.ZipFile(path, "r") as zf:
                _safe_extract_zip(zf, tmp)
        except (zipfile.BadZipFile, OSError) as e:
            shutil.rmtree(tmp, ignore_errors=True)
            raise ExtractionError(f"failed to extract zip {path}: {e}") from e
        return ExtractedSource(root=_first_subdir_or(tmp), source=source, scheme="file", cleanup_dir=tmp)

    raise ExtractionError(
        f"local path is a file but not a recognized archive (.tar.gz, .tgz, .zip): {path}"
    )


def _first_subdir_or(path: Path) -> Path:
    """If `path` contains exactly one subdirectory, return it; else return path itself.

    npm/pypi tarballs typically extract to a single top-level dir
    (e.g., package/, foo-1.2.3/); using that subdir as the analysis root keeps
    paths in findings short and meaningful.
    """
    entries = list(path.iterdir())
    subdirs = [e for e in entries if e.is_dir()]
    if len(subdirs) == 1 and len(entries) == 1:
        return subdirs[0]
    return path


def _extract_github(rest: str, source: str) -> ExtractedSource:
    """github:owner/repo[#ref] → shallow clone."""
    import subprocess  # local import — only needed for this scheme

    if "#" in rest:
        slug, ref = rest.split("#", 1)
    else:
        slug, ref = rest, None
    if slug.count("/") != 1 or not all(slug.split("/")):
        raise ExtractionError(f"bad github slug '{slug}'. Expected 'owner/repo'.")

    tmp = Path(tempfile.mkdtemp(prefix="mis_gh_"))
    url = f"https://github.com/{slug}.git"
    git_exe = shutil.which("git") or "git"
    cmd = [git_exe, "clone", "--depth", "1"]
    if ref:
        cmd += ["--branch", ref]
    cmd += [url, str(tmp / "repo")]
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=120)
    except FileNotFoundError as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ExtractionError("git not found on PATH — required for github: scheme") from e
    except subprocess.CalledProcessError as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ExtractionError(f"git clone failed: {e.stderr.decode('utf-8', errors='replace')[:200]}") from e
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ExtractionError("git clone timed out after 60s")

    return ExtractedSource(root=tmp / "repo", source=source, scheme="github", cleanup_dir=tmp)


def _extract_npm(rest: str, source: str) -> ExtractedSource:
    """npm:package[@version] → `npm pack` + extract tarball.

    `npm pack` downloads the tarball without running install scripts of
    dependencies, which is important — we do NOT want to execute arbitrary
    postinstall hooks during scan setup.
    """
    import subprocess

    tmp = Path(tempfile.mkdtemp(prefix="mis_npm_"))
    # On Windows, `npm` is `npm.cmd` — `subprocess.run` without shell=True
    # won't resolve PATHEXT, so we look up the full path. `shutil.which`
    # handles PATHEXT correctly on Windows.
    npm_exe = shutil.which("npm") or "npm"
    try:
        # npm pack outputs the tarball name (e.g., foo-1.2.3.tgz) on stdout
        result = subprocess.run(
            [npm_exe, "pack", "--silent", rest],
            check=True, capture_output=True, timeout=120, cwd=tmp,
        )
        tarball_name = result.stdout.decode("utf-8", errors="replace").strip().splitlines()[-1]
        tarball = tmp / tarball_name
        if not tarball.exists():
            raise ExtractionError(f"npm pack reported {tarball_name} but file missing")
        extract_dir = tmp / "extracted"
        extract_dir.mkdir()
        with tarfile.open(tarball, "r:gz") as tf:
            _safe_extract_tar(tf, extract_dir)
    except FileNotFoundError as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ExtractionError("npm not found on PATH — required for npm: scheme") from e
    except subprocess.CalledProcessError as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ExtractionError(f"npm pack failed: {e.stderr.decode('utf-8', errors='replace')[:200]}") from e
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ExtractionError("npm pack timed out after 60s")
    except (tarfile.TarError, OSError) as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ExtractionError(f"failed to extract npm tarball: {e}") from e

    return ExtractedSource(root=_first_subdir_or(extract_dir), source=source, scheme="npm", cleanup_dir=tmp)


def _extract_pypi(rest: str, source: str) -> ExtractedSource:
    """pypi:package[==version] → `pip download --no-deps --no-binary :all:`.

    --no-deps        : we don't want to fetch the dep tree, only this package
    --no-binary :all: : prefer sdist so we get source files, not compiled wheels
    """
    import subprocess

    tmp = Path(tempfile.mkdtemp(prefix="mis_pypi_"))
    pip_exe = shutil.which("pip") or "pip"
    try:
        subprocess.run(
            [
                pip_exe, "download", "--no-deps", "--no-binary", ":all:",
                "--dest", str(tmp), rest,
            ],
            check=True, capture_output=True, timeout=120,
        )
        # Find the downloaded archive
        archives = [
            p for p in tmp.iterdir()
            if p.suffix in {".gz", ".tgz", ".zip"} or p.name.endswith(".tar.gz")
        ]
        if not archives:
            raise ExtractionError(f"pip download succeeded but no archive found in {tmp}")
        archive = archives[0]
        extract_dir = tmp / "extracted"
        extract_dir.mkdir()
        if archive.name.endswith((".tar.gz", ".tgz")):
            with tarfile.open(archive, "r:gz") as tf:
                _safe_extract_tar(tf, extract_dir)
        elif archive.suffix == ".zip":
            with zipfile.ZipFile(archive, "r") as zf:
                _safe_extract_zip(zf, extract_dir)
        else:
            raise ExtractionError(f"unsupported pip archive type: {archive.name}")
    except FileNotFoundError as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ExtractionError("pip not found on PATH — required for pypi: scheme") from e
    except subprocess.CalledProcessError as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ExtractionError(f"pip download failed: {e.stderr.decode('utf-8', errors='replace')[:200]}") from e
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ExtractionError("pip download timed out after 60s")
    except (tarfile.TarError, zipfile.BadZipFile, OSError) as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ExtractionError(f"failed to extract pypi archive: {e}") from e

    return ExtractedSource(root=_first_subdir_or(extract_dir), source=source, scheme="pypi", cleanup_dir=tmp)


# --- safe extraction helpers (CVE-2007-4559 / zip-slip defense) ---

def _safe_extract_tar(tf: tarfile.TarFile, dest: Path) -> None:
    """Extract a tarball, rejecting any member that would write outside dest."""
    dest_resolved = dest.resolve()
    for member in tf.getmembers():
        target = (dest / member.name).resolve()
        if not str(target).startswith(str(dest_resolved)):
            raise ExtractionError(f"tar member would escape destination: {member.name}")
    tf.extractall(dest)  # noqa: S202 — validated above


def _safe_extract_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    """Extract a zip, rejecting any member that would write outside dest."""
    dest_resolved = dest.resolve()
    for name in zf.namelist():
        target = (dest / name).resolve()
        if not str(target).startswith(str(dest_resolved)):
            raise ExtractionError(f"zip member would escape destination: {name}")
    zf.extractall(dest)
