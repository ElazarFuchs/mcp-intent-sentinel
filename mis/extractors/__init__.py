"""Source extractors — turn a user-supplied source spec into a local directory.

Supported in v0.1:
- file://, /abs/path, ./rel/path — local directory (no extraction)
- file:///abs/path/to/archive.tar.gz, .tgz, .zip — extracted to tempdir
- github:owner/repo[#ref] — `git clone --depth 1` into tempdir
- npm:package[@version] — `npm pack` into tempdir then extract tarball
- pypi:package[==version] — `pip download --no-deps` then extract sdist

What is NOT supported in v0.1 — see LIMITATIONS.md L1:
- OCI / Docker images
- Smithery / private registries
- Authenticated git
- Signature verification (mcp-trust covers this; out of MIS scope)

All network-fetch extractors:
- Run in a tempdir that the caller is responsible for cleaning up
- Time out at 60 seconds
- Are explicitly opt-in (the user typed the source spec — no implicit fetch)
"""
from __future__ import annotations

from mis.extractors.base import ExtractedSource, ExtractionError, extract

__all__ = ["ExtractedSource", "ExtractionError", "extract"]
