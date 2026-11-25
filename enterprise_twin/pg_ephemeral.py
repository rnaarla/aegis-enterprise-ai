"""Zero-port-conflict Unix-socket PostgreSQL 18 ephemeral cluster manager."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

DEFAULT_PG_BIN_DIR = Path("/opt/homebrew/opt/postgresql@18/bin")


def _resolve_pg_bin(binary_name: str) -> str:  # pragma: no cover
    candidate = DEFAULT_PG_BIN_DIR / binary_name
    if candidate.exists():
        return str(candidate)
    which_hit = shutil.which(binary_name)
    if which_hit:
        return which_hit
    # Debian/Ubuntu apt installs PostgreSQL server binaries under /usr/lib/postgresql/<ver>/bin
    debian_pg_root = Path("/usr/lib/postgresql")
    if debian_pg_root.exists():
        for bin_dir in sorted(debian_pg_root.glob("*/bin"), reverse=True):
            deb_candidate = bin_dir / binary_name
            if deb_candidate.exists():
                return str(deb_candidate)
    raise RuntimeError(f"PostgreSQL binary {binary_name!r} not found on system PATH")


@contextmanager
def ephemeral_postgres_cluster(db_name: str = "aegis_rls") -> Iterator[str]:
    """Boot a real, isolated PostgreSQL 18 server over a `/tmp` Unix domain socket.

    Yields a libpq connection DSN (`postgresql:///aegis_rls?host=/tmp/...`).
    """
    initdb_bin = _resolve_pg_bin("initdb")
    pg_ctl_bin = _resolve_pg_bin("pg_ctl")
    createdb_bin = _resolve_pg_bin("createdb")

    base_dir = Path(tempfile.mkdtemp(prefix="aegis_pg18_", dir="/tmp"))
    data_dir = base_dir / "data"
    sock_dir = base_dir / "sock"
    log_file = base_dir / "postgres.log"
    sock_dir.mkdir(parents=True, exist_ok=True)

    try:
        subprocess.run(
            [
                initdb_bin,
                "-D",
                str(data_dir),
                "-A",
                "trust",
                "--no-locale",
                "-E",
                "UTF8",
                "-c",
                "shared_memory_type=mmap",
                "-c",
                "dynamic_shared_memory_type=mmap",
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        pg_opts = f"-k {sock_dir} -h '' -F"
        subprocess.run(
            [
                pg_ctl_bin,
                "-D",
                str(data_dir),
                "-l",
                str(log_file),
                "-o",
                pg_opts,
                "-w",
                "start",
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        subprocess.run(
            [createdb_bin, "-h", str(sock_dir), db_name],
            check=True,
            capture_output=True,
            text=True,
        )

        yield f"postgresql:///{db_name}?host={sock_dir}"
    finally:
        if (data_dir / "postmaster.pid").exists():
            subprocess.run(
                [pg_ctl_bin, "-D", str(data_dir), "-m", "immediate", "stop"],
                check=False,
                capture_output=True,
                text=True,
            )
        shutil.rmtree(base_dir, ignore_errors=True)
