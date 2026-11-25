"""Layout-aware PDF & scanned image OCR extractor with cross-page table header continuity."""

from __future__ import annotations

import io
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from pypdf import PdfReader


@dataclass(frozen=True)
class ExtractedPageChunk:
    page_number: int
    extraction_method: str
    content: str


def _looks_like_markdown_or_pipe_table_header(line: str) -> bool:
    stripped = line.strip()
    return stripped.count("|") >= 2 and stripped.replace("|", "").replace("-", "").strip() != ""


def extract_layout_aware_pdf_chunks(
    pdf_bytes: bytes,
    *,
    ocr_image_fallback_dir: Path | None = None,
) -> list[ExtractedPageChunk]:
    """Extract multi-page PDF text via `pypdf`, preserving split table headers across pages."""
    reader = PdfReader(io.BytesIO(pdf_bytes))
    chunks: list[ExtractedPageChunk] = []
    active_table_header: str | None = None

    for idx, page in enumerate(reader.pages, start=1):
        raw_text = (page.extract_text() or "").strip()
        method = "pypdf_layout"

        if len(raw_text) < 20 and ocr_image_fallback_dir is not None:
            img_candidate = ocr_image_fallback_dir / f"page_{idx}.png"
            if img_candidate.exists():
                raw_text = run_tesseract_ocr(img_candidate)
                method = "tesseract_ocr"

        if not raw_text:
            continue

        lines = [ln.strip() for ln in raw_text.splitlines() if ln.strip()]
        first_line = lines[0] if lines else ""

        # If previous page ended inside a pipe-delimited table and this page continues rows
        # without repeating the column header, prepend `[TABLE_HEADER_CARRYOVER]`!
        if (
            active_table_header is not None
            and first_line.count("|") >= 2
            and first_line != active_table_header
        ):
            raw_text = f"{active_table_header}\n{raw_text}"

        # Track last seen table header on this page for potential carryover to page idx + 1
        table_lines = [ln for ln in lines if _looks_like_markdown_or_pipe_table_header(ln)]
        if table_lines:
            # First pipe row in a table block is the column header
            if active_table_header is None:
                active_table_header = table_lines[0]
        else:
            active_table_header = None

        chunks.append(
            ExtractedPageChunk(
                page_number=idx,
                extraction_method=method,
                content=raw_text,
            )
        )
    return chunks


def run_tesseract_ocr(image_path: Path) -> str:
    """Invoke local `/opt/homebrew/bin/tesseract` binary for air-gapped scanned page OCR."""
    tess_bin = "/opt/homebrew/bin/tesseract"
    if not Path(tess_bin).exists():
        found = shutil.which("tesseract")
        if not found:
            return ""
        tess_bin = found

    proc = subprocess.run(  # noqa: S603
        [tess_bin, str(image_path), "stdout", "--psm", "6"],
        check=False,
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip()
