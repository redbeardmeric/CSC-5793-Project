"""
cve_cleaner.py
==============
Cleans NVD CVE CSV datasets from:


Handles the most common Kaggle NVD CSV column schemas:
  Schema A (common Kaggle export):
    Name, Status, Description, References, Phase, Votes, Comments
  Schema B (NVD enriched):
    CVE-ID, CVSS-V2, CVSS-V3, CVSS-V4, SEVERITY, DESCRIPTION, CWE-ID
  Schema C (NVD with dates):
    Name/CVE-ID, Description, Published Date, Last Modified Date,
    V2 Score/CVSS-V2, V3 Score/CVSS-V3, Severity, CWE

All schemas are auto-detected from headers.

Operations performed
--------------------
1.  Remove HTML/XML tags and entities from text fields
2.  Normalize Unicode / handle encoding issues (latin-1, cp1252, etc.)
3.  Filter RESERVED and REJECT CVEs (by description content or Status column)
4.  Validate required fields (CVE-ID, description)
5.  Standardize column names across schema variants
6.  Write cleaned output as CSV + optional report

Usage
-----
    python cve_cleaner.py --input "yourpathtocsvs" --output ./cleaned
    python cve_cleaner.py --input "yourpathtocsvs" --output ./cleaned --report --verbose
"""

from __future__ import annotations

import argparse
import csv
import html
import logging
import re
import sys
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger("cve_cleaner")

# Raise the CSV field size limit – the default 131072 bytes is too small for
# NVD rows with large `configurations` or `references` blobs.
csv.field_size_limit(min(sys.maxsize, 10 * 1024 * 1024))  # cap at 10 MB per field

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RESERVED_PHRASES = {
    "** reserved **",
    "** reserved",
    "reserved **",
    "this candidate has been reserved",
}

REJECT_PHRASES = {
    "** reject **",
    "** rejected **",
    "do not use this candidate",
    "this candidate was withdrawn",
}

# Only matches tags that start with a letter, /, or ! (proper HTML/XML tags)
# This avoids stripping version strings like <2.9.10> or comparison operators
_HTML_TAG_RE   = re.compile(r"<(?:[a-zA-Z/!][^>]*|!--.*?--)>", re.DOTALL)
_XML_PI_RE     = re.compile(r"<\?[^>]+\?>", re.DOTALL)
_MULTI_SPACE_RE = re.compile(r"[ \t]+")
_MULTI_NL_RE   = re.compile(r"\n{3,}")
_CVE_ID_RE     = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Column name aliases  →  canonical names
# ---------------------------------------------------------------------------

COL_MAP: dict[str, str] = {
    # CVE ID
    "name":               "cve_id",
    "cve-id":             "cve_id",
    "cve_id":             "cve_id",
    "cveid":              "cve_id",
    "id":                 "cve_id",

    # Description
    "description":        "description",
    "desc":               "description",
    "summary":            "description",

    # Status / State
    "status":             "status",
    "state":              "status",

    # Dates
    "published date":     "published_date",
    "published":          "published_date",
    "publisheddate":      "published_date",
    "published_date":     "published_date",
    "last modified date": "last_modified_date",
    "lastmodifieddate":   "last_modified_date",
    "last modified":      "last_modified_date",
    "last_modified_date": "last_modified_date",
    "modified":           "last_modified_date",

    # CVSS scores
    "v2 score":           "cvss_v2",
    "cvss-v2":            "cvss_v2",
    "cvss_v2":            "cvss_v2",
    "cvssv2":             "cvss_v2",
    "cvss v2":            "cvss_v2",
    "v3 score":           "cvss_v3",
    "cvss-v3":            "cvss_v3",
    "cvss_v3":            "cvss_v3",
    "cvssv3":             "cvss_v3",
    "cvss v3":            "cvss_v3",
    "v4 score":           "cvss_v4",
    "cvss-v4":            "cvss_v4",
    "cvss_v4":            "cvss_v4",
    "cvssv4":             "cvss_v4",

    # Severity
    "severity":           "severity",
    "v3 severity":        "severity",
    "v2 severity":        "severity",

    # CWE
    "cwe":                "cwe_id",
    "cwe-id":             "cwe_id",
    "cwe_id":             "cwe_id",
    "cweid":              "cwe_id",
    "cwe id":             "cwe_id",

    # References (keep raw, not critical)
    "references":         "references",

    # Configurations / CPE data (large blob — kept as-is, not in output)
    "configurations":     "configurations",

    # NVD API v2 style column names
    "cveid":              "cve_id",
    "cve id":             "cve_id",
    "vuln_id":            "cve_id",
    "vulnerabilityname":  "cve_id",
    "publisheddate":      "published_date",
    "lastmodifieddate":   "last_modified_date",
    "basescorev2":        "cvss_v2",
    "basescorev3":        "cvss_v3",
    "baseseverityv3":     "severity",
    "impactscore":        "cvss_v3",
    "exploitabilityscore":"cvss_v2",
}


def normalize_header(raw: str) -> str:
    """Lower-case, strip, collapse spaces for header matching."""
    return raw.strip().lower()


def map_headers(raw_headers: list[str]) -> dict[str, str]:
    """
    Return a mapping of raw_header → canonical_name for recognised columns.
    Unrecognised columns are included as-is (lower-cased).
    """
    mapping: dict[str, str] = {}
    for h in raw_headers:
        key = normalize_header(h)
        mapping[h] = COL_MAP.get(key, key.replace(" ", "_"))
    return mapping


# ---------------------------------------------------------------------------
# Text cleaning helpers
# ---------------------------------------------------------------------------

def remove_html_xml(text: str) -> str:
    text = _XML_PI_RE.sub("", text)
    text = _HTML_TAG_RE.sub(" ", text)
    text = html.unescape(text)
    return text


def fix_encoding(text: str) -> str:
    if not text:
        return text
    try:
        if "\ufffd" in text:
            encoded = text.encode("latin-1", errors="replace")
            text = encoded.decode("utf-8", errors="replace")
    except (UnicodeEncodeError, UnicodeDecodeError):
        pass
    return unicodedata.normalize("NFC", text)


def normalize_whitespace(text: str) -> str:
    text = _MULTI_SPACE_RE.sub(" ", text)
    text = _MULTI_NL_RE.sub("\n\n", text)
    return text.strip()


def clean_text(text: str) -> str:
    """Full text pipeline: encoding → HTML → whitespace."""
    if not text:
        return ""
    text = fix_encoding(text)
    text = remove_html_xml(text)
    text = normalize_whitespace(text)
    return text


def clean_score(value: str) -> str:
    """Normalize a CVSS score field; return '' for nulls/None strings."""
    v = value.strip()
    if v.lower() in ("none", "null", "n/a", "-", ""):
        return ""
    try:
        f = float(v)
        return str(round(f, 1))
    except ValueError:
        return v


def clean_severity(value: str) -> str:
    v = value.strip().upper()
    valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    return v if v in valid else ""


# ---------------------------------------------------------------------------
# Filter logic
# ---------------------------------------------------------------------------

def is_reserved(description: str) -> bool:
    lower = description.lower()
    return any(phrase in lower for phrase in RESERVED_PHRASES)


def is_rejected(description: str, status: str = "") -> bool:
    lower = description.lower()
    status_lower = status.lower()
    return (
        any(phrase in lower for phrase in REJECT_PHRASES)
        or "reject" in status_lower
    )


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@dataclass
class CleaningStats:
    total_input: int = 0
    reserved_filtered: int = 0
    rejected_filtered: int = 0
    validation_failed: int = 0
    cleaned_output: int = 0
    files_processed: int = 0
    files_failed: int = 0

    def summary(self) -> str:
        lines = [
            "=" * 60,
            "  CVE CLEANING RUN SUMMARY",
            "=" * 60,
            f"  Files processed   : {self.files_processed}",
            f"  Files with errors : {self.files_failed}",
            f"  Total CVEs read   : {self.total_input:,}",
            f"  RESERVED filtered : {self.reserved_filtered:,}",
            f"  REJECTED filtered : {self.rejected_filtered:,}",
            f"  Validation failed : {self.validation_failed:,}",
            f"  Clean CVEs output : {self.cleaned_output:,}",
            "=" * 60,
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Row-level cleaning
# ---------------------------------------------------------------------------

# Output columns — always emitted in this order
OUTPUT_COLS = [
    "cve_id",
    "description",
    "status",
    "published_date",
    "last_modified_date",
    "cvss_v2",
    "cvss_v3",
    "cvss_v4",
    "severity",
    "cwe_id",
    "references",
]


def clean_row(
    row: dict[str, str],
    col_mapping: dict[str, str],
    stats: CleaningStats,
) -> dict[str, str] | None:
    """
    Map raw columns → canonical names, clean each field, apply filters.
    Returns None if the row should be dropped.
    """
    stats.total_input += 1

    # Build canonical dict
    canonical: dict[str, str] = {}
    for raw_col, value in row.items():
        canon = col_mapping.get(raw_col, normalize_header(raw_col).replace(" ", "_"))
        # For duplicate canonical keys keep the first non-empty value
        if canon not in canonical or not canonical[canon]:
            canonical[canon] = value or ""

    description = clean_text(canonical.get("description", ""))
    status      = canonical.get("status", "").strip()
    cve_id      = canonical.get("cve_id", "").strip()

    # --- Filters ---
    if is_reserved(description):
        stats.reserved_filtered += 1
        return None
    if is_rejected(description, status):
        stats.rejected_filtered += 1
        return None

    # --- Validation ---
    errors: list[str] = []
    if not cve_id or not _CVE_ID_RE.match(cve_id):
        errors.append(f"Invalid/missing CVE-ID: '{cve_id}'")
    if not description or len(description) < 10:
        errors.append(f"{cve_id}: Description too short or missing")
    if errors:
        for e in errors:
            log.debug("Validation: %s", e)
        stats.validation_failed += 1
        return None

    # --- Build clean output row ---
    clean: dict[str, str] = {col: "" for col in OUTPUT_COLS}
    clean["cve_id"]             = cve_id.upper()
    clean["description"]        = description
    clean["status"]             = status.upper()
    clean["published_date"]     = canonical.get("published_date", "").strip()
    clean["last_modified_date"] = canonical.get("last_modified_date", "").strip()
    clean["cvss_v2"]            = clean_score(canonical.get("cvss_v2", ""))
    clean["cvss_v3"]            = clean_score(canonical.get("cvss_v3", ""))
    clean["cvss_v4"]            = clean_score(canonical.get("cvss_v4", ""))
    clean["severity"]           = clean_severity(canonical.get("severity", ""))
    clean["cwe_id"]             = canonical.get("cwe_id", "").strip()
    clean["references"]         = clean_text(canonical.get("references", ""))

    stats.cleaned_output += 1
    return clean


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

ENCODINGS_TO_TRY = ["utf-8", "utf-8-sig", "latin-1", "cp1252"]


def open_csv(filepath: Path):
    """
    Open a CSV file trying multiple encodings.
    Returns (file_handle, encoding_used) or raises on failure.
    """
    for enc in ENCODINGS_TO_TRY:
        try:
            fh = filepath.open("r", encoding=enc, newline="")
            # Probe the first line to catch silent mis-decodes
            fh.readline()
            fh.seek(0)
            return fh, enc
        except (UnicodeDecodeError, UnicodeError):
            continue
    raise ValueError(f"Could not decode {filepath.name} with any of {ENCODINGS_TO_TRY}")


def detect_delimiter(sample: str) -> str:
    """Sniff CSV delimiter from a sample string."""
    sniffer = csv.Sniffer()
    try:
        dialect = sniffer.sniff(sample, delimiters=",\t|;")
        return dialect.delimiter
    except csv.Error:
        return ","   # fallback


def clean_file(
    filepath: Path,
    output_dir: Path,
    stats: CleaningStats,
    verbose: bool = False,
) -> None:
    log.info("Processing: %s", filepath.name)
    stem     = filepath.stem
    out_path = output_dir / f"cleaned_{stem}.csv"

    try:
        fh, encoding = open_csv(filepath)
    except ValueError as exc:
        log.error("  %s", exc)
        stats.files_failed += 1
        return

    file_input  = 0
    file_output = 0

    with fh, out_path.open("w", newline="", encoding="utf-8") as out_fh:
        sample = fh.read(4096)
        fh.seek(0)
        delimiter = detect_delimiter(sample)
        reader = csv.DictReader(fh, delimiter=delimiter)

        if reader.fieldnames is None:
            log.error("  %s: No headers found, skipping.", filepath.name)
            stats.files_failed += 1
            return

        col_mapping = map_headers(list(reader.fieldnames))
        if verbose:
            log.info(
                "  Columns detected: %s",
                ", ".join(f"{k}→{v}" for k, v in col_mapping.items()),
            )

        writer = csv.DictWriter(out_fh, fieldnames=OUTPUT_COLS)
        writer.writeheader()

        for row in reader:
            file_input += 1
            result = clean_row(row, col_mapping, stats)
            if result is not None:
                writer.writerow(result)
                file_output += 1

            # Progress heartbeat every 50k rows for large files
            if file_input % 50_000 == 0:
                log.info("  ... %s rows read, %s written so far", f"{file_input:,}", f"{file_output:,}")

    log.info(
        "  %s (enc=%s) → input=%d  output=%d  filtered=%d  → %s",
        filepath.name, encoding,
        file_input, file_output, file_input - file_output,
        out_path.name,
    )
    stats.files_processed += 1


def find_csv_files(input_dir: Path) -> list[Path]:
    return sorted(input_dir.rglob("*.csv"))


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def write_report(output_dir: Path, stats: CleaningStats) -> None:
    report_path = output_dir / "cleaning_report.txt"
    lines = [
        stats.summary(),
        "",
        f"Report generated : {datetime.utcnow().isoformat()}Z",
        f"Output directory : {output_dir}",
    ]
    report_path.write_text("\n".join(lines), encoding="utf-8")
    log.info("Report written → %s", report_path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Clean NVD CVE CSV datasets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--input", "-i",
        default=r"C:\Users\Cmull\Downloads\archive (1)",
        help="Directory containing CVE CSV files (default: %(default)s)",
    )
    parser.add_argument(
        "--output", "-o",
        default="./cleaned",
        help="Output directory for cleaned CSV files (default: %(default)s)",
    )
    parser.add_argument(
        "--report", "-r",
        action="store_true",
        help="Write a cleaning_report.txt summary",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print per-file column mapping and stats",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.getLogger().setLevel(args.log_level)

    input_dir  = Path(args.input)
    output_dir = Path(args.output)

    if not input_dir.exists() or not input_dir.is_dir():
        log.error("Input directory not found: %s", input_dir)
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)

    csv_files = find_csv_files(input_dir)
    if not csv_files:
        log.warning("No .csv files found in %s", input_dir)
        return 0

    log.info("Found %d CSV file(s) in %s", len(csv_files), input_dir)

    stats = CleaningStats()

    for filepath in csv_files:
        try:
            clean_file(filepath, output_dir, stats, verbose=args.verbose)
        except Exception as exc:
            log.error("Failed to process %s: %s", filepath.name, exc)
            stats.files_failed += 1

    print()
    print(stats.summary())

    if args.report:
        write_report(output_dir, stats)

    return 0 if stats.files_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())