import math
from collections import Counter
from typing import Union

def calculate_shannon_entropy(data: Union[bytes, str]) -> float:
    """
    Calculates the Shannon entropy of the given data.
    Returns a float between 0.0 (uniform) and 8.0 (maximum randomness).
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    if not data:
        return 0.0
    length = len(data)
    frequencies = Counter(data)
    entropy = 0.0
    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy

def is_highly_entropic(data: Union[bytes, str], threshold: float = 7.9) -> bool:
    return calculate_shannon_entropy(data) >= threshold

# ──────────────────────────────────────────────
# Expanded Magic Bytes registry
# ──────────────────────────────────────────────
MAGIC_BYTES = {
    b'%PDF-':               'PDF Document',
    b'PK\x03\x04':         'ZIP / DOCX / XLSX / PPTX Archive',
    b'\xff\xd8\xff':        'JPEG Image',
    b'\x89PNG\r\n\x1a\n':  'PNG Image',
    b'GIF87a':              'GIF Image',
    b'GIF89a':              'GIF Image',
    b'BM':                  'BMP Image',
    b'RIFF':                'WAV / AVI Media',
    b'\x00\x00\x00\x18ftyp': 'MP4 Video',
    b'\x00\x00\x00\x20ftyp': 'MP4 Video',
    b'ID3':                 'MP3 Audio',
    b'\xff\xfb':            'MP3 Audio',
    b'OggS':                'OGG Audio/Video',
    b'fLaC':                'FLAC Audio',
    b'Rar!\x1a\x07':        'RAR Archive',
    b'7z\xbc\xaf\x27\x1c': '7-Zip Archive',
    b'\x1f\x8b':            'GZIP Archive',
    b'BZh':                 'BZIP2 Archive',
    b'\xfd7zXZ\x00':        'XZ Archive',
    b'MZ':                  'Windows EXE / DLL',
    b'\x7fELF':             'Linux ELF Executable',
    b'\xca\xfe\xba\xbe':    'Java Class File / macOS Binary',
    b'\xce\xfa\xed\xfe':    'macOS Mach-O Binary',
    b'\xcf\xfa\xed\xfe':    'macOS Mach-O 64-bit Binary',
    b'<!DOCTYPE':           'HTML Document',
    b'<html':               'HTML Document',
    b'<?xml':               'XML Document',
    b'{\n':                 'JSON File',
    b'{\"':                 'JSON File',
    b'\xd0\xcf\x11\xe0':   'MS Office Legacy (DOC/XLS/PPT)',
    b'SQLite format 3':     'SQLite Database',
    b'\x53\x51\x4c\x69':   'SQLite Database',
    b'DICOM':               'DICOM Medical Image',
    b'II\x2a\x00':          'TIFF Image (Little Endian)',
    b'MM\x00\x2a':          'TIFF Image (Big Endian)',
    b'#!':                  'Shell Script',
    b'#!/':                 'Script File',
}

# ──────────────────────────────────────────────
# Risk-factor scoring engine
# ──────────────────────────────────────────────

def _score_entropy(entropy: float) -> tuple[float, str]:
    """Returns a (0-100) entropy risk score and a human reason string."""
    if entropy < 6.0:
        return 0.0, f"Entropy {entropy:.4f} is very low — natural language / plaintext data."
    elif entropy < 7.0:
        return 15.0, f"Entropy {entropy:.4f} is moderate — structured binary or mixed content."
    elif entropy < 7.5:
        return 35.0, f"Entropy {entropy:.4f} is high — likely compressed content."
    elif entropy < 7.9:
        return 60.0, f"Entropy {entropy:.4f} is very high — borderline compressed or encrypted."
    else:
        return 85.0, f"Entropy {entropy:.4f} is near-maximum (≥7.9) — strong encryption or compression signature."

def _score_magic_bytes(data: bytes) -> tuple[float, str, str]:
    """
    Returns (risk_modifier, file_type, reason).
    A valid magic header REDUCES risk. Missing magic bytes INCREASES risk.
    """
    for magic, ftype in MAGIC_BYTES.items():
        if data.startswith(magic):
            return -55.0, ftype, f"Valid magic bytes found: file is a '{ftype}'. Known compressed formats are expected to have high entropy."
    return +15.0, "Unknown", "No recognizable magic byte signature found at file start — encrypted files typically destroy their headers."

def _score_chunk_entropy(data: bytes, threshold: float) -> tuple[float, str]:
    """Analyse the first 256-byte header chunk entropy."""
    chunk = data[:256]
    if len(chunk) < 8:
        return 0.0, "File too small for chunk analysis."
    h = calculate_shannon_entropy(chunk)
    if h >= threshold - 0.2:
        return 20.0, f"Header chunk entropy {h:.4f} is very high — ransomware scrambles file headers, this is a strong encryption indicator."
    elif h >= threshold - 0.8:
        return 5.0, f"Header chunk entropy {h:.4f} is elevated but not conclusive."
    else:
        return -10.0, f"Header chunk entropy {h:.4f} is relatively low — suggests structured header, likely a benign compressed format."

def _score_byte_distribution(data: bytes) -> tuple[float, str]:
    """Check if all 256 byte values appear with near-equal frequency (uniform distribution = encryption)."""
    if len(data) < 512:
        return 0.0, "File too small for byte distribution analysis."
    frequencies = Counter(data)
    present = len(frequencies)
    if present == 256:
        counts = list(frequencies.values())
        mean = sum(counts) / len(counts)
        variance = sum((c - mean) ** 2 for c in counts) / len(counts)
        std_dev = math.sqrt(variance)
        cv = std_dev / mean  # Coefficient of variation
        if cv < 0.1:
            return 15.0, f"Byte distribution is near-perfectly uniform (CV={cv:.3f}) — a hallmark of AES encryption output."
        else:
            return 0.0, f"Byte distribution has some variance (CV={cv:.3f}) — not perfectly uniform."
    elif present < 100:
        return -20.0, f"Only {present}/256 byte values appear — highly structured, very likely plaintext or binary format."
    else:
        return 5.0, f"{present}/256 byte values present — wide distribution, consistent with compressed or encrypted data."

def analyze_file_structure(data: bytes, threshold: float = 7.9) -> dict:
    """
    Multi-factor risk engine returning a threat probability score (0-100),
    a verdict, a detailed reason list, and entropy.
    """
    if not data:
        return {
            "is_malicious": False, "status_text": "Empty File",
            "entropy": 0.0, "risk_percent": 0, "reasons": ["File is empty."], "file_type": "Empty"
        }

    overall_entropy = calculate_shannon_entropy(data)

    # ── Collect all factor scores ──
    reasons = []
    total_risk = 0.0

    # Factor 1: Overall entropy
    e_score, e_reason = _score_entropy(overall_entropy)
    total_risk += e_score
    reasons.append(f"📊 Overall Entropy: {e_reason}")

    # Factor 2: Magic bytes
    m_score, file_type, m_reason = _score_magic_bytes(data)
    total_risk += m_score
    reasons.append(f"🔎 Magic Bytes: {m_reason}")

    # Factor 3: Header chunk entropy
    c_score, c_reason = _score_chunk_entropy(data, threshold)
    total_risk += c_score
    reasons.append(f"📦 Header Chunk: {c_reason}")

    # Factor 4: Byte distribution uniformity
    d_score, d_reason = _score_byte_distribution(data)
    total_risk += d_score
    reasons.append(f"🎲 Byte Distribution: {d_reason}")

    # Clamp to 0–100
    risk_percent = max(0.0, min(100.0, total_risk))

    is_malicious = risk_percent >= 50.0

    if risk_percent < 20:
        status_text = f"BENIGN — {file_type} (Low Threat)"
    elif risk_percent < 50:
        status_text = f"SUSPICIOUS — {file_type} (Moderate Threat)"
    elif risk_percent < 75:
        status_text = f"LIKELY MALICIOUS — {file_type} (High Threat)"
    else:
        status_text = f"MALICIOUS — {file_type} (Critical Threat)"

    return {
        "is_malicious": is_malicious,
        "status_text": status_text,
        "entropy": overall_entropy,
        "risk_percent": round(risk_percent, 1),
        "reasons": reasons,
        "file_type": file_type
    }
