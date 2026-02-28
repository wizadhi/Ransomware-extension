import math
import os
import struct


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_pe_features(file_path: str) -> dict:
    """
    Extract PE header features that match the training dataset columns:
      Machine, DebugSize, DebugRVA, MajorImageVersion, MajorOSVersion,
      ExportRVA, ExportSize, IatVRA, MajorLinkerVersion, MinorLinkerVersion,
      NumberOfSections, SizeOfStackReserve, DllCharacteristics,
      ResourceSize, BitcoinAddresses
    Returns a dict with these keys. Falls back to 0 for unreadable fields.
    """
    features = {
        "Machine": 0,
        "DebugSize": 0,
        "DebugRVA": 0,
        "MajorImageVersion": 0,
        "MajorOSVersion": 0,
        "ExportRVA": 0,
        "ExportSize": 0,
        "IatVRA": 0,
        "MajorLinkerVersion": 0,
        "MinorLinkerVersion": 0,
        "NumberOfSections": 0,
        "SizeOfStackReserve": 0,
        "DllCharacteristics": 0,
        "ResourceSize": 0,
        "BitcoinAddresses": 0,
    }

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        if len(data) < 64 or data[:2] != b'MZ':
            return features  # Not a PE file — return zero features

        # PE header offset is at 0x3C
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 24 > len(data):
            return features
        if data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
            return features

        coff_offset = pe_offset + 4
        features["Machine"] = struct.unpack_from("<H", data, coff_offset)[0]
        features["NumberOfSections"] = struct.unpack_from("<H", data, coff_offset + 2)[0]

        opt_offset = coff_offset + 20
        if opt_offset + 2 > len(data):
            return features

        magic = struct.unpack_from("<H", data, opt_offset)[0]
        is_pe32_plus = (magic == 0x20B)

        features["MajorLinkerVersion"] = struct.unpack_from("<B", data, opt_offset + 2)[0]
        features["MinorLinkerVersion"] = struct.unpack_from("<B", data, opt_offset + 3)[0]
        features["MajorOSVersion"] = struct.unpack_from("<H", data, opt_offset + 40)[0]
        features["MajorImageVersion"] = struct.unpack_from("<H", data, opt_offset + 44)[0]
        features["DllCharacteristics"] = struct.unpack_from("<H", data, opt_offset + 70)[0]

        if is_pe32_plus:
            features["SizeOfStackReserve"] = struct.unpack_from("<Q", data, opt_offset + 72)[0]
        else:
            features["SizeOfStackReserve"] = struct.unpack_from("<I", data, opt_offset + 72)[0]

        # Data directories (each is RVA + Size, 8 bytes)
        dd_offset = opt_offset + (112 if is_pe32_plus else 96)
        if dd_offset + 16 * 8 <= len(data):
            features["ExportRVA"] = struct.unpack_from("<I", data, dd_offset)[0]
            features["ExportSize"] = struct.unpack_from("<I", data, dd_offset + 4)[0]
            # IAT is entry 12 (index 12)
            features["IatVRA"] = struct.unpack_from("<I", data, dd_offset + 12 * 8)[0]
            # Debug is entry 6
            features["DebugRVA"] = struct.unpack_from("<I", data, dd_offset + 6 * 8)[0]
            features["DebugSize"] = struct.unpack_from("<I", data, dd_offset + 6 * 8 + 4)[0]
            # Resource is entry 2
            features["ResourceSize"] = struct.unpack_from("<I", data, dd_offset + 2 * 8 + 4)[0]

    except Exception:
        pass  # Return whatever we parsed so far

    return features


# FIX: keep simple entropy-based extraction for non-PE files (JS, scripts, etc.)
def extract_simple_features(file_path: str) -> dict:
    """
    Fallback feature extraction for non-PE files.
    Returns a zeroed PE feature dict (file will be scored as benign by ML).
    Signature engine handles non-PE heuristics separately.
    """
    return {
        "Machine": 0, "DebugSize": 0, "DebugRVA": 0,
        "MajorImageVersion": 0, "MajorOSVersion": 0,
        "ExportRVA": 0, "ExportSize": 0, "IatVRA": 0,
        "MajorLinkerVersion": 0, "MinorLinkerVersion": 0,
        "NumberOfSections": 0, "SizeOfStackReserve": 0,
        "DllCharacteristics": 0, "ResourceSize": 0,
        "BitcoinAddresses": 0,
    }


def is_pe_file(file_path: str) -> bool:
    try:
        with open(file_path, "rb") as f:
            magic = f.read(2)
        return magic == b'MZ'
    except Exception:
        return False
