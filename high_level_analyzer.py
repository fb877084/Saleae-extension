from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List, Tuple

try:
    from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, ChoicesSetting, NumberSetting
except Exception:  # pragma: no cover
    # Allows running unit tests without Saleae's runtime.
    HighLevelAnalyzer = object  # type: ignore

    class AnalyzerFrame:  # type: ignore
        def __init__(self, type, start_time, end_time, data):
            self.type = type
            self.start_time = start_time
            self.end_time = end_time
            self.data = data

    class ChoicesSetting:  # type: ignore
        def __init__(self, choices=()):
            self.choices = choices

    class NumberSetting:  # type: ignore
        def __init__(self, min_value=0, max_value=0):
            self.min_value = min_value
            self.max_value = max_value


def _hex(bs: bytes) -> str:
    return " ".join(f"{b:02X}" for b in bs)


def _as_u8(x) -> Optional[int]:
    """Best-effort conversion of Saleae SPI analyzer mosi/miso fields to a single byte."""
    if x is None:
        return None
    if isinstance(x, int):
        return x & 0xFF
    if isinstance(x, (bytes, bytearray)):
        if len(x) == 0:
            return None
        if len(x) == 1:
            return x[0]
        # Some SPI analyzer configs can emit multiple bytes; callers should iterate.
        return None
    # Sometimes Saleae uses a string like '0xAB'
    if isinstance(x, str):
        s = x.strip()
        try:
            if s.lower().startswith("0x"):
                return int(s, 16) & 0xFF
            return int(s) & 0xFF
        except Exception:
            return None
    return None


# eSPI response codes (Table 3)
RSP_ACCEPT_MASK = 0x0F
RSP_ACCEPT = 0x08
RSP_DEFER = 0x01
RSP_NON_FATAL = 0x02
RSP_FATAL = 0x03
RSP_WAIT_STATE = 0x0F
RSP_NO_RESPONSE = 0xFF


CMD_NAMES = {
    0x00: "PUT_PC",
    0x02: "PUT_NP",
    0x01: "GET_PC",
    0x03: "GET_NP",
    0x04: "PUT_VWIRE",
    0x05: "GET_VWIRE",
    0x06: "PUT_OOB",
    0x07: "GET_OOB",
    0x08: "PUT_FLASH_C",
    0x09: "GET_FLASH_NP",
    0x0A: "PUT_FLASH_NP",
    0x0B: "GET_FLASH_C",
    0x25: "GET_STATUS",
    0x22: "SET_CONFIGURATION",
    0x21: "GET_CONFIGURATION",
    0xFF: "RESET",
}


def _cmd_name(cmd: int) -> str:
    # Short opcodes encode length in bits; keep a hint.
    if (cmd & 0b11111011) == 0b01000001:  # 01000C1C01 (PUT_IORD_SHORT)
        return f"PUT_IORD_SHORT(len={_short_len(cmd)})"
    if (cmd & 0b11111011) == 0b01000101:  # PUT_IOWR_SHORT
        return f"PUT_IOWR_SHORT(len={_short_len(cmd)})"
    if (cmd & 0b11111011) == 0b01001001:  # PUT_MEMRD32_SHORT
        return f"PUT_MEMRD32_SHORT(len={_short_len(cmd)})"
    if (cmd & 0b11111011) == 0b01001101:  # PUT_MEMWR32_SHORT
        return f"PUT_MEMWR32_SHORT(len={_short_len(cmd)})"
    return CMD_NAMES.get(cmd, f"CMD_0x{cmd:02X}")


def _short_len(cmd: int) -> str:
    c1c0 = (cmd >> 2) & 0b11
    return {0: "1B", 1: "2B", 3: "4B"}.get(c1c0, "?")


def crc8_espi(data: bytes, poly: int = 0x07, init: int = 0x00) -> int:
    """CRC-8 (poly x^8 + x^2 + x + 1 == 0x07), MSB-first."""
    crc = init & 0xFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ poly) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc


@dataclass
class EspiDecoded:
    cmd: Optional[int]
    cmd_name: str
    cmd_crc_rx: Optional[int]
    cmd_crc_calc: Optional[int]
    cmd_detail: List[str]

    rsp: Optional[int]
    rsp_name: str
    wait_states: int
    rsp_detail: List[str]

    status_raw: Optional[Tuple[int, int]]
    status_u16: Optional[int]
    status_fields: List[str]

    rsp_crc_rx: Optional[int]
    rsp_crc_calc: Optional[int]

    mosi: bytes
    miso: bytes


def _decode_status_fields(sts: int) -> List[str]:
    # Table 4 bit names (bits not supported are ignored by controller)
    names = [
        (0, "PC_FREE"),
        (1, "NP_FREE"),
        (2, "VWIRE_FREE"),
        (3, "OOB_FREE"),
        (4, "PC_AVAIL"),
        (5, "NP_AVAIL"),
        (6, "VWIRE_AVAIL"),
        (7, "OOB_AVAIL"),
        (8, "FLASH_C_FREE"),
        (9, "FLASH_NP_FREE"),
        (12, "FLASH_C_AVAIL"),
        (13, "FLASH_NP_AVAIL"),
    ]
    out = []
    for bit, nm in names:
        if (sts >> bit) & 1:
            out.append(nm)
    return out


def _pick_status_endianness(b0: int, b1: int) -> Tuple[int, bool]:
    """Return (sts_u16, little_endian) choosing the interpretation where VWIRE_FREE (bit2) is set."""
    le = b0 | (b1 << 8)
    be = (b0 << 8) | b1
    # VWIRE_FREE must be always 1; prefer the one that matches.
    le_ok = (le >> 2) & 1
    be_ok = (be >> 2) & 1
    if le_ok and not be_ok:
        return le, True
    if be_ok and not le_ok:
        return be, False
    # Otherwise fall back to little-endian.
    return le, True


def _pick_addr_endianness(b0: int, b1: int) -> Tuple[int, bool]:
    """Return (addr_u16, little_endian) using plausibility checks.

    For config accesses:
      - only lower 12 bits used (addr[15:12]==0)
      - dword aligned (addr[1:0]==0)

    Spec defines byte order in another section; use these checks to decide.
    """
    le = b0 | (b1 << 8)
    be = (b0 << 8) | b1

    def ok(a: int) -> bool:
        return (a & 0xF000) == 0 and (a & 0x0003) == 0

    le_ok = ok(le)
    be_ok = ok(be)
    if le_ok and not be_ok:
        return le, True
    if be_ok and not le_ok:
        return be, False
    return le, True


def _is_valid_rsp_byte(b: int) -> bool:
    if b == RSP_NO_RESPONSE:
        return True
    nib = b & 0x0F
    return nib in (RSP_ACCEPT, RSP_DEFER, RSP_NON_FATAL, RSP_FATAL, RSP_WAIT_STATE)


def _guess_req_len(mosi: bytes) -> Optional[int]:
    """Return expected command-phase byte length (including CMD+CRC) when fixed/derivable."""
    if not mosi:
        return None
    cmd = mosi[0]
    if cmd in (0x25, 0x01, 0x03, 0x05):  # GET_STATUS, GET_PC, GET_NP, GET_VWIRE
        return 2
    if cmd == 0x21:  # GET_CONFIGURATION: CMD + ADDR(2) + CRC
        return 4
    if cmd == 0x22:  # SET_CONFIGURATION: CMD + ADDR(2) + DATA(4) + CRC
        return 8
    return None


def _find_rsp_start(mosi: bytes, miso: bytes) -> Optional[int]:
    """Best-effort response alignment.

    Prefer fixed request length (where known). Otherwise, search for a plausible
    response opcode in the later part of the transfer.
    """
    if not miso or not mosi:
        return None

    # If the whole MISO stream is pulled-up, treat as NO_RESPONSE.
    if all(b == 0xFF for b in miso[1:]):
        return None

    req_len = _guess_req_len(mosi)
    start_i = 1
    if req_len is not None and req_len < len(miso):
        start_i = req_len

    # Search for WAIT_STATE(s) followed by a valid response opcode.
    # Require space for trailing STS(2)+CRC(1) to reduce false positives.
    for i in range(start_i, min(len(miso), len(mosi))):
        if len(miso) - i < 4:
            break
        j = i
        while j < len(miso) and miso[j] == RSP_WAIT_STATE:
            j += 1
        if j >= len(miso):
            break
        if _is_valid_rsp_byte(miso[j]):
            return i

    # Fallback: first non-0xFF byte.
    for i in range(1, min(len(miso), len(mosi))):
        if miso[i] != 0xFF:
            return i
    return None


def _decode_periph_hdr(hdr: bytes) -> List[str]:
    """Decode the common peripheral channel header fields (Table 5 packet header)."""
    if len(hdr) < 4:
        return []
    cycle = hdr[0]
    tag = hdr[1]
    length = ((hdr[2] & 0x0F) << 8) | hdr[3]
    parts = [f"CT=0x{cycle:02X}", f"TAG=0x{tag:02X}", f"LEN={length}"]

    # Some common cycle types include addresses; decode a few well-known ones.
    if cycle in (0x00, 0x01) and len(hdr) >= 8:
        addr = (hdr[4] << 24) | (hdr[5] << 16) | (hdr[6] << 8) | hdr[7]
        parts.append(f"A32=0x{addr:08X}")
    elif cycle in (0x02, 0x03) and len(hdr) >= 12:
        addr64 = 0
        for b in hdr[4:12]:
            addr64 = (addr64 << 8) | b
        parts.append(f"A64=0x{addr64:016X}")

    return parts


def _decode_vwire_group(idx: int, data: int) -> str:
    """Best-effort decode for a single Virtual Wire group (Index, Data).

    Spec: Transaction Layer 4.2.2.1 (Table 8). Only a small subset is
    implemented here; unknown indices are shown as raw.
    """
    # Index 0/1: Interrupt event.
    if idx in (0x00, 0x01):
        level = (data >> 7) & 0x1
        line = data & 0x7F
        base = 0 if idx == 0 else 128
        return f"VW_IRQ lvl={level} irq={base + line} (idx=0x{idx:02X} data=0x{data:02X})"

    return f"VW idx=0x{idx:02X} data=0x{data:02X}"


def _decode_vwire_packet(pkt: bytes) -> List[str]:
    """Decode Virtual Wire packet (count + N*(idx,data)).

    pkt must start at Virtual Wire Count byte.
    Count is 0-based (0 => 1 group).
    """
    if not pkt:
        return []

    count = pkt[0] & 0x3F
    n = count + 1
    needed = 1 + 2 * n
    if len(pkt) < needed:
        # Partial / truncated.
        return [f"VW cnt={count} (trunc: need {needed}B have {len(pkt)}B)"]

    out = [f"VW cnt={count} (n={n})"]
    off = 1
    for gi in range(n):
        idx = pkt[off]
        data = pkt[off + 1]
        out.append(f"[{gi}] {_decode_vwire_group(idx, data)}")
        off += 2

    return out


def decode_espi_best_effort(mosi: bytes, miso: bytes) -> EspiDecoded:
    cmd = mosi[0] if len(mosi) > 0 else None
    cmd_name = _cmd_name(cmd) if cmd is not None else "<no-cmd>"

    cmd_detail: List[str] = []
    rsp_detail: List[str] = []

    # Command-specific decode (best-effort, independent of response alignment).
    if cmd == 0x21 and len(mosi) >= 3:  # GET_CONFIGURATION
        a0, a1 = mosi[1], mosi[2]
        addr, _ = _pick_addr_endianness(a0, a1)
        cmd_detail.append(f"ADDR=0x{addr:04X}")
    elif cmd == 0x22 and len(mosi) >= 7:  # SET_CONFIGURATION
        a0, a1 = mosi[1], mosi[2]
        addr, _ = _pick_addr_endianness(a0, a1)
        cmd_detail.append(f"ADDR=0x{addr:04X}")
        if len(mosi) >= 7:
            data_le = int.from_bytes(mosi[3:7], byteorder="little", signed=False)
            cmd_detail.append(f"DATA_LE=0x{data_le:08X}")
    elif cmd in (0x00, 0x02) and len(mosi) >= 5:  # PUT_PC / PUT_NP
        cmd_detail.extend(_decode_periph_hdr(mosi[1:1 + min(12, len(mosi) - 1)]))
    elif cmd == 0x04 and len(mosi) >= 3:  # PUT_VWIRE
        # Command phase: CMD + VW packet + CRC
        # Best-effort: assume last byte is CRC when present.
        pkt = mosi[1:-1] if len(mosi) >= 2 else b""
        cmd_detail.extend(_decode_vwire_packet(pkt))

    # Find response start.
    rsp_start = _find_rsp_start(mosi, miso)

    # If we couldn't find it, it might be NO_RESPONSE (all 0xFF). Assume no response.
    rsp = None
    rsp_name = "NO_RESPONSE"
    wait_states = 0

    cmd_crc_rx = None
    cmd_crc_calc = None

    status_raw = None
    status_u16 = None
    status_fields: List[str] = []

    rsp_crc_rx = None
    rsp_crc_calc = None

    if rsp_start is not None:
        # Command CRC is typically the last byte before TAR/response.
        if rsp_start >= 2:
            cmd_crc_rx = mosi[rsp_start - 1]
            cmd_crc_calc = crc8_espi(mosi[: rsp_start - 1])

        # Parse response including possible WAIT_STATE bytes.
        j = rsp_start
        rsp0 = miso[j]
        # Count WAIT_STATE(s) (0x0F) at start of response phase.
        while j < len(miso) and miso[j] == RSP_WAIT_STATE:
            wait_states += 1
            j += 1
        if j < len(miso):
            rsp = miso[j]
            rsp0 = rsp
            j += 1
        else:
            rsp = None

        if rsp is None:
            rsp_name = "<no-rsp>"
        elif rsp == RSP_NO_RESPONSE:
            rsp_name = "NO_RESPONSE"
        elif (rsp & 0x0F) == RSP_ACCEPT:
            mod = (rsp >> 6) & 0b11
            mod_name = {0: "", 1: "+PC", 2: "+VWIRE", 3: "+FLASH"}.get(mod, "")
            rsp_name = f"ACCEPT{mod_name}"
        elif (rsp & 0x0F) == RSP_DEFER:
            rsp_name = "DEFER"
        elif (rsp & 0x0F) == RSP_NON_FATAL:
            rsp_name = "NON_FATAL_ERROR"
        elif (rsp & 0x0F) == RSP_FATAL:
            rsp_name = "FATAL_ERROR"
        elif (rsp & 0x0F) == RSP_WAIT_STATE:
            rsp_name = "WAIT_STATE"  # should have been counted earlier
        else:
            rsp_name = f"RSP_0x{rsp:02X}"

        # Response payload decoding.
        if cmd in (0x01, 0x03) and rsp is not None and (rsp & 0x0F) == RSP_ACCEPT:
            # GET_PC / GET_NP: response phase carries HDR+DATA then trailing STS+CRC.
            payload = miso[j:-3] if len(miso) >= 3 and j <= len(miso) - 3 else miso[j:]
            rsp_detail.extend(_decode_periph_hdr(payload[: min(12, len(payload))]))

        if cmd == 0x05 and rsp is not None and (rsp & 0x0F) == RSP_ACCEPT:
            # GET_VWIRE: response phase carries VW packet then trailing STS+CRC.
            payload = miso[j:-3] if len(miso) >= 3 and j <= len(miso) - 3 else miso[j:]
            rsp_detail.extend(_decode_vwire_packet(payload))

        # Status + CRC are at the end of response: ... STS(2) CRC(1)
        if len(miso) >= 3 and j <= len(miso) - 3:
            b0, b1, bcrc = miso[-3], miso[-2], miso[-1]
            status_raw = (b0, b1)
            status_u16, _ = _pick_status_endianness(b0, b1)
            status_fields = _decode_status_fields(status_u16)
            rsp_crc_rx = bcrc

            # Compute response CRC over (rsp + payload + status), excluding WAIT_STATE(s) and excluding CRC itself.
            # Best-effort: take from first non-wait response byte through status bytes.
            rsp_region = bytes([rsp0]) + miso[j: -3] + bytes([b0, b1])
            rsp_crc_calc = crc8_espi(rsp_region)

    return EspiDecoded(
        cmd=cmd,
        cmd_name=cmd_name,
        cmd_crc_rx=cmd_crc_rx,
        cmd_crc_calc=cmd_crc_calc,
        cmd_detail=cmd_detail,
        rsp=rsp,
        rsp_name=rsp_name,
        wait_states=wait_states,
        rsp_detail=rsp_detail,
        status_raw=status_raw,
        status_u16=status_u16,
        status_fields=status_fields,
        rsp_crc_rx=rsp_crc_rx,
        rsp_crc_calc=rsp_crc_calc,
        mosi=mosi,
        miso=miso,
    )


class Hla(HighLevelAnalyzer):
    """eSPI High Level Analyzer (Milestone 1)

    Input: Saleae built-in SPI analyzer.

    Logic2 SPI analyzer typically produces:
      - frame.type == 'enable' / 'disable' (CS asserted/deasserted)
      - frame.type == 'result' per byte with data {'mosi': int/bytes, 'miso': int/bytes}

    This HLA aggregates bytes between enable->disable and decodes a best-effort
    eSPI transaction: CMD, (TAR heuristic), RSP (+WAIT_STATE count), STATUS, CRC.
    """

    decode_direction = ChoicesSetting(choices=("mosi", "miso", "both"))
    show_raw = ChoicesSetting(choices=("no", "yes"))
    split_on_idle_us = NumberSetting(min_value=1, max_value=5000)

    def __init__(self):
        self._reset()

    def _reset(self):
        self._buf_mosi = bytearray()
        self._buf_miso = bytearray()
        self._t_start = None
        self._t_last = None
        self._in_xfer = False

    def _flush(self, end_time):
        if self._t_start is None:
            self._reset()
            return None

        mosi = bytes(self._buf_mosi)
        miso = bytes(self._buf_miso)
        t0 = self._t_start

        self._reset()

        if len(mosi) == 0 and len(miso) == 0:
            return None

        dec = decode_espi_best_effort(mosi, miso)

        parts = []
        if dec.cmd is not None:
            parts.append(f"{dec.cmd_name} (0x{dec.cmd:02X})")
        else:
            parts.append("<no-cmd>")

        if dec.cmd_detail:
            parts.append(" ".join(dec.cmd_detail))

        if dec.cmd_crc_rx is not None and dec.cmd_crc_calc is not None:
            ok = "OK" if dec.cmd_crc_rx == dec.cmd_crc_calc else "BAD"
            parts.append(f"CMD_CRC {dec.cmd_crc_rx:02X}({ok})")

        if dec.wait_states:
            parts.append(f"WAITx{dec.wait_states}")

        if dec.rsp is not None:
            parts.append(f"{dec.rsp_name} (0x{dec.rsp:02X})")
        else:
            parts.append(dec.rsp_name)

        if dec.rsp_detail:
            parts.append(" ".join(dec.rsp_detail))

        if dec.status_u16 is not None:
            sts_bits = ",".join(dec.status_fields) if dec.status_fields else "-"
            b0, b1 = dec.status_raw
            parts.append(f"STS {b0:02X} {b1:02X} (0x{dec.status_u16:04X}: {sts_bits})")

        if dec.rsp_crc_rx is not None and dec.rsp_crc_calc is not None:
            ok = "OK" if dec.rsp_crc_rx == dec.rsp_crc_calc else "BAD"
            parts.append(f"RSP_CRC {dec.rsp_crc_rx:02X}({ok})")

        if self.show_raw == "yes":
            raw_parts = []
            if self.decode_direction in ("mosi", "both"):
                raw_parts.append(f"MOSI[{len(mosi)}]: {_hex(mosi)}")
            if self.decode_direction in ("miso", "both"):
                raw_parts.append(f"MISO[{len(miso)}]: {_hex(miso)}")
            if raw_parts:
                parts.append(" | ".join(raw_parts))

        return AnalyzerFrame(
            "espi",
            t0,
            end_time,
            {
                "text": " | ".join(parts),
                "cmd": dec.cmd_name,
                "rsp": dec.rsp_name,
                "wait_states": dec.wait_states,
                "status": f"0x{dec.status_u16:04X}" if dec.status_u16 is not None else "",
            },
        )

    def decode(self, frame: AnalyzerFrame):
        # Some SPI analyzer configs emit explicit enable/disable frames.
        if frame.type == "enable":
            self._reset()
            self._in_xfer = True
            self._t_start = frame.start_time
            self._t_last = frame.end_time
            return None

        if frame.type == "disable":
            # End of CS asserted window.
            if self._in_xfer:
                self._in_xfer = False
                return self._flush(frame.end_time)
            return None

        # Idle-gap split heuristic (for SPI analyzers that don't emit enable/disable).
        if self._t_last is not None and frame.start_time is not None:
            dt_s = float(frame.start_time - self._t_last)
            if dt_s * 1e6 > float(self.split_on_idle_us):
                out = self._flush(self._t_last)
                # Start a new accumulation with this frame.
                self._t_start = frame.start_time
                self._t_last = frame.end_time
                if out is not None:
                    # We still need to process current frame after flushing; fall through.
                    pass

        data = frame.data if isinstance(frame.data, dict) else {}

        mosi = data.get("mosi", None)
        miso = data.get("miso", None)

        # Start time comes from first observed byte.
        if self._t_start is None:
            self._t_start = frame.start_time

        # Append bytes.
        if isinstance(mosi, (bytes, bytearray)) and len(mosi) > 1:
            self._buf_mosi.extend(mosi)
        else:
            b = _as_u8(mosi)
            if b is not None:
                self._buf_mosi.append(b)

        if isinstance(miso, (bytes, bytearray)) and len(miso) > 1:
            self._buf_miso.extend(miso)
        else:
            b = _as_u8(miso)
            if b is not None:
                self._buf_miso.append(b)

        self._t_last = frame.end_time

        return None
