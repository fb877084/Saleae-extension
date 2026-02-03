# Saleae HLA: eSPI (Intel-style)

This is a Saleae **High Level Analyzer (HLA)** extension for decoding **eSPI-over-SPI-capture** using Logic 2’s built-in **SPI** analyzer as the low-level source.

Milestone 1 decodes (best-effort):
- **CMD** (command opcode) → names like `GET_STATUS`, `PUT_PC`, `PUT_NP`, etc.
- **RSP** (response opcode) → `ACCEPT`, `DEFER`, `NON_FATAL_ERROR`, `FATAL_ERROR`, `NO_RESPONSE`
- **WAIT_STATE** count (0x0F) at the start of the response phase
- **STATUS** (16-bit) + decoded bit names (e.g. `PC_FREE`, `NP_AVAIL`, …)
- **CRC** bytes shown and compared against a CRC-8(0x07) best-effort calculation

Milestone 2 (partial):
- **Virtual Wire (Channel 1)** packet decoding for `PUT_VWIRE` and `GET_VWIRE`
  - decodes VW packet header (`count`) and groups (`index`, `data`)
  - decodes interrupt event VW group (`index=0x00/0x01`) into IRQ number + level

Notes / limitations (Milestone 1):
- eSPI has a 2-clock **TAR** window; when decoding from an 8-bit SPI analyzer stream, TAR may not align cleanly to a byte boundary. This HLA uses heuristics to locate the response phase.
- Payload (HDR/DATA) parsing per command type is not fully implemented yet; it focuses on transaction framing and readability.

## Install (Logic 2)
1. Logic 2 → **Extensions**.
2. (Developer) **Install from Folder**.
3. Select this folder: `saleae-espi-hla/`.

## Verify using the provided capture (Logic 2 v2.4.40)
The repository includes a capture folder: `inbound/`.

1. Logic 2 → **Open Capture…**
2. Select the folder `saleae-espi-hla/inbound/` (it contains `meta.json` and `digital-*.bin`).
3. Add the built-in **SPI** analyzer with these settings (from `inbound/meta.json`):
   - MOSI: **Digital 1**
   - MISO: **Digital 2**
   - Clock: **Digital 7**
   - Enable (CS#): **Digital 5** (Active Low)
   - Bits per transfer: **8**
   - Bit order: **MSB first**
   - CPOL: **0** (clock low when idle)
   - CPHA: **0** (sample on leading edge)
4. Add the **eSPI (HLA)** analyzer on top of the SPI analyzer.
5. Optional HLA settings:
   - `show_raw = yes` to include raw MOSI/MISO bytes in the summary
   - `split_on_idle_us` if your SPI analyzer does not emit enable/disable frames

You should see one HLA frame per CS# transaction with summary text like:
- `GET_STATUS (0x25) | CMD_CRC .. | ACCEPT (0x08) | STS .. | RSP_CRC ..`
- `PUT_VWIRE (0x04) VW cnt=0 (n=1) [0] VW_IRQ lvl=1 irq=5 (idx=0x00 data=0x85) | ...`
- `GET_VWIRE (0x05) | ACCEPT (0x08) VW cnt=0 (n=1) [0] VW_IRQ lvl=1 irq=5 (idx=0x00 data=0x85) | ...`

## Development notes
- Decoder source: `high_level_analyzer.py`
- Spec references extracted into `spec_text/*.txt`
