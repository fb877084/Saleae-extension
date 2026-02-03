# Progress: saleae-espi-hla

## Milestone 1 (Logic2 v2.4.40, Windows x64)

### Goal
Parse Logic2 **SPI analyzer** frames into **eSPI transactions** and show readable summary lines including:
- CMD (command opcode)
- TAR (handled heuristically)
- RSP (response opcode)
- WAIT_STATE count
- STATUS (16-bit) + bit names
- CRC bytes (and best-effort CRC8 check)

### Implemented
- `high_level_analyzer.py`
  - Added robust aggregation:
    - Uses SPI analyzer `enable`/`disable` frames when present (preferred).
    - Fallback: splits on idle gaps using `split_on_idle_us` setting.
    - Handles SPI analyzer data values as `int`, `bytes`, or simple strings.
  - Added best-effort eSPI transaction parsing:
    - Command opcode naming for common opcodes (`GET_STATUS`, `GET/SET_CONFIGURATION`, `PUT/GET_PC/NP`, VWIRE, OOB, flash).
    - Response opcode decoding per spec (`ACCEPT`, `DEFER`, `NON_FATAL_ERROR`, `FATAL_ERROR`, `NO_RESPONSE`).
    - WAIT_STATE detection/count (0x0F).
    - STATUS extraction from last 3 response bytes (STS[2] + CRC[1]).
      - Endianness heuristic: prefer interpretation where `VWIRE_FREE` bit2 is set.
      - Decodes set bits to names (`PC_FREE`, `NP_FREE`, `PC_AVAIL`, `NP_AVAIL`, …).
    - CRC8 (poly 0x07) calculator:
      - Compares command CRC and response CRC against computed values (best-effort; WAIT_STATE excluded from response CRC).
  - Output: one AnalyzerFrame of type `espi` per CS# transaction with a compact `text` summary.

- `README.md`
  - Added installation steps.
  - Added verification procedure using the included `inbound/` capture and SPI settings from `meta.json`.

### Known gaps / next milestones
- True TAR-aware bit-level alignment (SPI analyzer gives 8-bit chunks; TAR is 2 clocks).
- Full command-specific HDR/DATA parsing (e.g., GET/SET_CONFIGURATION address/data decoding, peripheral channel packet formats).
- More reliable response start detection on captures where response bytes can legitimately be 0xFF.
