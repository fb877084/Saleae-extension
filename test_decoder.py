import unittest

from high_level_analyzer import crc8_espi, decode_espi_best_effort


class TestDecoder(unittest.TestCase):
    def test_get_configuration_parses_addr_and_rsp(self):
        # GET_CONFIGURATION: CMD + ADDR(2) + CRC
        cmd = bytes([0x21, 0x00, 0x04])  # addr 0x0400 or 0x0004 depending on endianness
        cmd_crc = bytes([crc8_espi(cmd)])
        mosi = cmd + cmd_crc

        # Response: ACCEPT + 1DW data + STS(2) + CRC
        rsp0 = bytes([0x08])
        data = bytes([0x11, 0x22, 0x33, 0x44])
        sts = bytes([0x0F, 0x03])
        rsp_crc = bytes([crc8_espi(rsp0 + data + sts)])

        # Align MISO with pulled-up bytes during command phase.
        miso = bytes([0xFF]) * len(mosi) + rsp0 + data + sts + rsp_crc
        # Pad MOSI during response with dummy bytes so streams are similar length.
        mosi = mosi + bytes([0x00]) * (len(miso) - len(mosi))

        dec = decode_espi_best_effort(mosi, miso)
        self.assertEqual(dec.cmd, 0x21)
        self.assertIn("ADDR=", " ".join(dec.cmd_detail))
        self.assertEqual(dec.rsp_name.split("+")[0], "ACCEPT")
        self.assertIsNotNone(dec.status_u16)
        self.assertEqual(dec.rsp_crc_rx, dec.rsp_crc_calc)

    def test_set_configuration_parses_data(self):
        # SET_CONFIGURATION: CMD + ADDR(2) + DATA(4) + CRC
        cmd = bytes([0x22, 0x00, 0x04, 0x78, 0x56, 0x34, 0x12])
        cmd_crc = bytes([crc8_espi(cmd)])
        mosi = cmd + cmd_crc

        rsp0 = bytes([0x08])
        sts = bytes([0x0F, 0x03])
        rsp_crc = bytes([crc8_espi(rsp0 + sts)])

        miso = bytes([0xFF]) * len(mosi) + rsp0 + sts + rsp_crc
        mosi = mosi + bytes([0x00]) * (len(miso) - len(mosi))

        dec = decode_espi_best_effort(mosi, miso)
        self.assertEqual(dec.cmd, 0x22)
        self.assertIn("DATA_LE=0x12345678", " ".join(dec.cmd_detail))

    def test_put_vwire_decodes_irq_event(self):
        # PUT_VWIRE: CMD + VW packet + CRC
        # VW packet: count(0 => 1 group) + idx + data
        # idx=0 => IRQ[0..127], data: bit7 level, bits6:0 line
        cmd = bytes([0x04, 0x00, 0x00, 0x85])  # irq=5, level=1
        cmd_crc = bytes([crc8_espi(cmd)])
        mosi = cmd + cmd_crc

        rsp0 = bytes([0x08])
        sts = bytes([0x0F, 0x03])
        rsp_crc = bytes([crc8_espi(rsp0 + sts)])

        miso = bytes([0xFF]) * len(mosi) + rsp0 + sts + rsp_crc
        mosi = mosi + bytes([0x00]) * (len(miso) - len(mosi))

        dec = decode_espi_best_effort(mosi, miso)
        self.assertEqual(dec.cmd, 0x04)
        s = " ".join(dec.cmd_detail)
        self.assertIn("VW", s)
        self.assertIn("VW_IRQ", s)
        self.assertIn("irq=5", s)

    def test_get_vwire_decodes_response_packet(self):
        # GET_VWIRE: assume CMD + CRC
        cmd = bytes([0x05])
        cmd_crc = bytes([crc8_espi(cmd)])
        mosi = cmd + cmd_crc

        rsp0 = bytes([0x08])
        vw_pkt = bytes([0x00, 0x00, 0x85])  # count=0, idx=0, data=0x85
        sts = bytes([0x0F, 0x03])
        rsp_crc = bytes([crc8_espi(rsp0 + vw_pkt + sts)])

        miso = bytes([0xFF]) * len(mosi) + rsp0 + vw_pkt + sts + rsp_crc
        mosi = mosi + bytes([0x00]) * (len(miso) - len(mosi))

        dec = decode_espi_best_effort(mosi, miso)
        self.assertEqual(dec.cmd, 0x05)
        s = " ".join(dec.rsp_detail)
        self.assertIn("VW", s)
        self.assertIn("VW_IRQ", s)
        self.assertIn("irq=5", s)

    def test_rsp_start_not_missed_after_ff_run(self):
        # Real capture pattern: MISO begins with a run of 0xFF then transitions
        # to 0xC3... We should not label this as NO_RESPONSE.
        mosi = bytes.fromhex('44 09 10 00 AE 00 00 00 00 00 00 00 00 25')
        miso = bytes.fromhex('FF FF FF FF FF C3 C3 C3 C3 C3 C2 03 C0 A7')
        dec = decode_espi_best_effort(mosi, miso)
        self.assertNotEqual(dec.rsp_name, 'NO_RESPONSE')
        self.assertEqual(dec.rsp_name, 'FATAL_ERROR')


if __name__ == "__main__":
    unittest.main()
