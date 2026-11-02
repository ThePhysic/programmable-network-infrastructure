import socket
import struct
import unittest

from netlab.dns import _question, respond


def request(name="backend.lab", qtype=1):
    encoded = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"
    return struct.pack("!6H", 1234, 0x0100, 1, 0, 0, 0) + encoded + struct.pack("!HH", qtype, 1)


class DNSTests(unittest.TestCase):
    def test_address_and_transaction_are_preserved(self):
        answer = respond(request())
        ident, flags, questions, answers, _, _ = struct.unpack("!6H", answer[:12])
        self.assertEqual((ident, questions, answers), (1234, 1, 1))
        self.assertEqual(flags & 15, 0)
        self.assertTrue(flags & 0x8000)
        self.assertEqual(socket.inet_ntoa(answer[-4:]), "10.77.3.2")

    def test_case_insensitive_name(self):
        self.assertEqual(respond(request("BACKEND.LAB"))[-4:], socket.inet_aton("10.77.3.2"))

    def test_nxdomain_fault_and_unknown_name(self):
        for packet, mode in ((request(), "nxdomain"), (request("unknown.lab"), "healthy")):
            answer = respond(packet, mode)
            self.assertEqual(struct.unpack("!H", answer[2:4])[0] & 15, 3)
            self.assertEqual(struct.unpack("!H", answer[6:8])[0], 0)

    def test_aaaa_is_nodata_not_false_address(self):
        answer = respond(request(qtype=28))
        self.assertEqual(struct.unpack("!H", answer[2:4])[0] & 15, 0)
        self.assertEqual(struct.unpack("!H", answer[6:8])[0], 0)

    def test_wrong_answer_is_an_actual_different_address(self):
        self.assertEqual(respond(request(), "wrong-answer")[-4:], socket.inet_aton("10.77.3.99"))

    def test_malformed_packets_fail_without_unbounded_parsing(self):
        malformed = [b"", b"\0" * 11, request()[:15], request()[:-1],
                     struct.pack("!6H", 1, 0, 1, 0, 0, 0) + b"\xc0\x0c\0\1\0\1",
                     struct.pack("!6H", 1, 0, 2, 0, 0, 0) + b"\0\0\1\0\1",
                     b"x" * 4097]
        for packet in malformed:
            with self.subTest(packet=packet[:20]), self.assertRaises((ValueError, UnicodeError)):
                respond(packet)

    def test_question_name_length_is_bounded(self):
        name = ".".join(["a" * 63] * 5)
        with self.assertRaises(ValueError):
            _question(request(name))


if __name__ == "__main__":
    unittest.main()
