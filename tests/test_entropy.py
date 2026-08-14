import os
import shutil
import tempfile
import unittest
from app.entropy.entropy_engine import ShannonEntropyEngine

class TestShannonEntropy(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_entropy_empty_file(self):
        file_path = os.path.join(self.test_dir, "empty.txt")
        with open(file_path, "wb") as f:
            pass
        entropy = ShannonEntropyEngine.calculate_entropy(file_path)
        self.assertEqual(entropy, 0.0)

    def test_entropy_plain_text(self):
        file_path = os.path.join(self.test_dir, "plain.txt")
        with open(file_path, "wb") as f:
            f.write(b"AAAA" * 100)
        entropy = ShannonEntropyEngine.calculate_entropy(file_path)
        self.assertLess(entropy, 3.0)

    def test_entropy_random_bytes(self):
        file_path = os.path.join(self.test_dir, "encrypted.bin")
        with open(file_path, "wb") as f:
            f.write(os.urandom(2048))
        entropy, is_threat, meta = ShannonEntropyEngine.evaluate_threat(file_path, threshold=7.0)
        self.assertGreater(entropy, 7.0)
        self.assertTrue(is_threat)

if __name__ == '__main__':
    unittest.main()
