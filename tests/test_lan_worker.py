import importlib.util
import tempfile
import unittest
from pathlib import Path


class LanWorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1] / "lan-worker.py"
        spec = importlib.util.spec_from_file_location("newfpv_lan_worker", path)
        cls.worker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.worker)

    def test_single_windows_backslashes_are_repaired(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "lan-worker.json"
            config.write_text('{"coordinator_url":"http://host:8787","token":"x","wordlist_roots":["C:\\HandshakeWordlists"]}', encoding="utf-8")
            original = self.worker.CONFIG_PATH
            try:
                self.worker.CONFIG_PATH = config
                loaded = self.worker.load_config()
            finally:
                self.worker.CONFIG_PATH = original
            self.assertEqual(loaded["wordlist_roots"], [r"C:\HandshakeWordlists"])
            self.assertEqual(__import__("json").loads(config.read_text(encoding="utf-8"))["wordlist_roots"], [r"C:\HandshakeWordlists"])

    def test_hashcat_712_recovered_pair_uses_found_count(self):
        self.assertEqual(self.worker.recovered_count([0, 1]), 0)
        self.assertEqual(self.worker.recovered_count([1, 1]), 1)
        self.assertEqual(self.worker.recovered_count(2), 2)


if __name__ == "__main__":
    unittest.main()
