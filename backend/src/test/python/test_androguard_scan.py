import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


module = types.ModuleType("androguard")
misc = types.ModuleType("androguard.misc")
misc.AnalyzeAPK = lambda path: None
sys.modules["androguard"] = module
sys.modules["androguard.misc"] = misc
source = Path(__file__).resolve().parents[2] / "main" / "resources" / "androguard_scan.py"
spec = importlib.util.spec_from_file_location("androguard_scan", source)
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


class FakeApk:
    def get_package(self):
        return "example.app"

    def get_permissions(self):
        return ["android.permission.INTERNET", "android.permission.INTERNET"]

    def get_dex_names(self):
        return ["classes.dex", "classes2.dex"]


class FakeDex:
    def get_classes(self):
        return [types.SimpleNamespace(name="Lexample/Main;")]

    def get_methods(self):
        return [
            types.SimpleNamespace(class_name="Ljava/lang/Runtime;", name="exec"),
            types.SimpleNamespace(class_name="java.lang.Runtime", name="exec"),
            types.SimpleNamespace(class_name="Ljavax/crypto/Cipher;", name="getInstance"),
        ]


class AndroguardHelperTest(unittest.TestCase):
    def test_metadata_and_dex_references_are_bounded_and_deduplicated(self):
        with patch.object(scan, "AnalyzeAPK", return_value=(FakeApk(), [FakeDex()], None)):
            result = scan.analyze("sample.apk")
        self.assertEqual(result["metadata"]["packageName"], "example.app")
        self.assertEqual(result["permissions"], ["android.permission.INTERNET"])
        self.assertEqual(result["dexFileNames"], ["classes.dex", "classes2.dex"])
        self.assertEqual(result["dexClassCount"], 1)
        self.assertEqual(result["dexMethodCount"], 3)
        self.assertEqual([finding["apiName"] for finding in result["apiFindings"]], ["Runtime.exec", "Cipher.getInstance"])


if __name__ == "__main__":
    unittest.main()
