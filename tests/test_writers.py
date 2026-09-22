import json
import os
import tempfile
import unittest
from pathlib import Path

from snyk_generate_cra_sbom_vex import writers


class WriteOutputsTests(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp()
        os.chdir(self._tmp)

    def tearDown(self):
        os.chdir(self._cwd)

    def test_default_names_are_sbom_and_vex_json_in_cwd(self):
        result = writers.write_outputs({"a": 1}, {"b": 2}, output_prefix=None)
        self.assertEqual(result.sbom_path, Path("sbom.json"))
        self.assertEqual(result.vex_path, Path("vex.json"))
        self.assertEqual(json.loads(Path("sbom.json").read_text()), {"a": 1})
        self.assertEqual(json.loads(Path("vex.json").read_text()), {"b": 2})

    def test_output_prefix_is_used_as_filename_stem(self):
        result = writers.write_outputs({"a": 1}, {"b": 2}, output_prefix="myrun")
        self.assertEqual(result.sbom_path, Path("myrun.sbom.json"))
        self.assertEqual(result.vex_path, Path("myrun.vex.json"))
        self.assertTrue(result.sbom_path.exists())
        self.assertTrue(result.vex_path.exists())

    def test_none_document_is_not_written(self):
        result = writers.write_outputs(None, None, output_prefix=None)
        self.assertIsNone(result.sbom_path)
        self.assertIsNone(result.vex_path)
        self.assertFalse(Path("sbom.json").exists())
        self.assertFalse(Path("vex.json").exists())

    def test_writes_only_sbom_when_vex_is_none(self):
        result = writers.write_outputs({"a": 1}, None, output_prefix=None)
        self.assertIsNotNone(result.sbom_path)
        self.assertIsNone(result.vex_path)
        self.assertFalse(Path("vex.json").exists())


if __name__ == "__main__":
    unittest.main()
