import runpy
import sys
from pathlib import Path
from unittest import TestCase


class ImportIsolationTest(TestCase):
    def test_import_preserves_pyoaev_modules_and_finders(self):
        def pyoaev_modules():
            return {
                name: module
                for name, module in sys.modules.items()
                if name == "pyoaev" or name.startswith("pyoaev.")
            }

        modules = pyoaev_modules()
        finders = list(sys.meta_path)

        runpy.run_path(str(Path(__file__).with_name("test_none_response.py")))

        self.assertEqual(pyoaev_modules(), modules)
        self.assertEqual(sys.meta_path, finders)
