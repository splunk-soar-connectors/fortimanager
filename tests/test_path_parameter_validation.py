# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import ast
import re
import unittest
from pathlib import Path


CONNECTOR = Path(__file__).resolve().parents[1] / "fortimanager_connector.py"


def _load_validator():
    source = CONNECTOR.read_text()
    tree = ast.parse(source)
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_is_valid_path_parameter")
    namespace = {"re": re}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(CONNECTOR), "exec"), namespace)
    return namespace["_is_valid_path_parameter"]


_is_valid_path_parameter = _load_validator()


class PathParameterValidationTests(unittest.TestCase):
    def test_accepts_canonical_object_names(self):
        for value in ("root", "pkg-1", "address_name", "segment.with.dot"):
            with self.subTest(value=value):
                self.assertTrue(_is_valid_path_parameter(value))

    def test_rejects_path_active_or_noncanonical_values(self):
        for value in (".", "..", "a..b", "a/b", "a b", "", None, 1):
            with self.subTest(value=value):
                self.assertFalse(_is_valid_path_parameter(value))


if __name__ == "__main__":
    unittest.main()
