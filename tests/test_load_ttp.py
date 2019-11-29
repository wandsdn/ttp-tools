# Copyright 2019 Richard Sanger, Wand Network Research Group
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest
import logging
from ttp_tools import TTP
BASE = './tests/test_patterns/'
BASE_ISSUES = 0

class TestInputParsing(unittest.TestCase):

    def verify_loaded(self, ttp, issues=None, tables=2, groups=0, features=0,
                      identifiers=0):
        if issues is None:
            self.assertEqual(len(ttp.issues), BASE_ISSUES)
        else:
            self.assertGreaterEqual(len(ttp.issues), BASE_ISSUES+issues)
        self.assertEqual(len(ttp.tables_by_number), tables)
        self.assertEqual(len(ttp.tables_by_name), tables)
        self.assertEqual(len(ttp.groups_by_name), groups)
        self.assertEqual(len(ttp.features), features)
        self.assertEqual(len(ttp.identifiers), identifiers)

    def setUp(self):
        logging.getLogger().setLevel(level=logging.WARNING)

    def test_0(self):
        ttp = TTP.TableTypePattern(BASE+'0-simple_working_example-utf8.json', track_orig=True)
        self.verify_loaded(ttp)

    def test_1(self):
        ttp = TTP.TableTypePattern(BASE+'1-utf16.json', track_orig=True)
        self.verify_loaded(ttp)

    def test_2(self):
        ttp = TTP.TableTypePattern(BASE+'2-utf32.json', track_orig=True)
        self.verify_loaded(ttp)

    def test_3(self):
        ttp = TTP.TableTypePattern(BASE+'3-extra-tablemap.json', track_orig=True)
        self.verify_loaded(ttp, issues=1)

    def test_4(self):
        ttp = TTP.TableTypePattern(BASE+'4-extra-flowtable.json', track_orig=True)
        self.verify_loaded(ttp, issues=1)

    def test_5(self):
        ttp = TTP.TableTypePattern(BASE+'5-alternate-tablemap.json', track_orig=True)
        self.verify_loaded(ttp)

    def test_6(self):
        ttp = TTP.TableTypePattern(BASE+'6-bad-tablemap.json', track_orig=True)
        self.verify_loaded(ttp, issues=1)

    def test_7(self):
        ttp = TTP.TableTypePattern(BASE+'7-bad-alternate-tablemap.json', track_orig=True)
        self.verify_loaded(ttp, issues=3)

    def test_8(self):
        ttp = TTP.TableTypePattern(BASE+'8-unnamed-flowtable.json', track_orig=True)
        self.verify_loaded(ttp, issues=1, tables=1)

    def test_9(self):
        ttp = TTP.TableTypePattern(BASE+'9-empty.json', track_orig=True)
        self.verify_loaded(ttp, issues=3, tables=0)

if __name__ == '__main__':
    unittest.main()
