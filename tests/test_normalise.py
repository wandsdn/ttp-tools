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
from ttp_tools.TTP import normalise_value


class TestNormaliseValue(unittest.TestCase):

    def test_mac_address(self):
        self.assertEqual(normalise_value('f5-88-24-a1-b6-ff'), 0xf58824a1b6ff)
        # not in TTP spec but not unambiguous either
        self.assertEqual(normalise_value('f5:88:24:a1:b6:ff'), 0xf58824a1b6ff)

    def test_int(self):
        self.assertEqual(normalise_value(14), 14)

    def test_int_as_string(self):
        self.assertEqual(normalise_value('143'), 143)

    def test_int_as_hex_string(self):
        self.assertEqual(normalise_value('0x143'), 0x143)

    def test_bad_string(self):
        # self.assertEqual(normalise_value('a0x143'), None)
        pass

    def test_ipv4(self):
        self.assertEqual(normalise_value('244.0.0.0'), 0xF4000000)
        self.assertEqual(normalise_value('244.7.5.8'), 0xF4070508)

    def test_ipv6(self):
        self.assertEqual(normalise_value('bade:0:ca54:5:4:ffff:4:9'),
                         0xbade0000ca5400050004ffff00040009)
        self.assertEqual(normalise_value('bade::ca54:5:4:ffff:4:9'),
                         0xbade0000ca5400050004ffff00040009)
        self.assertEqual(normalise_value('bade::5:4:ffff:4:9'),
                         0xbade0000000000050004ffff00040009)
        self.assertEqual(normalise_value('::'), 0x0)
        self.assertEqual(normalise_value('bade:0:ca54:5:4:ffff:4::'),
                         0xbade0000ca5400050004ffff00040000)
        self.assertEqual(normalise_value('::bade:ca54:5:4:ffff:4:0'),
                         0x0000badeca5400050004ffff00040000)
