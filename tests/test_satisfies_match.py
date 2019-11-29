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
from ofequivalence.rule import Match
import ttp_tools.ttp_satisfies
from ttp_tools import TTP


class TestTTPMatches(unittest.TestCase):

    def setUp(self):
        self.ttp = TTP.TableTypePattern('./tests/test_patterns/satisfies_match.json')

    def check_cases(self, match, cases):
        for case in cases:
            fm = Match()
            for i in case[0]:
                fm.append(*i)
            if match.satisfies(fm) != case[1]:
                ret = match.satisfies(fm)
                raise self.failureException("match.satisfies(" + str(case[0])
                                            + ") != " + str(case[1]))

    def test_simple_exact_match(self):
        """ Tests Simple Match and Simple Matchv2
            {
                "name": "Test Simple Match",
                "match_set": [
                    {"field": "IN_PORT", "match_type": "exact"}
                ],...
            },
            {
                "name": "Test Simple Matchv2",
                "match_set": [
                    {"field": "IN_PORT"}
                ],...
            }
            Note: the default match type should be exact hence these should
                  seem identical
            Note: IN_PORT is 32 bit wide
        """
        # Do we match
        simple_match = (self.ttp.find_table("First Table")
                        .find_flow_mod("Test Simple Match").match_set)
        # We check that the default no mask works
        simple_matchv2 = (self.ttp.find_table("First Table")
                          .find_flow_mod("Test Simple Matchv2").match_set)

        cases = [
            ([],                                    False),  # Empty
            ([("IN_PORT", 1, None)],                True),  # exact case
            ([("IN_PORT", 63, None)],               True),  # exact case
            ([("VLAN_VID", 1, None)],               False),  # Wrong field case
            ([("IN_PORT", 1, 0x3fab)],              False),  # Random mask
            ([("IN_PORT", 0, 0)],                   False),  # Zero (all) mask
            ([("IN_PORT", 1, 0xff000000)],          False),  # Prefix mask
            ([("IN_PORT", 12, 0xffffffff)],         True),  # Exact
            ([("IN_PORT", 12, 0xffffffffff)],       True),  # Exact trunc
            ([("IN_PORT", 11, None), ("VLAN_VID", 1, None)], False),  # Two fields
            ]
        self.check_cases(simple_match, cases)
        self.check_cases(simple_matchv2, cases)

    def test_simple_all_or_exact_match(self):
        """ Tests a simple all or exact match
            {
                "name": "Test Simple Exact or All",
                "match_set": [
                    {"field": "IN_PORT", "match_type": "exact_or_all"}
                ],...
            }
        """
        simple_match = (self.ttp.find_table("First Table")
                        .find_flow_mod("Test Simple All or Exact").match_set)
        cases = [
            ([],                                    True),  # Empty Flowmod all case
            ([("IN_PORT", 0, 0x0)],                 True),  # Simple all case
            ([("IN_PORT", 16, 0x0)],                True),  # all case
            ([("VLAN_VID", 1024, None)],            False),  # Wrong field case
            ([("IN_PORT", 1, 0x3fab)],              False),  # Random mask
            ([("IN_PORT", 1, 0xff000000)],          False),  # prefix mask
            ([("IN_PORT", 1, None)],                True),  # exact mask
            ([("IN_PORT", 12, 0xffffffff)],         True),  # exact mask
            ([("IN_PORT", 12, 0xffffffffff)],       True),  # exact mask trunc
            ([("IN_PORT", 11, None), ("VLAN_VID", 1, None)], False),  # 2 fields
            ]
        self.check_cases(simple_match, cases)

    def test_simple_prefix_mask(self):
        """ Tests a simple prefix mask - We say all and exact are valid prefixes
            {
                "name": "Test Simple Prefix",
                "match_set": [
                    {"field": "IPV4_SRC", "match_type": "prefix"}
                ],...
            }
        """
        simple_match = (self.ttp.find_table("First Table")
                        .find_flow_mod("Test Simple Prefix").match_set)
        cases = [
            ([],                                    True),  # Empty Flowmod all
            ([("IPV4_SRC", 0, 0x0)],                True),  # Simple all case
            ([("IPV4_SRC", 16, 0x0)],               True),  # all case
            ([("IN_PORT", 1024, 0xfffffff0)],       False),  # Wrong field case
            ([("IPV4_SRC", 1, 0x3fab)],             False),  # Random mask
            ([("IPV4_SRC", 1, 0xff800000)],         True),  # prefix mask
            ([("IPV4_SRC", 154, 0xffff0000)],       True),  # prefix mask
            ([("IPV4_SRC", 154, 0x7fff0000)],       False),  # bad prefix mask
            ([("IPV4_SRC", 154, 0xfffff0000)],      True),  # prefix mask trunc
            ([("IPV4_SRC", 1, None)],               True),  # exact mask
            ([("IPV4_SRC", 12, 0xffffffff)],        True),  # exact mask
            ([("IPV4_SRC", 12, 0xffffffffff)],      True),  # exact mask trunc
            ([("IPV4_SRC", 11, 0xffff0000), ("VLAN_VID", 1, None)], False),  # 2 fields
            ]
        self.check_cases(simple_match, cases)

    def test_simple_mask(self):
        """ Tests a simple mask - We say all and exact are valid prefixes
            {
                "name": "Test Simple Mask",
                "match_set": [
                    {"field": "IPV4_SRC", "match_type": "mask"}
                ],...
            }
        """
        simple_match = (self.ttp.find_table("First Table")
                        .find_flow_mod("Test Simple Mask").match_set)
        cases = [
            ([],                                    True),  # Empty Flowmod all
            ([("IPV4_SRC", 0, 0x0)],                True),  # Simple all case
            ([("IPV4_SRC", 16, 0x0)],               True),  # all case
            ([("IN_PORT", 1024, 0xfffffff0)],       False),  # Wrong field case
            ([("IPV4_SRC", 1, 0x3fab)],             True),  # Random mask
            ([("IPV4_SRC", 1, 0xff800000)],         True),  # prefix mask
            ([("IPV4_SRC", 154, 0xffff0000)],       True),  # prefix mask
            ([("IPV4_SRC", 154, 0x7fff0000)],       True),  # bad prefix mask
            ([("IPV4_SRC", 154, 0xfffff0000)],      True),  # prefix mask trunc
            ([("IPV4_SRC", 1, None)],               True),  # exact mask
            ([("IPV4_SRC", 12, 0xffffffff)],        True),  # exact mask
            ([("IPV4_SRC", 12, 0xffffffffff)],      True),  # exact mask trunc
            ([("IPV4_SRC", 11, 0xffff0000), ("VLAN_VID", 1, None)], False),  # 2 fields
            ]
        self.check_cases(simple_match, cases)

    def test_simple_value(self):
        """ Tests a mask field with a fixed value
            {
                "name": "Test Fixed Value",
                "match_set": [
                    {"field": "IPV4_SRC", "match_type": "all_or_exact", "value": "16"}
                ],...
            },
        """
        simple_match = (self.ttp.find_table("First Table")
                        .find_flow_mod("Test Fixed Value").match_set)
        cases = [
            ([],                                    True),  # Empty Flowmod all
            ([("IPV4_SRC", 16, 0x0)],               True),  # Simple all case
            ([("IPV4_SRC", 0, 0x0)],                True),  # all case
            ([("IPV4_SRC", 16, 0x3fab)],            False),  # Bad mask !all or exact
            ([("IN_PORT", 16, None)],               False),  # Wrong field case
            ([("IPV4_SRC", 16, None)],              True),  # Exact correct
            ([("IPV4_SRC", 17, None)],              False),  # Exact wrong value
            ([("IPV4_SRC", 16, 0xffffffff)],        True),  # Exact mask
            ([("IPV4_SRC", 17, 0xffffffff)],        False),  # Wrong + exact mask
            ([("IPV4_SRC", 16, None), ("VLAN_VID", 1, None)], False),  # 2 fields
            ]
        self.check_cases(simple_match, cases)

    def test_simple_fixed_mask(self):
        """ Tests a mask field with a fixed value
            - The standard seems unclear on this point, I interpret the
              mask much like the value, in that it must be set to the supplied
              value. This seems to be how it is used.
            {
                "name": "Test Fixed Value",
                "match_set": [
                    {"field": "IPV4_SRC", "match_type": "mask", "mask": "0xfa0"}
                ],...
            },
        """
        simple_match = (self.ttp.find_table("First Table")
                        .find_flow_mod("Test Fixed Mask").match_set)
        cases = [
            ([],                                    False),  # All
            ([("IPV4_SRC", 0, 0xfa0)],              True),  # Correct mask
            ([("IPV4_SRC", 0x12168910, 0xfa0)],     True),  # Other masked
            ([("IN_PORT", 1024, 0xfa0)],            False),  # Wrong field case
            ([("IPV4_SRC", 1, 0xaa0)],              False),  # undermasked
            ([("IPV4_SRC", 1, 0xfaf)],              False),  # overmasked
            ([("IPV4_SRC", 1, None)],               False),  # exact mask
            ([("IPV4_SRC", 1, 0xffffffff)],         False),  # exact mask
            ([("IPV4_SRC", 1, 0x0)],                False),  # all mask
            ([("IPV4_SRC", 11, 0xfa0), ("VLAN_VID", 1, 0xfa0)], False),  # 2 fields
            ]
        self.check_cases(simple_match, cases)

    def test_simple_const_bitmask(self):
        """ Tests a bit mask
            {
                "name": "Test Const Bitmask",
                "match_set": [
                    {"field": "IPV4_SRC", "match_type": "mask",
                     "const_mask": "0xf3", "const_value": "0x51"}
                ],...
            },
        """
        simple_match = (self.ttp.find_table("First Table")
                        .find_flow_mod("Test Const Bitmask").match_set)
        cases = [
            ([],                                    False),  # Nope
            ([("IPV4_SRC", 0x51, 0xf3)],            True),  # Exact match
            ([("IPV4_SRC", 0x51, 0xfff)],           True),  # Extra mask
            ([("IPV4_SRC", 0xf51, 0xf3)],           True),  # Extended value
            ([("IPV4_SRC", 0xf51, 0xff3)],          True),  # Extended value+Mask
            ([("IPV4_SRC", 0x51, 0x0)],             False),  # Missing mask
            ([("IPV4_SRC", 0x50, 0xff)],            False),  # 1->0
            ([("IPV4_SRC", 0x53, 0xff)],            False),  # 0->1
            ([("IPV4_SRC", 0xff51, None)],          True),  # all mask
            ([("IPV4_SRC", 0xffff, None)],          False),  # all mask
            ([("IPV4_SRC", 0x51, 0xffffffff)],      True),  # all mask
            ([("IPV4_SRC", 0x00, 0xffffffff)],      False),  # all mask
            ]
        self.check_cases(simple_match, cases)

    def test_all(self):
        """ Test a match requiring IPV4_SRC,IN_PORT and VLAN_VID"""
        simple_match = (self.ttp.find_table("First Table")
                        .find_flow_mod("Test Meta All").match_set)
        simple_matchv2 = (self.ttp.find_table("First Table")
                          .find_flow_mod("Test Meta Allv2").match_set)
        vlan = ("VLAN_VID", 1, None)
        in_port = ("IN_PORT", 2, None)
        ipv4_src = ("IPV4_SRC", 45, None)
        cases = [
            ([],                                    False),
            ([vlan, in_port, ipv4_src],             True),
            ([ipv4_src, in_port, vlan],             True),  # Order don't matter
            ([ipv4_src],                            False),  # 1 wont work
            ([in_port],                             False),  # 1 wont work
            ([vlan],                                False),  # 1 wont work
            ([vlan, in_port],                       False),  # 2 wont work
            ([ipv4_src, vlan],                      False),  # 2 wont work
            ([ipv4_src, vlan, ("IPV4_DST", 1, None)], False),  # Wrong field fails
            ]
        self.check_cases(simple_match, cases)
        self.check_cases(simple_matchv2, cases)

    def test_zero_or_more(self):
        """ Test a zero or more requiring IPV4_SRC and IN_PORT """
        simple_match = (self.ttp.find_table("First Table")
                        .find_flow_mod("Test Meta Zero or More").match_set)
        vlan = ("VLAN_VID", 1, None)
        in_port = ("IN_PORT", 2, None)
        ipv4_src = ("IPV4_SRC", 45, None)
        cases = [
            ([],                                    True),  # 0
            ([vlan, in_port, ipv4_src],             True),  # 3
            ([ipv4_src, in_port, vlan],             True),  # Order don't matter
            ([ipv4_src],                            True),  # 1
            ([in_port],                             True),  # 1
            ([vlan],                                True),  # 1
            ([vlan, in_port],                       True),  # 2
            ([ipv4_src, vlan],                      True),  # 2
            ([ipv4_src, vlan, ("IPV4_DST", 1, None)], False),  # Wrong field fails
            ]
        self.check_cases(simple_match, cases)

    def test_one_or_more(self):
        """ Test a one or more requiring IPV4_SRC and IN_PORT """
        simple_match = (self.ttp.find_table("First Table")
                        .find_flow_mod("Test Meta One or More").match_set)
        vlan = ("VLAN_VID", 1, None)
        in_port = ("IN_PORT", 2, None)
        ipv4_src = ("IPV4_SRC", 45, None)
        cases = [
            ([],                                    False),  # 0
            ([vlan, in_port, ipv4_src],             True),  # 3
            ([ipv4_src, in_port, vlan],             True),  # Order don't matter
            ([ipv4_src],                            True),  # 1
            ([in_port],                             True),  # 1
            ([vlan],                                True),  # 1
            ([vlan, in_port],                       True),  # 2
            ([ipv4_src, vlan],                      True),  # 2
            ([ipv4_src, vlan, ("IPV4_DST", 1, None)], False),  # Wrong field fails
            ]
        self.check_cases(simple_match, cases)

    def test_zero_or_one(self):
        """ Test a zero or one requiring IPV4_SRC and IN_PORT """
        simple_match = (self.ttp.find_table("First Table")
                        .find_flow_mod("Test Meta Zero or One").match_set)
        vlan = ("VLAN_VID", 1, None)
        in_port = ("IN_PORT", 2, None)
        ipv4_src = ("IPV4_SRC", 45, None)
        cases = [
            ([],                                    True),  # 0
            ([vlan, in_port, ipv4_src],             False),  # 3
            ([ipv4_src, in_port, vlan],             False),  # Order don't matter
            ([ipv4_src],                            True),  # 1
            ([in_port],                             True),  # 1
            ([vlan],                                True),  # 1
            ([vlan, in_port],                       False),  # 2
            ([ipv4_src, vlan],                      False),  # 2
            ]
        self.check_cases(simple_match, cases)
