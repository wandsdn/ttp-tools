#!/usr/bin/python
""" Displays a Table Type Pattern to the CLI
"""

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

from __future__ import print_function
import argparse
import logging

from .TTP import TableTypePattern

# In python3 raw_input has been removed and renamed to input
try:
    raw_input
except NameError:
    raw_input = input

# A ugly hack to print unicode correctly in python2
try:
    unicode
    old_print = print
    print = lambda *args, **dargs: old_print(*map(unicode, args), **dargs)
except NameError:
    pass

MATCH_DOCS = """
Match Suffix Key: !exact match, @prefix match, *optional, =value, /mask
"""

def wait():
    """ Give the user a chance to read output """
    print("")
    raw_input("---Press any key to continue---")


def select_options(options, text="Which one?", pre_numbered=False):
    """ Prompt the user to select from a number of options

        Automatically adds the q, quit option to any list.

        options: A list of choices
        text: The text displayed to the user
        pre_numbered: If true, options should be a list of tuples

        Returns the option, otherwise

    """
    if not pre_numbered:
        new_options = []
        for idx, element in enumerate(options, 1):
            new_options.append((idx, element))
        options = new_options
    options.append(('q', 'quit'))

    for ele in options:
        print("{}) {}".format(ele[0], ele[1]))
    input_ = raw_input(text + " ")
    print("")
    for item in options:
        if str(item[0]) == input_:
            return item
    for item in options:
        if item[1] == input_:
            return item
    return None


def menu_identifiers(ttp):
    while True:
        if ttp.identifiers:
            print("Found", len(ttp.identifiers.variables), "variables and",
                  len(ttp.identifiers.identifiers), "identifiers")
            options = ["Variables", "Extension Identifiers"]
            var = select_options(options)
            if var is None:
                print("I didn't quite catch that")
                continue
            elif var[0] == 'q':
                return
            elif var[1] == "Variables":
                options = list(enumerate(ttp.identifiers.variables.keys(), 1))
                options.append(('a', 'all'))
                var = select_options(options, pre_numbered=True)
                if var[0] == 'q':
                    continue
                elif var[0] == 'a':
                    for i in ttp.identifiers.variables.values():
                        print(i)
                        print('')
                else:
                    print(ttp.identifiers.variables[var[1]])
                wait()
            elif var[1] == "Extension Identifiers":
                options = list(enumerate(ttp.identifiers.identifiers.keys(), 1))
                options.append(('a', 'all'))
                var = select_options(options, pre_numbered=True)
                if var[0] == 'q':
                    continue
                elif var[0] == 'a':
                    for i in ttp.identifiers.identifiers.values():
                        print(i)
                        print('')
                else:
                    print(ttp.identifiers.identifiers[var[1]])
                wait()
        else:
            print("There seem to be no extra identifiers specified")
            wait()


def menu_tables(ttp):
    while True:
        print("Found ", len(ttp.get_tables()), "tables:")
        tables = [(t.number, t.name) for t in ttp.get_tables()]
        var = select_options(tables, "Which table?", True)
        if var is None:
            print("I didn't quite catch that")
            continue
        elif var[0] == 'q':
            return
        else:
            menu_flows(ttp.find_table(var[0]), ttp)

def menu_flows(table, ttp):
    while True:
        flows = [(i, f.name, f) for i, f in enumerate(table.flow_mod_types, 1)]
        flows += [(i, "Built-in: " + f.name, f) for i, f in
                  enumerate(table.built_in_flow_mods, len(flows) + 1)]
        flows.append(('b', 'all built-in'))
        flows.append(('a', 'all'))
        print("Found ", len(table.flow_mod_types),
              "flow mod types in", table.name + ":")
        var = select_options(flows, "Which flow?", True)
        if var is None:
            print("I didn't quite catch that")
            continue
        elif var[0] == 'a':
            ttp.print_table(table)
        elif var[0] == 'b':
            for bifm in table.built_in_flow_mods:
                print("")
                bifm.print_flow()
        elif var[0] == 'q':
            return
        else:
            var[2].print_flow()
        print(MATCH_DOCS)
        wait()


def menu_groups(ttp):
    while True:
        print("Found ", len(ttp.get_groups()), "groups:")
        groups = [g.name for g in ttp.get_groups()]
        var = select_options(groups, "Which group?")
        if var is None:
            print("I didn't quite catch that")
            continue
        elif var[0] == 'q':
            return
        else:
            print(ttp.groups_by_name[var[1]])
            wait()


def main():
    parser = argparse.ArgumentParser(
        description='Command line tool for traversing the hierarchy of a TTP.')
    parser.add_argument('ttp', help='A Table Type Pattern JSON description')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Disable printing errors from parsing the TTP')

    args = parser.parse_args()

    logger = None
    if args.quiet:
        # Use a logger which logs nothing
        logger = logging.getLogger('dummy')
        logger.addHandler(logging.NullHandler())
        logger.propagate = False


    ttp = TableTypePattern(args.ttp, track_orig=True, logger=logger)

    print("")
    print("Finished loading", ttp.NDM_metadata.get_short_description())
    print("")

    while True:
        options = ["TTP Info", "Security", "Variables and Extension Identifiers",
                   "Tables", "Groups"]
        var = select_options(options)
        if var is None:
            print("I didn't quite catch that")
            continue
        elif var[0] == 'q':
            break
        elif var[1] == "TTP Info":
            print(ttp.NDM_metadata)
            wait()
        elif var[1] == "Security":
            if ttp.security:
                print(ttp.security)
            else:
                print("No security guidance was provided by the TTP")
            wait()
        elif var[1] == "Variables and Extension Identifiers":
            menu_identifiers(ttp)
        elif var[1] == "Tables":
            menu_tables(ttp)
        elif var[1] == "Groups":
            menu_groups(ttp)

if __name__ == "__main__":
    main()
