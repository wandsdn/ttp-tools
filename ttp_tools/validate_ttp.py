#!/usr/bin/python
""" Validates a Table Type Pattern

    Produces an HTML document which highlights any issues.
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
import json
import logging
import cgi
import argparse
import io

from .TTP import TableTypePattern


def parse_args():
    """ Parse command line arguments """
    parser = argparse.ArgumentParser(
        description='Validates a Table Type Pattern and produces an HTML document'
                    ' with the issues found'
        )

    parser.add_argument('ttp',
                        help='the Table Type Pattern')
    parser.add_argument('-o', '--output',
                        default="validator.html", help="the output file (default: validator.html)")
    parser.add_argument('-v', '--verbose', action="store_true",
                        help="print errors found to the console")
    parser.add_argument('-p', '--prettify', help="prettify the JSON output",
                        action="store_true")
    parser.add_argument('-e', '--evaluate-math', action="store_true",
                        help="evaluate maths expressions in values. "
                             "Warning: This can exhaust memory because python "
                             "has no integer size limits.")
    args = parser.parse_args()
    return args

def sort_issues(issues):
    """ Sort issues in-place into the order they appear in the source
    """
    issues.sort(key=lambda issue: issue[1])

def generate_issue_list(issues, source):
    """ Generates an HTML list of issues

        issues: A sorted list (from sort_issues) of TableTypePattern.issues
        source: The original source Table Type Pattern as a unicode string
        return: A string with the HTML in the format

        <li><a href="#offset" title="JSON source">Issue Description</li>
        ...

        see also: generate_listing, (href links into this listing)
    """
    ret = []
    for issue in issues:
        ret.append(u'<li><a href="#%s" title="%s">%s</a></li>'
                   % (issue[1], cgi.escape(source[issue[1]:issue[2]], True),
                      cgi.escape(issue[0])))
    return "\n".join(ret)


# HTML span for every newline
NEWLINE_SPAN = u'<span class="line"></span>'


def _escape_lines(string):
    """ Escapes and marks newlines """
    escaped = cgi.escape(string)
    escaped = escaped.replace(u"\n", u'\n' + NEWLINE_SPAN)
    return escaped


def generate_listing(issues, source):
    """ Generates the HTML listing of the JSON Table Type Pattern

        Suitable to put in preformatted (pre) tags.

        issues: A sorted list (from sort_issues) of TableTypePattern.issues
        source: The original source Table Type Pattern as a unicode string

        Each line has the format (the span is styled for line numbers):
        <span class="line"></span>   code here
        ...

        Issues are highlighted using spans across multiple lines and
        will finish and start midway through lines as appropriate:

        <span title="&bull; issue 1 &bull; issue 2 ..." id="offset",
         style="background: rgba(255, 0, 0, 0.x);">
         { json here }
        </span>

        see also: generate_issue_list
    """
    issues = list(issues)
    active = []  # A list of current issues on this source line
    offset = 0
    o_str = NEWLINE_SPAN

    while active or issues:
        if active:
            # Get the next issue to close
            min_active = min(active, key=lambda x: x[2])
            if not issues or min_active[2] <= issues[0][1]:
                o_str += _escape_lines(source[offset:min_active[2]])
                o_str += u'</span>'
                offset = min_active[2]
                while active and min_active[2] == offset:
                    active.remove(min_active)
                    if active:
                        min_active = min(active, key=lambda x: x[2])
            else:
                o_str += _escape_lines(source[offset:issues[0][1]])
                o_str += u'</span>'
                offset = issues[0][1]
                while issues and issues[0][1] == offset:
                    active.append(issues[0])
                    issues = issues[1:]
        else:
            o_str += _escape_lines(source[offset:issues[0][1]])
            offset = issues[0][1]
            while issues and issues[0][1] == offset:
                active.append(issues[0])
                issues = issues[1:]
        title = u""
        for issue in reversed(active):
            title += u"&bull;" + cgi.escape(issue[0], True) + "\n"
        if title:
            o_str += (u'<span title="%s" id="%s" style="background:'
                      u' rgba(255, 0, 0, 0.%s);">' %
                      (title, offset, min(len(active), 9)))

    o_str += _escape_lines(source[offset:])
    return o_str

def main():
    """ Generates an html report of a table type pattern's issues
    """

    args = parse_args()
    # Log to a string
    my_logger = logging.getLogger("null")
    my_logger.addHandler(logging.NullHandler())
    my_logger.setLevel(logging.WARNING)
    my_logger.propagate = 0

    for codec in [None, 'utf-8', 'utf-16', 'utf-32']:
        try:
            with io.open(args.ttp, encoding=codec) as src:
                source = src.read()
                break
        except UnicodeError:
            continue
    else:
        raise UnicodeError("Cannot decode the input TTP to unicode.")


    if args.prettify:
        parsed = json.loads(source)
        source = json.dumps(parsed, ensure_ascii=False, indent=4)

    ttp = TableTypePattern(source, logger=my_logger, track_orig=True,
                           as_unicode=True, allow_unsafe=args.evaluate_math)

    issues = ttp.issues

    sort_issues(issues)

    with open(args.output, 'w') as fout:
        fout.write(u"""<!DOCTYPE html>
    <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>TTP Validator</title>
            <style>
                body {
                    counter-reset: l_counter;
                }
                .line::before {
                        counter-increment: l_counter;
                        content: counter(l_counter);
                        display: inline-block;
                        border-right: 1px solid #ddd;
                        padding: 0 .5em;
                        margin-right: .5em;
                        min-width: 5ch;
                        color: #888;
                }
            </style>
        </head>
        <body style='background: white;'>
            <h1>TTP Validator</h1>
            <h2>Issues Detected (%d)</h2>
            <ol>
    """ % (len(issues),))
        # Output a list of errors found
        fout.write(generate_issue_list(issues, source))
        fout.write(u"""
            </ol>
            <h2>Annotated Table Type Pattern %s</h2>
            <pre>""" % (cgi.escape(args.ttp, False),))
        # Output the JSON listing
        fout.write(generate_listing(issues, source))

        fout.write(u"""
            </pre>
        </body>
    </html>
    """)

    print("Written to file:", args.output)

if __name__ == "__main__":
    main()
