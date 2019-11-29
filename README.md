A python [Table Type Pattern](https://www.opennetworking.org/wp-content/uploads/2013/04/OpenFlow%20Table%20Type%20Patterns%20v1.0.pdf) library to load, validate and fit rules to Table Type Patterns.


### Installation

Install the C library requirements for [gmpy2](https://gmpy2.readthedocs.io/en/latest/) as required by [ofequivalence](https://github.com/wandsdn/ofequivalence). For Debian based distributions run:
```
apt install libgmp-dev libmpfr-dev libmpc-dev
```
Then use pip to install the python requirements. In the root directory (containing this readme) run:
```
pip install -r requirements.txt
```
Then use pip to install the ttp_tools library and tools (use the pip --user option to install for only the local user):
```
pip install .
```


#### Running tests
Unittest is used for the tests. In the root directory, where this readme
is located, the following command will run the tests:
```
python -m unittest discover -v
```

### Tools

This library ships two tools: view_ttp and validate_ttp.

#### View TTP

A command line tool for viewing a Table Type Pattern

```
$ view_ttp -h
usage: view_ttp [-h] [-q] ttp

Command line tool for traversing the hierarchy of a TTP.

positional arguments:
  ttp          A Table Type Pattern JSON description

optional arguments:
  -h, --help   show this help message and exit
  -q, --quiet  Disable printing errors from parsing the TTP
```

view_ttp presents the TTP a hierarchy, for example:

```
$ view_ttp -q tests/test_patterns/0-simple_working_example-utf8.json

Finished loading TEST_CASE v1.0.0

1) TTP Info
2) Security
3) Variables and Extension Identifiers
4) Tables
5) Groups
q) quit
Which one?
```


#### Validate TTP

Validates a Table Type Pattern and produces an HTML document with issues it found annotated.
For an online variant see [flask-ttp-validator](https://github.com/wandsdn/flask-ttp-validator).

```
$ validate_ttp -h
usage: validate_ttp [-h] [-o OUTPUT] [-v] [-p] [-e] ttp

Validates a Table Type Pattern and produces an HTML document with the issues
found

positional arguments:
  ttp                   the Table Type Pattern

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        the output file (default: validator.html)
  -v, --verbose         print errors found to the console
  -p, --prettify        prettify the JSON output
  -e, --evaluate-math   evaluate maths expressions in values. Warning: This
                        can exhaust memory because python has no integer size
                        limits.
```


### License

The code is licensed under the Apache License Version 2.0, see the included LICENSE file.
