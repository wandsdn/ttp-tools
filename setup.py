#!/usr/bin/env python
""" Installs the ttp_tools library """

from setuptools import setup

with open('README.md') as f:
    README = f.read()

with open('LICENSE') as f:
    LICENSE = f.read()

setup(
    name='ttp-tools',
    version='0.0.1',
    description='A python Table Type Pattern library and tools',
    long_description=README,
    author='Richard Sanger',
    author_email='rsanger@wand.net.nz',
    url='https://github.com/wandsdn/ttp-tools',
    license=LICENSE,
    packages=['ttp_tools'],
    install_requires=['ofequivalence', 'six'],
    entry_points={
        "console_scripts": [
            "view_ttp = ttp_tools.view_ttp:main",
            "validate_ttp = ttp_tools.validate_ttp:main"
            ]
        }
    )
