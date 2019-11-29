"""
Some helpful methods used by TTP and users of it.

This includes extend_class, intended to be used as an decorator to merge
a class directly into its base class and the accompanying allow_override
and subclass attribute decorators.
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

import types
import functools
import ast
import json
import inspect
from six import string_types


class allow_override(tuple):
    """
    A decorator used with extend_class, this allows an attribute in the base
    class to be overwritten with this value if it exists, otherwise it is
    created. Because decorators cannot be used on attribute assignments
    the value can simply be wrapped in this.

    For example:
    @extend_class
    class B(A):
        @allow_override
        def existing_func(x):
            print x

        existing_attr = allow_override({"new": "value"})
    """
    def __new__(cls, a):
        return tuple.__new__(cls, (a,))


class subclass(tuple):
    """
    A decorator used with extend_class. This gives the existing version of the
    function as the first argument to the decorated function. This works with
    all types of methods (instancemethod, classmethod and staticmethod). This
    should be ordered above the method modifier decorator. When calling the
    base method this will be unbound as such pass in the instance (self)
    or class (cls) as needed, much like old style inheritance.

    For example:
    @extend_class
    class B(A):
        @subclass
        @classmethod
        def print(base, cls, *args, **kargs):
            # Pass unmodified arguments to the base method
            base(cls, *args, **kargs)

    """
    def __new__(cls, a):
        return tuple.__new__(cls, (a,))


def extend_class(*replace):
    """
    A decorator that merges the decorated class into the base classes directly.
    This is similar to a partial class, allowing classes to be split across
    files.

    If multiple base classes are specified this is applied to each, however
    only the first is returned.

    By default a TypeError will be raised if an existing method or variable
    is overridden. The allow_override or subclass decorators can be used to
    allow this override. Optionally a list of the names can be passed as
    strings to the extend_class decorator, these will be allowed.

    We also note that due to the way python classes are implemented this change
    will apply to all subclasses, as this seems to be computed at runtime.

    For example (also see the subclass and allow_override docs):
    @extend_class('overwrite_me')
    class B(A):
        overwrite_me = 1

        def func(self):
            pass
    """
    def do_extend(cls, replace):
        # Using __dict__ rather than vars and getattr, otherwise function
        # types are not set correctly
        for k, v in cls.__dict__.items():
            # Built in things we don't want to break
            if k in ('__module__', '__doc__'):
                continue
            for base in cls.__bases__:
                # Are we replacing the underlying?
                if isinstance(v, allow_override):
                    setattr(base, k, v[0])
                elif isinstance(v, subclass):
                    # Is it a normal function, it is not a (unbound) method yet
                    if isinstance(v[0], types.FunctionType):
                        func = functools.partial(v[0], base.__dict__[k])
                        # Wrap back as a standard function make it bind
                        # We have bind this in specially otherwise we
                        # get stuck with only using only the latest function
                        x = lambda f, *a, **b: lambda *a, **b: f(*a, **b)
                        setattr(base, k, x(func))
                    # It is a special type (static/class), we make it unspecial
                    # for the partial and special for the install
                    else:
                        klass = v[0].__class__
                        partial = klass(functools.partial(v[0].__func__,
                                        base.__dict__[k].__func__))
                        setattr(base, k, partial)
                elif k in base.__dict__ and k not in replace:
                    raise TypeError("%s will not replace %s" % (repr(base), k))
                else:
                    setattr(base, k, v)
        # Return the first base class
        return cls.__bases__[0]
    # Check if we have been given and return a function
    if len(replace) == 0 or isinstance(replace[0], string_types):
        return functools.partial(do_extend, replace=replace)
    assert len(replace) == 1
    return do_extend(replace[0], replace=tuple())


def expect_list(obj):
    """ Returns the given object within a list if it is not already """
    return obj if isinstance(obj, list) else [obj]


def safe_eval_maths(expr):
    """
    Safely evaluates a maths expression,
    such as (2**32-1) or (400|0x1000)
    Will throw a ValueError exception on error

    Note: This is still susceptible to memory or CPU exhaustion by putting
          in large numbers.
    """
    allowed = (ast.Expression, ast.BinOp, ast.UnaryOp, ast.operator,
               ast.unaryop, ast.Num)
    try:
        tree = ast.parse(expr, mode='eval')
        valid = all(isinstance(n, allowed) for n in ast.walk(tree))
        if valid:
            return eval(expr, {"__builtins__": None})
    except Exception as e:
        raise ValueError("Refusing to execute " + expr + str(e))



class _OffsetDict(dict):
    """ Used by _load_tracked_json stores the starting and ending character
        offset from the original source
    """
    char_start = None  # The starting char offset in the original JSON
    char_end = None  # The ending char offset in the original JSON


def _load_tracked_json(fp, use_loads=False):
    """
    Loads a json file and adds char_start and char_end attributes to returned
    objects (_OffsetDict)

    The returned _OffsetDict are subclasses of dict, but include the char_start
    and char_end relating to the character offset in the original json.

    Warning: This is very much tied to cPython and likely wont work and may
    crash in others.
    """
    class JSONOffsetDecoder(json.JSONDecoder):
        """ A decoder that forces python to use the software JSON implementation.
            We can then walk the stack and find line numbers
        """
        def __init__(self, *a, **b):
            super(JSONOffsetDecoder, self).__init__(*a, **b)
            self.scan_once = json.scanner.py_make_scanner(self)

    def hook(obj):
        assert isinstance(obj, dict)
        frame = inspect.currentframe()
        if frame:  # Might work but who knows?
            parents = inspect.getouterframes(frame, 2)
            parent_locals = parents[1][0].f_locals
            start = parent_locals['s_and_end'][1]
            end = parent_locals['end']
            obj = _OffsetDict(obj)
            # The start excludes the curly brace
            obj.char_start = max(0, start-1)
            obj.char_end = end
        return obj
    if use_loads:
        return json.loads(fp, cls=JSONOffsetDecoder, object_hook=hook)
    return json.load(fp, cls=JSONOffsetDecoder, object_hook=hook)
