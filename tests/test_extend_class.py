import unittest
from ttp_tools.ttp_util import allow_override, subclass, extend_class

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


class TestExtendClass(unittest.TestCase):

    def setUp(self):
        class base(object):
            req = None
            overwrite_me = "base_overwrite"

            def __init__(self, req):
                self.req = req

            def method(self, items):
                items.append("base:method")
                items.append(self)
                return items

            def method2(self):
                items = []
                items.append("base:method2")
                items.append(self)
                return items

            @staticmethod
            def static_m(items):
                items.append("base:static_m")
                return items

            @classmethod
            def class_m(cls, items):
                items.append("base:class_m")
                items.append(cls)
                return items
        self.base = base

    def test_base_works(self):
        r = 'test_base_works'
        i = self.base(r)
        # Test req on the class
        self.assertIs(self.base.req, None)
        # Test req on the instance
        self.assertEqual(i.req, r)
        # Test method
        self.assertListEqual(i.method([r]),
                             [r, "base:method", i])
        # Test static_m of the class
        self.assertListEqual(self.base.static_m([r]),
                             [r, "base:static_m"])
        # Test static_m of an instance
        self.assertListEqual(i.static_m([r]),
                             [r, "base:static_m"])
        # Test classmethod of the class
        self.assertListEqual(self.base.class_m([r]),
                             [r, "base:class_m", self.base])
        # Test classmethod of an instance
        self.assertListEqual(i.class_m([r]),
                             [r, "base:class_m", self.base])

    def test_add_new_attribute(self):
        self.assertFalse(hasattr(self.base, 'new_attr'))

        @extend_class
        class tmp(self.base):
            new_attr = 'new_value'

        i = self.base(None)
        # Check the class
        self.assertEqual(self.base.new_attr, 'new_value')
        # Check the instance
        self.assertEqual(i.new_attr, 'new_value')

    def test_extending_empty_class(self):
        @extend_class
        class tmp(self.base):
            pass
        # Check this returns tmp as self.base
        self.assertEqual(tmp, self.base)
        # Make sure nothing has changed
        self.test_base_works()

    def test_multiple_extensions(self):
        class other(object):
            pass

        @extend_class
        class tmp(self.base, other):
            new_attr = 'new_value'
        # Check this returns the first
        self.assertEqual(tmp, self.base)
        # Check new_attr has been added
        self.assertEqual(self.base.new_attr, 'new_value')
        self.assertEqual(other.new_attr, 'new_value')

    def test_fails_override_attribute(self):
        with self.assertRaises(TypeError):
            @extend_class
            class tmp(self.base):
                overwrite_me = 'I already exist and should fail'

        with self.assertRaises(TypeError):
            @extend_class
            class tmp2(self.base):
                def __init__(self, r):
                    self.r = r

    def test_override_list(self):
        # Note this still works in the case an override is
        # not required
        self.assertFalse(hasattr(self.base, 'new_attr'))
        self.assertEqual(self.base.overwrite_me, 'base_overwrite')

        @extend_class('new_attr', 'overwrite_me')
        class tmp(self.base):
            new_attr = 'new_value'
            overwrite_me = 'ex_overwrite'

        i = self.base(None)
        # Check the class
        self.assertEqual(self.base.new_attr, 'new_value')
        self.assertEqual(self.base.overwrite_me, 'ex_overwrite')
        # Check the instance
        self.assertEqual(i.new_attr, 'new_value')
        self.assertEqual(i.overwrite_me, 'ex_overwrite')

    def test_allow_override_decorator(self):
        # Note this still works in the case an override is
        # not required
        self.assertFalse(hasattr(self.base, 'new_attr'))
        self.assertEqual(self.base.overwrite_me, 'base_overwrite')

        @extend_class
        class tmp(self.base):
            new_attr = allow_override('new_value')
            overwrite_me = allow_override('ex_overwrite')

        i = self.base(None)
        # Check the class
        self.assertEqual(self.base.new_attr, 'new_value')
        self.assertEqual(self.base.overwrite_me, 'ex_overwrite')
        # Check the instance
        self.assertEqual(i.new_attr, 'new_value')
        self.assertEqual(i.overwrite_me, 'ex_overwrite')

        @extend_class
        class tmp2(self.base):
            @allow_override
            @staticmethod
            def overwrite_me():
                return 5
        self.assertEqual(self.base.overwrite_me(), 5)
        self.assertEqual(i.overwrite_me(), 5)

    def test_subclass_instance_method(self):
        # Here we check a second to ensure the func
        # has bound correctly and that method and method2
        # are not accidentally mapped to each only one
        r = 'test_subclass_instance_method'

        @extend_class
        class tmp(self.base):
            @subclass
            def method(base, self, items):
                items.append("ex:method")
                items.append(self)
                return base(self, items)

            @subclass
            def method2(base, self):
                items = []
                items.append("ex:method2")
                items.append(self)
                return items + base(self)

        i = self.base(None)
        # Test method
        self.assertListEqual(i.method([r]),
                             [r, "ex:method", i, "base:method", i])
        self.assertListEqual(i.method2(),
                             ["ex:method2", i, "base:method2", i])

    def test_subclass_static_method(self):
        r = 'test_subclass_static_method'

        @extend_class
        class tmp(self.base):
            @subclass
            @staticmethod
            def static_m(base, items):
                items.append("ex:static_m")
                return base(items)

        i = self.base(None)
        # Test static_m of the class
        self.assertListEqual(self.base.static_m([r]),
                             [r, "ex:static_m", "base:static_m"])
        # Test static_m of an instance
        self.assertListEqual(i.static_m([r]),
                             [r, "ex:static_m", "base:static_m"])

    def test_subclass_class_method(self):
        r = 'test_subclass_class_method'

        @extend_class
        class tmp(self.base):
            @subclass
            @classmethod
            def class_m(base, cls, items):
                items.append("ex:class_m")
                items.append(cls)
                return base(cls, items)

        i = self.base(None)
        self.assertEqual(self.base, tmp)
        # Test classmethod of the class
        self.assertListEqual(self.base.class_m([r]),
                             [r, "ex:class_m", tmp, "base:class_m", tmp])
        # Test classmethod of an instance
        self.assertListEqual(i.class_m([r]),
                             [r, "ex:class_m", tmp, "base:class_m", tmp])

    def test_allow_override_all_methods(self):
        r = 'test_override_all_methods'

        @extend_class
        class tmp(self.base):
            @allow_override
            def method(self, items):
                items.append("ex:method")
                items.append(self)
                return items

            @allow_override
            @staticmethod
            def static_m(items):
                items.append("ex:static_m")
                return items

            @allow_override
            @classmethod
            def class_m(cls, items):
                items.append("ex:class_m")
                items.append(cls)
                return items

        i = self.base(None)
        # Test method
        self.assertListEqual(i.method([r]),
                             [r, "ex:method", i])
        # Test static_m of the class
        self.assertListEqual(self.base.static_m([r]),
                             [r, "ex:static_m"])
        # Test static_m of an instance
        self.assertListEqual(i.static_m([r]),
                             [r, "ex:static_m"])
        # Test classmethod of the class
        self.assertListEqual(self.base.class_m([r]),
                             [r, "ex:class_m", self.base])
        # Test classmethod of an instance
        self.assertListEqual(i.class_m([r]),
                             [r, "ex:class_m", self.base])

    def test_override_list_all_methods(self):
        r = 'test_override_list_all_methods'

        @extend_class('method', 'static_m', 'class_m')
        class tmp(self.base):
            def method(self, items):
                items.append("ex:method")
                items.append(self)
                return items

            @staticmethod
            def static_m(items):
                items.append("ex:static_m")
                return items

            @classmethod
            def class_m(cls, items):
                items.append("ex:class_m")
                items.append(cls)
                return items

        i = self.base(None)
        # Test method
        self.assertListEqual(i.method([r]),
                             [r, "ex:method", i])
        # Test static_m of the class
        self.assertListEqual(self.base.static_m([r]),
                             [r, "ex:static_m"])
        # Test static_m of an instance
        self.assertListEqual(i.static_m([r]),
                             [r, "ex:static_m"])
        # Test classmethod of the class
        self.assertListEqual(self.base.class_m([r]),
                             [r, "ex:class_m", self.base])
        # Test classmethod of an instance
        self.assertListEqual(i.class_m([r]),
                             [r, "ex:class_m", self.base])

    def test_override_in_subclass(self):
        """ Check that setting a undefined method in a subclass works when it
            already exists in the base. Without have to ignore it!!
        """
        r = 'test_override_in_subclass'

        class RealSub(self.base):
            pass
        base_class = self.base

        @extend_class
        class tmp(RealSub):
            def method(self, items):
                items.append("sub:method")
                items.append(self)
                return base_class.method(self, items)

        i = RealSub(None)
        # Test method
        self.assertListEqual(i.method([r]),
                             [r, "sub:method", i, "base:method", i])


if __name__ == '__main__':
    unittest.main()
