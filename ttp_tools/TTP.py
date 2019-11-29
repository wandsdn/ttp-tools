"""
The main TTP parsing class, this will normalise a Table Type Pattern version 1
into classes. The structure of the TTP is retained throughout the classes.

The TTP spec is not entirely clear on the meaning of certain aspects as
such this has been written to load TTP's as found in the wild. This will
also handle a couple of non-standard fields found in TTPs. When loading
the TTP errors found are logged.

One such example is seen with the ofdpa 2.0 release's TTP, which uses
both support vs use meta-members in the same way. This is
because ofdpa is describing the entire pipeline, whereas a TTP was
intended to describe the required (and optional) components of a
pipeline for a specific application. This could be a subset, or even
remapping of the real hardware pipeline.


### How to extend and add your own code or functionality:
Rather than subclassing one should use the extend_class decorator in ttp_util.
This will directly update the classes in this file, and also the class
decorated.

Why?
Due to the hierarchical parsing of the TTP every class's __init__ function
explicitly creates the appropriate children classes. For example a TTPFlow
will create a TTPInstructionSet which may in turn create a TTPInstruction
then TTPActionList then TTPAction. One solution would be to pass this in as
a mapping dict, such that the subclass would be created. However this
does not solve the problem in the case of subclassed objects. For instance
TTPObject is the base to all other classes, subclassing this would not update
any of the existing subclasses.
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

import json
import io
import logging
import difflib
from collections import defaultdict

from six import viewitems, viewvalues, integer_types, string_types

from ofequivalence.openflow_desc import OpenFlow1_3_5
from .ttp_util import expect_list, safe_eval_maths, _load_tracked_json

logging.basicConfig(level=logging.INFO,)


MATCH_TYPES = ["exact",  # Match a single value, i.e. mask is all 1's
               "mask",  # Arbitrary bit masking allow, including an all 0 mask
                        # one would assume. Unless overridden by mask and value
               "prefix",  # Prefix matching only (including an all 0 mask)
               "all_or_exact"]  # Field can be omitted, or is exact

META_MEMBERS = ["all",
                "one_or_more",
                "zero_or_more",
                "exactly_one",
                "zero_or_one"]


# Map special names to fixed values
# This is to deal with silly ofdpa etc stuff
VALUE_OVERRIDE = {
    # For ofdpa-2.01-16-feb-2016.json
    "L3 PHP": 32,
    # "127.0.0.1" For ACL-IPv4-v1.0.0.ttp
    "<Router_IP>": 0x7f000001,
    # For sample unicast mac to reach L3 routing
    "<Router_MAC_DA>": 0xf00000000001,
    }


class TTPRange(object):
    """ A class representing an inclusive range in TTP """
    min_ = None  # The lower bound
    max_ = None  # The upper bound

    def __init__(self, min_, max_):
        self.min_ = min_
        self.max_ = max_

    def contains(self, num):
        return self.min_ <= num <= self.max_

    def __contains__(self, num):
        return self.min_ <= num <= self.max_

    def __str__(self):
        return str(self.min_) + ".." + str(self.max_)


class TTPIssueCollector(logging.Filter):
    """ A log filter class used to intercept TTP error messages.
        These are stored as a list against ttp.issues if track input
        is enabled.
    """
    def __init__(self, ttp, *args, **kargs):
        self.ttp = ttp
        self.ttp.issues = []
        logging.Filter.__init__(self, *args, **kargs)

    def filter(self, record):
        if hasattr(record, 'char_start'):
            self.ttp.issues.append((record.getMessage(), record.char_start,
                                    record.char_end))
        return True


class TTPObject(object):
    """
    A generic TTP base object, providing common functionality which all other
    classes inherit from. This including the attributes 'name', 'doc' and
    'opt_tag' which are defined in the spec to be valid for all objects in the
    TTP.

    We also include a reference back to the base TableTypePattern, the original
    input and our parent and some methods for traversing the TTP.
    """
    #: The original input JSON objects
    input_ = None
    #: Our parent TTPObject, or None in the base this is the base
    #: TableTypePattern
    parent = None
    #: The base TableTypePattern object
    ttp = None
    #: The logger for the TableTypePattern
    log = None
    #: TTP,Opt,Str - Documentation, normalised to a string separated by
    #: or None if not found.
    doc = None
    #: TTP,Opt,Str - Name or None if not found
    name = None
    # TTP,Opt,Str - Opt_tag a string or None, it is given a name of the
    # optional functionality. And is used to link an optional feature, I.e.
    # we need match x and group x to do feature x. This is equivalent to a
    # zero_or_more support request
    opt_tag = None

    def read_value(self, attr, opt=False, default=None):
        """ reads in a value of any type and logs if not found """
        value = None
        if isinstance(self.input_, dict):
            value = self.input_.get(attr, None)
        if value is None:
            if not opt:
                self.log.warning("Required attribute %s not found in %s - %s",
                                 attr, self.__class__.__name__, self.input_)
            return default
        return value

    def read_string(self, attr, opt=False, default=None):
        """ Expects a string, and logs if a string is not found """
        value = self.read_value(attr, opt, default=None)
        if value is None:
            return default
        if isinstance(value, string_types):
            return value
        self.log.warning("String expected for %s but found a %s instead"
                         " in %s", attr, value.__class__.__name__,
                         self.input_)
        try:
            return str(value)
        except ValueError:
            return default

    def read_integer(self, attr, opt=False, default=None, min_=None,
                     max_=None):
        """ Reads in an integer value, min_ and max_ are inclusive
            JSON is quite restrictive in only allowing decimal, so we don't
            error on strings unless they don't represent an integer at all.
        """
        value = self.read_value(attr, opt, default=None)
        if value is None:
            return default
        if not isinstance(value, integer_types):
            try:
                value = int(value, 0)
            except (TypeError, ValueError):
                self.log.warning("Integer expected for %s but found %s"
                                 " instead in %s", attr,
                                 value, self.input_)
                return default
        if isinstance(value, integer_types):
            if min_ is not None and value < min_:
                self.log.warning("Attribute %s value smaller than the minimum"
                                 " allowed (%s < %s)", attr, value, min_)
                return default
            if max_ is not None and value > max_:
                self.log.warning("Attribute %s value larger than the maximum"
                                 " allowed (%s > %s)", attr, value, max_)
                return default
            return value
        # We don't expect to get here
        return default

    def read_string_stripped(self, attr, opt=False, default=None):
        """ Loads a string and strips the output, logs an error if stripped """
        ret = self.read_string(attr, opt, default)
        if ret is not None:
            orig_len = len(ret)
            ret = ret.strip()
            if orig_len != len(ret):
                self.log.warning("Attribute %s's value contained leading or "
                                 "trailing whitespace '%s'.", attr, ret)
        return ret

    def read_range(self, attr, opt=False, default=None, min_=None, max_=None):
        """ Read a ttp range "a...b" where both a and b are integers.
            Returns a TTPRange or the default value.
            min and max_ are inclusive, as is the resulting range.
        """
        value = self.read_string(attr, opt=opt, default=None)

        if value is not None:
            try:
                split = value.split("..")
                range_min = None
                range_max = None

                # Validate the minimum
                try:
                    range_min = int(split[0], 0)
                except ValueError:
                    pass
                if range_min is None and self.ttp.allow_unsafe:
                    try:
                        range_min = safe_eval_maths(split[0])
                        self.log.error("An expression should not be used in a"
                                       " range replace %s with %s", split[0],
                                       hex(range_min))
                    except ValueError:
                        pass
                if range_min is None:
                    self.log.error("Invalid non-numeric value %s in range"
                                   " %s", split[0], value)
                    return default
                if min_ is not None and range_min < min_:
                    self.log.warning("Minimum range %s value smaller than"
                                     " the minimum allowed (%s < %s)", value,
                                     range_min, min_)
                    return default

                # Validate the maximum
                try:
                    range_max = int(split[1], 0)
                except ValueError:
                    pass
                if range_max is None and self.ttp.allow_unsafe:
                    try:
                        range_max = safe_eval_maths(split[1])
                        self.log.error("An expression should not be used in a"
                                       " range replace %s with %s", split[1],
                                       hex(range_max))
                    except ValueError:
                        pass
                if range_max is None:
                    self.log.error("Invalid non-numeric value %s in range"
                                   " %s", split[1], value)
                    return default
                if max_ is not None and range_max > max_:
                    self.log.warning("Maximum range %s value larger than"
                                     " the maximum allowed (%s > %s)", value,
                                     range_max, max_)
                    return default
                if range_max < range_min:
                    self.log.warning("Invalid range, minimum (%s) is larger"
                                     "than the maximum (%s)", hex(range_min),
                                     hex(range_max))
                    return default

                return TTPRange(range_min, range_max)
            except IndexError:
                self.log.error("Attribute %s is expected to be a range in"
                               " the format min..max but found %s"
                               " instead.", attr, value)
                return default
        else:
            return default

    def read_range_or_integer(self, attr, opt=False, default=None, min_=None,
                              max_=None):
        """ Reads in either a range or integer - see those docs """
        value = self.read_value(attr, opt=opt, default=None)
        if value is None:
            return default
        if isinstance(value, string_types) and ".." in value:
            return self.read_range(attr, opt=opt, default=default, min_=min_,
                                   max_=max_)
        return self.read_integer(attr, opt=opt, default=default, min_=min_,
                                 max_=max_)

    def __init__(self, input_, parent):
        self.input_ = input_
        self.parent = parent
        if isinstance(self, TableTypePattern):
            self.ttp = self
            if hasattr(self.input_, "char_start"):
                formatter = logging.Formatter("%(asctime)s - %(levelname)s -"
                                              " %(message)s - %(char_start)s"
                                              ":%(char_end)s")
                if self.log.handlers:
                    self.log.handlers[0].setFormatter(formatter)
                log_filter = TTPIssueCollector(self.ttp)
                self.log.addFilter(log_filter)
                self.log = logging.LoggerAdapter(
                    self.log, {"char_start": self.input_.char_start,
                               "char_end": self.input_.char_end})
        else:
            self.ttp = parent.ttp
            self.log = self.parent.log
            # Do we have line numbers?
            if hasattr(self.input_, "char_start"):
                # Our parents logger will be of this type
                self.log = logging.LoggerAdapter(
                    self.parent.log.logger,
                    {"char_start": self.input_.char_start,
                     "char_end": self.input_.char_end})

        if "doc" in input_:
            if isinstance(input_["doc"], list):
                self.doc = " ".join(input_["doc"])
            else:
                self.doc = self.read_string("doc", True, None)
        self.name = self.read_string("name", True, None)
        self.opt_tag = self.read_string("opt_tag", True, None)
        if self.opt_tag is not None:
            self.ttp.add_opt_tagged(self)

        if isinstance(parent, (TTPObject, type(None))):
            self.parent = parent
        else:
            assert "Bad parent type" == 0

    def walk_parents(self, class_):
        """ Walk the parents of a TTP object looking for a parent type
        """
        parent = self
        while parent is not None:
            if isinstance(parent, class_):
                return parent
            parent = parent.parent
        return None

    def collect_children(self, class_=None):
        """ Walk all children and collect them into a flat generator """
        if class_ is None:
            class_ = TTPObject
        if isinstance(self, class_):
            yield self

    def __str__(self):
        """ Subclasses are expected to override this """
        raise NotImplementedError("Subclasses should override __str__")

    def __repr__(self):
        """ Returns the original object which made this object """
        return str(self.input_)

    def __getstate__(self):
        """ Remove the unpicklable log element """
        ret = self.__dict__.copy()
        try:
            del ret['log']
        except KeyError:
            pass
        return ret


class TTPList(TTPObject, list):
    meta_type = None

    def __init__(self, input_, parent, item_class=None,
                 meta_type=None, filter_=None, **extras):
        TTPObject.__init__(self, input_=input_, parent=parent)
        list.__init__(self)

        # We shell do the processing for this
        if item_class is not None:
            self.meta_type = meta_type
            input_ = expect_list(input_)

            # Flatten the case that a single meta label is the first item
            if (meta_type in ('all', 'exactly_one', 'one_or_more') and
                    len(input_) == 1 and self._is_meta(input_[0])):
                self.meta_type = check_meta(input_[0])
                input_ = input_[0][self.meta_type]
                input_ = expect_list(input_)

            for item in input_:
                if filter_ is not None and filter_(item):
                    continue
                if isinstance(item, list):
                    self.append(self.__class__(input_=item, parent=self,
                                               **extras))
                elif self._is_meta(item):
                    meta = check_meta(item)
                    self.append(self.__class__(input_=item[meta], parent=self,
                                               meta_type=meta, **extras))
                else:
                    self.append(item_class(input_=item, parent=self, **extras))

    @staticmethod
    def _is_meta(item):
        if len(item) == 1:
            if next(iter(item)) in META_MEMBERS:
                return True
        return False

    def __str__(self):
        ret = ",".join([str(x) for x in self])
        if self.meta_type == "all":
            return '(' + ret + ')'
        return self.meta_type + '(' + ret + ')'

    def get_flat(self):
        """ Returns a generator of a flattened version of a list.
            Use if you don't care about the meta_type
        """
        for item in self:
            if isinstance(item, TTPList):
                for i in item.get_flat():
                    yield i
            else:
                yield item

    def collect_children(self, class_=TTPObject):
        """ Walk all children and collect them into a flat generator """
        for child in TTPObject.collect_children(self, class_):
            yield child
        for child in self:
            for i in child.collect_children(class_):
                yield i


def normalise_value(value, ttp_object=None):
    """ Normalise a value to a int representation.

    If interpretation is not possible throws a ValueError.

    Returns None when the result cannot be represented as a single
    integer, for example a range of values.
    """
    if value in VALUE_OVERRIDE:
        return int(VALUE_OVERRIDE[value])
    if isinstance(value, string_types):
        if value.startswith('<'):
            if ttp_object is None:
                return None
            if value in ttp_object.ttp.identifiers.variables:
                var = ttp_object.ttp.identifiers.variables[value]
                ttp_object.log.debug("Value uses variable %s with range:%s",
                                     value, var.range_)
            else:
                ttp_object.log.warning("Unspecified variable %s used, this"
                                       " should be in the variable table",
                                       value)
            return None
        parts = None
        # Check for IPv6 before MAC
        # The smallest IPv6 is '::'
        num_parts = len(value.split(':'))
        if (num_parts == 8 or
                (9 >= num_parts >= 3 and "::" in value)):
            expanded = value.replace('::', ':' * (10-num_parts))
            parts = expanded.split(':')
            assert len(parts) == 8
            res = 0
            shift = 112
            for part in parts:
                part = "0" if part == "" else part
                if int(part, 16) > 0xFFFF:
                    raise ValueError("Invalid IPv6 address " + value)
                res |= int(part, 16) << shift
                shift -= 16
            return res
        # IPv4
        if len(value.split('.')) == 4:
            parts = value.split('.')
            if (int(parts[0]) | int(parts[1]) |
                    int(parts[2]) | int(parts[3])) > 0xFF:
                raise ValueError("Invalid IPv4 address " + value)
            return (int(parts[0]) << 24 | int(parts[1]) << 16 |
                    int(parts[2]) << 8 | int(parts[3]))
        # Check for mac addresses
        if len(value.split(':')) == 6:
            parts = value.split(':')
        elif len(value.split('-')) == 6:
            parts = value.split('-')
        if parts:
            return int("".join(parts), 16)
        if (ttp_object and
                ttp_object.ttp.OF.value_from_OFP(value) is not None):
            return ttp_object.ttp.OF.value_from_OFP(value)
        return int(value, 0)
    return int(value)


def check_meta(obj):
    """ Check if an object is a meta, if so returns the meta type """
    assert len(obj) == 1
    for type_ in META_MEMBERS:
        if type_ in obj:
            return type_
    assert "Unknown Data" == 0


class TTPAction(TTPObject):
    action = None
    port_values = {"IN_PORT": 0xfffffff8,
                   "TABLE": 0xfffffff9,
                   "NORMAL": 0xfffffffa,
                   "FLOOD": 0xfffffffb,
                   "ALL": 0xfffffffc,
                   "CONTROLLER": 0xfffffffd,
                   "LOCAL": 0xfffffffe
                   }
    rport_values = dict(zip(port_values.values(), port_values))

    """
    field = None  # If action="SET_FIELD"
    value = None  # If action="SET_FIELD" Is this required by the spec?
    port = None  # If action="OUTPUT"
    ttl = None  # If action="SET_MPLS_TTL" or "SET_NW_TTL"
    ethertype = None  # If action="PUSH_VLAN" or "PUSH/POP_MPLS" or "PUSH_PBB"
    queue_id = None # If action="SET_QUEUE"
    group_id = None # If action="GROUP"
    """

    def __init__(self, input_, parent):
        TTPObject.__init__(self, input_=input_, parent=parent)
        self.action = input_['action']

        if self.action == "OUTPUT":
            self.port = input_.get('port', None)
            if self.port in self.port_values:
                self.port = self.port_values[self.port]
        elif self.action == "COPY_TTL_OUT":
            pass
        elif self.action == "COPY_TTL_IN":
            pass
        elif self.action == "SET_MPLS_TTL":
            self.ttl = input_.get('ttl', None)
        elif self.action == "DEC_MPLS_TTL":
            pass
        elif self.action == "PUSH_VLAN":
            self.ethertype = input_.get("ethertype", None)
        elif self.action == "POP_VLAN":
            pass
        elif self.action == "PUSH_MPLS":
            self.ethertype = input_.get("ethertype", None)
        elif self.action == "POP_MPLS":
            self.ethertype = input_.get("ethertype", None)
        elif self.action == "SET_QUEUE":
            self.queue_id = input_.get("queue_id", None)
        elif self.action == "GROUP":
            self.group_id = self.read_string("group_id", opt=True)
            if self.group_id:
                try:
                    self.ttp.find_group(self.group_id)
                except LookupError:
                    maybes = difflib.get_close_matches(
                        self.group_id, self.ttp.groups_by_name)
                    maybes = " or ".join(maybes)
                    if maybes:
                        self.log.critical("Invalid group reference %s not"
                                          " found! Did you mean: %s?",
                                          self.group_id, maybes)
                    else:
                        self.log.critical("Invalid group reference %s not"
                                          " found!", self.group_id)
        elif self.action == "SET_NW_TTL":
            self.ttl = input_.get('ttl', None)
        elif self.action == "DEC_NW_TTL":
            pass
        elif self.action == "SET_FIELD":
            if "field" in input_:
                self.field = input_["field"]
            elif "type" in input_:
                self.log.warning("Incorrect use of 'type' instead of 'field'"
                                 " within a SET_FIELD action")
                self.field = input_["type"]
            else:
                self.log.critical("SET_FIELD does not have a field set")

            self.value = input_.get("value", None)
            if not self.field.startswith("$"):
                # Check this is a defined OF type
                self.ttp.OF.check_oxm_name(self.field, self.log)
            else:
                # Check this has been defined in variables
                self.ttp.identifiers.check_identifier(self.field, "field",
                                                      self.log)

        elif self.action == "PUSH_PBB":
            self.ethertype = input_.get("ethertype", None)
        elif self.action == "POP_PBB":
            pass
        else:
            # Check that this exists in the defined list
            if self.action.startswith("$"):
                self.ttp.identifiers.check_identifier(self.action, "action",
                                                      self.log)
            else:
                self.log.warning("Unspecified action id: %s", self.action)
                self.log.warning("Experimenter types should be prefixed"
                                 " with '$'")

    def __str__(self):
        if self.action == "SET_FIELD":
            return self.field + "=" + str(self.value)
        if self.action == "GROUP":
            return self.action + "=" + str(self.group_id)
        if self.action == "OUTPUT" and self.port:
            if self.port in self.rport_values:
                return self.action + "=" + self.rport_values[self.port]
            return self.action + "=" + str(self.port)
        return self.action


class TTPActionList(TTPList):

    def __init__(self, input_, parent, meta_type="all"):
        TTPList.__init__(self, input_=input_, parent=parent,
                         item_class=TTPAction, meta_type=meta_type)

    def __str__(self):
        strs = []
        for action in self:
            strs.append(str(action))
        return self.meta_type + '(' + ','.join(strs) + ')'


class TTPFeatureList(TTPList):
    """ List of required OpenFlow features.
    """
    def __init__(self, input_, parent, meta_type="all"):
        TTPList.__init__(self, input_=input_, parent=parent,
                         item_class=TTPFeature, meta_type=meta_type)

    def __str__(self):
        strs = []
        for action in self:
            strs.append(str(action))
        return self.meta_type + '(' + ','.join(strs) + ')'


class TTPFeature(TTPObject):
    feature = None
    #  doc from TTPObject

    def __init__(self, input_, parent):
        TTPObject.__init__(self, input_=input_, parent=parent)
        self.feature = self.read_string_stripped('feature')

    def __str__(self):
        return str(self.feature) + " [" + str(self.doc) + "]"


class TTPBucket(TTPObject):
    name = None
    action_set = None

    def __init__(self, input_, parent):
        TTPObject.__init__(self, input_=input_, parent=parent)
        self.name = input_['name']
        if 'action_set' in input_:
            self.action_set = TTPActionList(input_['action_set'], self)
        elif 'action_list' in input_:
            self.log.warning("Incorrect usage of action_list instead of"
                             " action_set")
            self.action_set = TTPActionList(input_['action_list'], self)
        else:
            self.log.critical("Could not find an action_set within this"
                              " bucket")

    def __str__(self):
        return self.name + str(self.action_set)

    def collect_children(self, class_=TTPObject):
        """ Walk all children and collect them into a flat generator """
        for child in TTPObject.collect_children(self, class_):
            yield child

        for child in self.action_set.collect_children(class_):
            yield child


class TTPBucketList(TTPList):

    def __init__(self, input_, parent, meta_type="all"):
        # I'm not sure if meta_type 'all' makes sense here
        TTPList.__init__(self, input_=input_, parent=parent,
                         item_class=TTPBucket, meta_type=meta_type)


class TTPGroup(TTPObject):
    name = None
    group_type = None
    bucket_types = None

    def __init__(self, input_, parent):
        TTPObject.__init__(self, input_=input_, parent=parent)
        self.name = input_['name']
        self.group_type = input_['group_type']
        meta_type = "all"
        if self.group_type == "INDIRECT":
            meta_type = "exactly_one"
        self.bucket_types = TTPBucketList(input_=input_['bucket_types'],
                                          parent=self, meta_type=meta_type)

    def __str__(self):
        return ("Group:" + self.name + " - Type:" + self.group_type +
                "\nBuckets:" + str(self.bucket_types))

    def collect_children(self, class_=TTPObject):
        """ Walk all children and collect them into a flat generator """
        for child in TTPObject.collect_children(self, class_):
            yield child

        for child in self.bucket_types.collect_children(class_):
            yield child


class TTPInstruction(TTPObject):
    instruction = None
    actions = None

    def __init__(self, input_, parent):
        TTPObject.__init__(self, input_=input_, parent=parent)
        self.instruction = input_['instruction']

        if self.instruction == "GOTO_TABLE":
            that_table = self.read_string('table', opt=True)
            if that_table is not None:
                this_table = self.walk_parents(TTPTable)
                flow = self.walk_parents(TTPFlow)
                this_table.link_to(that_table, flow)
                self.table = that_table
                # This is done during init and as such the full link is delayed
                # until all tables are processed see TableTypePattern.__init__()
        elif self.instruction in ("APPLY_ACTIONS", "WRITE_ACTIONS"):
            self.actions = TTPActionList(input_['actions'], self)
        # TODO METER

    def __str__(self):
        # Instructions defined by the spec are METER, APPLY_ACTIONS,
        # CLEAR_ACTIONS, WRITE_ACTIONS, WRITE_METADATA, GOTO_TABLE
        # executed in that order
        if self.instruction == "GOTO_TABLE":
            return "GOTO_TABLE: " + self.input_["table"]
        if self.instruction == "WRITE_ACTIONS":
            return "WRITE_ACTIONS: " + str(self.actions)
        if self.instruction == "APPLY_ACTIONS":
            return "APPLY_ACTIONS: " + str(self.actions)
        return self.instruction

    def collect_children(self, class_=TTPObject):
        """ Walk all children and collect them into a flat generator """
        for child in TTPObject.collect_children(self, class_):
            yield child
        if self.actions:
            for child in self.actions.collect_children(class_):
                yield child


class TTPTable(TTPObject):
    name = None
    number = None
    flow_mod_types = None
    built_in_flow_mods = None
    tos = None  # Can goto a dict of tables linked to flows
    froms = None  # Can goto a dict of tables linked to flows
    cache_reachable = None

    def _flatten_metaflows(self, flows):
        tmp = []
        for flow in flows:
            if 'name' in flow:
                tmp.append(flow)
            else:
                for key, value in viewitems(flow):
                    if key not in META_MEMBERS:
                        TTPObject(flow, self).log.error(
                            "Ignoring flow without name: %s", str(flow))
                        break
                    else:
                        tmp += self._flatten_metaflows(expect_list(value))
        return tmp

    def __init__(self, input_, number, parent):
        TTPObject.__init__(self, input_=input_, parent=parent)
        self.number = number
        self.name = input_['name']
        self.tos = defaultdict(list)
        self.froms = defaultdict(list)

        self.flow_mod_types = []
        if 'flow_mod_types' in input_:
            for flow in self._flatten_metaflows(input_['flow_mod_types']):
                self.flow_mod_types.append(TTPFlow(flow, self))

        self.built_in_flow_mods = []
        if 'built_in_flow_mods' in input_:
            for flow in input_['built_in_flow_mods']:
                self.built_in_flow_mods.append(TTPFlow(flow, self,
                                                       built_in=True))

        if 'builtin_flow_mods' in input_:
            self.log.warning("Misspelt builtin_flow_mods should be"
                             " built_in_flow_mods")
            for flow in input_['builtin_flow_mods']:
                self.built_in_flow_mods.append(TTPFlow(flow, self,
                                                       built_in=True))

    def link_from(self, table, flow):
        self.froms[table].append(flow)
        self.cache_reachable = None

    def link_to(self, table, flow):
        self.tos[table].append(flow)
        self.cache_reachable = None

    def get_reachable(self):
        ret = []
        if self.cache_reachable is not None:
            return list(self.cache_reachable)
        if self.number == 0:
            return [(0,)]
        for table in self.froms:
            paths = table.get_reachable()
            for path in paths:
                ret.append(path + (self.number,))
        self.cache_reachable = list(ret)
        return ret

    def find_flow_mod(self, flow_mod):
        if isinstance(flow_mod, TTPFlow):
            return flow_mod
        return [x for x in self.flow_mod_types if x.name == flow_mod][0]

    def collect_children(self, class_=TTPObject):
        """ Walk all children and collect them into a flat generator """
        for child in TTPObject.collect_children(self, class_):
            yield child
        # These are both lists, we should really make these TTPLists
        # so we can include meta info even if we just flatten it out
        for child in self.built_in_flow_mods:
            for i in child.collect_children(class_):
                yield i
        for child in self.flow_mod_types:
            for i in child.collect_children(class_):
                yield i


class TTPInstructionSet(TTPList):
    """ A list of matches along with a meta_type.
        By default the meta_type is 'all', these
        are nested to store matches with meta_type requirements
    """

    def __init__(self, input_, parent, meta_type="all"):
        TTPList.__init__(self, input_=input_, parent=parent,
                         item_class=TTPInstruction, meta_type=meta_type)

    def __str__(self):
        strs = []
        for instruction in self:
            strs.append(str(instruction))
        if self.meta_type != "all":
            return self.meta_type + '(' + '\n'.join(strs) + ')'
        return '\n'.join(strs)


class TTPMatchSet(TTPList):
    """ A list of matches along with a meta_type.
        By default the meta_type is 'all', these
        are nested to store matches with meta_type requirements
    """

    def __init__(self, input_, parent, meta_type="all", built_in=False):
        err_type = None
        if built_in and meta_type != 'all':
            err_type = meta_type
            meta_type = 'all'
        TTPList.__init__(self, input_=input_, parent=parent,
                         meta_type=meta_type, item_class=TTPMatch,
                         filter_=None, built_in=built_in)
        if err_type is not None:
            self.log.error("Expecting an all meta type in a builtin flow"
                           " match, but found %s", meta_type)
        if built_in:
            for match in self:
                if not isinstance(match, TTPMatch):
                    self.log.warning("Meta lists within a builtin match don't"
                                     " make sense.")

    def __str__(self):
        recr_str = ",".join([str(x) for x in self])
        return self.meta_type + '(' + recr_str + ')'


class TTPFlow(TTPObject):
    priority = None  # The priority as an integer or range
    priority_rank = None  # The priority rank as an integer
    built_in = None

    def __init__(self, input_, parent, built_in=False):
        TTPObject.__init__(self, input_=input_, parent=parent)
        self.built_in = built_in
        self.name = self.read_string_stripped('name')

        # Per spec the min value for priority does not include 0,
        # but it really should to allow default flow rules!!
        if built_in:
            self.priority = self.read_integer("priority", min_=0)
        else:
            self.priority = self.read_range_or_integer("priority", opt=True,
                                                       min_=0)
        # Priority rank is an "integer greater than 0"
        self.priority_rank = self.read_integer("priority_rank", opt=True,
                                               min_=1)
        if "match_set" in input_:
            self.match_set = TTPMatchSet(input_["match_set"], self,
                                         built_in=built_in)
        else:
            self.match_set = TTPMatchSet([], self, built_in=built_in)
        self.instruction_set = TTPInstructionSet(input_["instruction_set"],
                                                 self)

    def print_flow(self, nesting=None):
        n = ''
        if nesting is not None:
            n = nesting
        nn = n + '\t'
        nnn = n + '\t\t'
        if self.built_in:
            print(n + (('%-10s' % self.name)[0:10] + ' ' +
                       'priority=' + str(self.priority) + ' ' +
                       str(self.match_set) + ' ' +
                       str(self.instruction_set)
                       .replace("\n", ",").replace("\t", "")))
            return
        print(n + self.name)
        if self.doc:
            print(nn + "Doc: " + str(self.doc))
        print(nn + "Priority: " + str(self.priority))
        print(nn + "Matches: " + str(self.match_set))
        print(nn + "Instructions:")
        print(nnn + str(self.instruction_set).replace('\n', '\n' + nnn))

    def __str__(self):
        if self.built_in:
            ret = "DefaultFlow("
        else:
            ret = "Flow("
        ret += (('%-10s' % self.name)[0:10] + ' priority=' +
                str(self.priority) + ' ' + str(self.match_set) +
                ' ' + str(self.instruction_set) + ')')
        return ret

    def collect_children(self, class_=TTPObject):
        """ Walk all children and collect them into a flat generator """
        for child in TTPObject.collect_children(self, class_):
            yield child
        for child in self.match_set.collect_children(class_):
            yield child
        for child in self.instruction_set.collect_children(class_):
            yield child


class TTPMatch(TTPObject):
    field_name = None
    const_mask = None
    const_value = None
    value = None
    mask = None
    match_type = MATCH_TYPES[0]
    optional_mask = 0
    required_mask = 0
    built_in = None
    width_mask = -1  # Unknown - -1 is infinitely wide

    def __init__(self, input_, parent, built_in=False):
        TTPObject.__init__(self, input_=input_, parent=parent)
        self.built_in = built_in
        # Check field

        self.field_name = self.read_string_stripped('field')

        # Generate width mask
        if (self.field_name in self.ttp.OF.oxm_fields and
                self.ttp.OF.oxm_fields[self.field_name][self.ttp.OF.INDEX_BITS]
                is not None):
            self.width_mask = (1 << (self.ttp.OF.oxm_fields
                               [self.field_name][self.ttp.OF.INDEX_BITS])) - 1

        # Check match type
        self.match_type = self.read_string_stripped('match_type', True,
                                                    MATCH_TYPES[0])
        if self.match_type not in MATCH_TYPES:
            self.log.warning("Invalid match type '%s', using default '%s'",
                             self.match_type, MATCH_TYPES[0])
            self.match_type = MATCH_TYPES[0]
        # Check for constant bits
        if 'const_value' in input_ or 'const_mask' in input_:
            if not('const_mask' in input_ and 'const_value' in input_):
                self.log.error("Both const_mask and const_value are required")
            else:
                try:
                    self.const_mask = normalise_value(input_['const_mask'],
                                                      self)
                except ValueError:
                    self.log.error("Unable to interpret value %s",
                                   input_['const_mask'])
                try:
                    self.const_value = normalise_value(input_['const_value'],
                                                       self)
                except ValueError:
                    self.log.error("Unable to interpret value %s",
                                   input_['const_mask'])
                if self.const_mask is not None:
                    self.const_mask &= self.width_mask
                if self.const_value is not None:
                    self.const_value &= self.width_mask
        # Check for required value
        if 'value' in input_:
            if isinstance(input_['value'], string_types):
                input_['value'] = self.read_string_stripped('value')
            # The TTP and Broadcom way of trying to ask for VLANS
            if input_['value'] in ('OFPVID_PRESENT', '<vid>|0x1000'):
                self.const_mask = 0x1000
                self.const_value = 0x1000
                self.log.error("Use a const_mask and const_value of 0x1000 to"
                               " indicate a VLAN is required. Rather than a"
                               " value of %s", input_['value'])
            else:
                try:
                    self.value = normalise_value(input_['value'], self)
                except ValueError:
                    self.log.error("Unable to interpret value %s",
                                   input_['value'])
                if self.value is not None:
                    self.value &= self.width_mask

        # Check for a required mask
        if 'mask' in input_:
            try:
                self.mask = normalise_value(input_['mask'], self)
                if self.mask is not None:
                    self.mask &= self.width_mask
            except ValueError:
                self.log.error("Unable to parse a mask with value %s",
                               input_['mask'])

            if (self.match_type in ('exact', 'all_or_exact') and
                    ((self.const_mask | self.mask) != self.width_mask if
                     self.const_mask is not None else self.mask != self.width_mask)):
                self.log.error("Unexpected mask in an %s match - %s",
                               self.match_type, self.input_)
                # Promote to a mask
                self.match_type = 'mask'

        self._make_masks()

        if (self.mask is None and self.value is not None and
                self.match_type in ('mask', 'prefix')):
            self.log.warning("Match has a fixed value, but no mask and can"
                             " be left out: %s", str(self))

        if self.built_in:
            # The value must be set
            if self.value is None and input_['value'] == "OFPVID_PRESENT":
                self.value = 0x1000

            if self.value is None:
                if 'value' in self.input_:
                    self.log.error("Cannot interpret value %s in "
                                   "built-in flow", self.input_['value'])
                else:
                    self.log.error("Built-in flow is missing a value")

    def is_standard_field(self):
        """ Returns true if field is in standard OpenFlow
            otherwise false for extensions
        """
        return not self.field_name.startswith('$')

    def __str__(self):
        value = ''
        mask = ''
        require = ''
        if self.match_type in ('exact', 'all_or_exact'):
            require += '!'
        if self.match_type in ('prefix',):
            require += '@'
        if not self.is_required():
            require += '*'
        if self.value is not None:
            value = '=' + hex(self.value)
        if self.mask is not None:
            mask = '/' + hex(self.mask)
        return self.field_name + require + value + mask

    def is_required(self):
        """ Returns True if the field is required in the match, otherwise False.
        """
        # Check to see if the value is required, otherwise skipping it is OK
        if self.match_type == 'exact':
            return True
        if self.match_type == 'all_or_exact':
            # Here lets assume that if exact it must meet requirements below
            # otherwise is it can be excluded
            return False
        # Either None or 0 can be ignored
        if self.const_mask:
            return True
        # From my understanding a mask means, you have to set the mask to this
        # If a const_mask is also included this is or'd in
        if self.mask:
            return True
        # Again like the mask if the value must be set to that requested
        if self.value is not None:
            return False
        return False

    def get_masks(self):
        return (self.required_mask, self.optional_mask)

    def _make_masks(self):
        self.required_mask = 0
        self.optional_mask = 0
        if not self.field_name.startswith('$'):
            self.ttp.OF.check_oxm_name(self.field_name, self.log)
            mask_bit = 1 << self.ttp.OF.oxm_name_to_id(self.field_name)
            if self.is_required():
                self.required_mask |= mask_bit
            else:
                self.optional_mask |= mask_bit
        else:
            self.ttp.identifiers.check_identifier(self.field_name, "field",
                                                  self.log)


class TTPMetadata(TTPObject):
    """ Contains the version of this Table Type Pattern i.e. NDM_metadata """
    authority = None
    NDM_type = None
    # name - inherited
    # doc - inherited
    version = None
    version_edit = None
    version_minor = None
    version_major = None
    OF_protocol_version = None

    def __init__(self, input_, parent):
        TTPObject.__init__(self, input_=input_, parent=parent)
        self.authority = self.read_string("authority", False, "")
        self.NDM_type = self.read_string("type", False, "")
        self.name = self.read_string("name", False, "")
        self.version = self.read_string("version", False, "")
        self.OF_protocol_version = self.read_string("OF_protocol_version",
                                                    False, "")

        if self.NDM_type != "TTPv1":
            self.log.warning("Unexpected type %s was expecting TTPv1",
                             self.NDM_type)
        if self.doc is None:
            self.log.info("It is recommended to include a doc string"
                          "describing a TTP in NDM_metadata")

        split_version = self.version.split(".")
        try:
            self.version_major = int(split_version[0])
            self.version_minor = int(split_version[1])
            self.version_edit = int(split_version[2])
        except (IndexError, ValueError):
            self.log.warning("TTP version should be in the format"
                             " <major>.<minor>.<edit>")

    def get_short_description(self):
        """ A short human readable description """
        return self.name + " v" + self.version

    def get_identifier(self):
        """ As per the spec the authority, type, name & version
            uniquely identifies a TTP
        """
        return (self.authority + '/' + self.NDM_type + '/' + self.name +
                '/' + self.version)

    def __str__(self):
        return (self.get_identifier() + " for OFv" + self.OF_protocol_version +
                ":\n" + self.doc)


class TTPSecurity(TTPObject):
    sig = None

    def __init__(self, input_, parent):
        TTPObject.__init__(self, input_=input_, parent=parent)
        if not isinstance(self.doc, string_types):
            self.log.error("The security section should contain a doc string")
            self.doc = ''

        if "sig" in input_:
            self.sig = input_["sig"]

    def __str__(self):
        return ("Security considerations: " + self.doc +
                ("\n " + "Signed: " + self.sig) if self.sig else "")


class TTPVariable(TTPObject):
    """ A constraint on the value used in the TTP
        "var": "<port_id>",
        "range": "1..48"
        "doc": "A port number, we have 48 on this switch"
        Then later:
        "type": "IN_PORT"
        "value": "<port_id>"
    """
    var = None  # Required, must be <id> or <<id>>
    range_ = None  # Optional an TTPRange object or None
    # doc handled by TTPObject

    def __init__(self, input_, parent):
        TTPObject.__init__(self, input_=input_, parent=parent)
        self.var = self.read_string_stripped("var", False, None)
        if not (self.var.startswith('<') and self.var.endswith('>')):
            self.log.error("%s identifier must be enclosed in angle brackets"
                           " (<>)", self.var)
            self.var = '<' + self.var + '>'

        self.range_ = self.read_range("range", opt=True, default=None)

    def __str__(self):
        return ("Variable:" + self.var +
                (" Range:" + str(self.range_) if self.range_ else "") +
                "\n\t" + self.doc)


class TTPExtensionIdentifier(TTPObject):
    id_ = None
    type_ = None
    exp_id = None
    exp_code = None
    # doc handled by TTPObject

    def __init__(self, input_, parent):
        TTPObject.__init__(self, input_=input_, parent=parent)
        self.id_ = input_['id']
        self.type_ = self.read_string_stripped('type')
        self.exp_id = self.read_integer('exp_id', default=None, min_=0,
                                        max_=(2**32)-1)
        self.exp_code = self.read_integer('exp_code', opt=True, default=None,
                                          min_=0)
        if self.type_ not in ("field", "inst", "action", "error"):
            self.log.warning("Invalid extension type %s. Expecting type of"
                             " field, inst, action or error.", self.type_)

    def __str__(self):
        code = (" Exp_code:" + hex(self.exp_code)) if self.exp_code else ""
        return ("Extension identifier " + self.type_ + ":" + self.id_ +
                " Exp_id:" + hex(self.exp_id) + code + "\n\t" + self.doc)


class TTPIdentifiers(TTPObject):
    variables = None
    identifiers = None

    def __init__(self, input_, parent):
        TTPObject.__init__(self, input_=input_, parent=parent)
        self.identifiers = {}
        self.variables = {}
        # Fix Pica8 TTP
        if isinstance(input_, dict):
            if "Identifier list" in input_:
                self.log.warning("Pica8 style Identifier list found, the"
                                 " identifier list should be a direct list"
                                 " of variables and identifiers")
                input_ = input_['Identifier list']

        for item in input_:
            if 'var' in item:
                var = TTPVariable(input_=item, parent=self)
                if var.var in self.variables:
                    diff = []
                    for attr in ('range_', 'doc'):
                        if (getattr(self.variables[var.var], attr) !=
                                getattr(var, attr)):
                            diff.append(attr)
                    var.log.warning("Multiple copies of %s have been defined,"
                                    " these differ by: %s", var.var, diff)
                    continue
                self.variables[var.var] = var
            elif 'id' in item:
                ident = TTPExtensionIdentifier(input_=item, parent=self)
                if ident.id_ in self.identifiers:
                    diff = []
                    for attr in ('exp_id', 'exp_code', 'type_', 'doc'):
                        if (getattr(self.identifiers[ident.id_], attr) !=
                                getattr(ident, attr)):
                            diff.append(attr)
                    ident.log.warning("Multiple copies of %s have been defined"
                                      ", these differ by: %s", ident.id_,
                                      str(diff))
                    continue
                self.identifiers[ident.id_] = ident
            else:
                var.log.error("Invalid identifier type found: %s", item)

    def __len__(self):
        return len(self.identifiers) + len(self.variables)

    def check_identifier(self, id_, type_, log):
        """
        Check that an identifier exists, if not logs a warning
        id_: The variable name/id
        type_: The expected type of the field
        """
        if id_.startswith("$"):
            id_ = id_[1:]

        if id_ in self.identifiers:
            that_type = self.identifiers[id_].type_
            if that_type == type_:
                log.debug("%s used known experimenter id: %s",
                          type_, id_)
                return True
            log.warning("experimenter id found with wrong type,"
                        " expected %s found %s", type_, that_type)
        else:
            maybes = [k for k, v in viewitems(self.identifiers)
                      if v.type_ == type_]
            maybes = difflib.get_close_matches(id_, maybes)
            maybes = " or ".join(maybes)
            if maybes:
                log.warning("Experimental %s id %s not found"
                            " - did you mean: %s?", type_, id_, maybes)
            else:
                log.warning("Experimental %s id %s not found", type_, id_)
        return False

    def collect_children(self, class_=TTPObject):
        """ Walk all children and collect them into a flat generator """
        for child in TTPObject.collect_children(self, class_):
            yield child
        for child in viewvalues(self.identifiers):
            for i in child.collect_children(class_):
                yield i
        for child in viewvalues(self.variables):
            for i in child.collect_children(class_):
                yield i


class TableTypePattern(TTPObject):
    allow_unsafe = False  # For publishing online turn off unsafe evaluation
    path = None  # The path to the JSON TTP we loaded
    tables_by_name = None  # By name and number
    tables_by_number = None
    groups_by_name = None
    NDM_metadata = None
    security = None
    identifiers = None
    opt_tag_labels = None
    issues = None  # A list of issues detected (msg, char_start, char_end)
    features = None  # TTPFeatureList - required OpenFlow protocol features
    OF = None  # The OpenFlow defines, oxms, etc

    def add_opt_tagged(self, member):
        self.opt_tag_labels[member.opt_tag].append(member)

    def _flatten_metagroup(self, groups):
        tmp = []
        for group in groups:
            if 'name' in group:
                tmp.append(group)
            else:
                for key, value in viewitems(group):
                    if key not in META_MEMBERS:
                        TTPObject(group, self).log.error(
                            "Ignoring group without name: %s", str(group))
                        break
                    else:
                        tmp += self._flatten_metagroup(expect_list(value))
        return tmp

    def __init__(self, path, logger=None, track_orig=False, as_unicode=False,
                 allow_unsafe=False):
        if logger:
            self.log = logger
        else:
            self.log = logging.getLogger(__name__)
        if as_unicode:
            self.log.info("Loading TTP from the string")
        else:
            self.path = path
            self.log.info("Loading TTP from the file %s", self.path)
        if track_orig:
            if as_unicode:
                tmp = _load_tracked_json(path, as_unicode)
            else:
                _e = None
                for enc in ['utf-8', 'utf-16', 'utf-32']:
                    try:
                        with io.open(self.path, encoding=enc) as data_file:
                            tmp = _load_tracked_json(data_file, as_unicode)
                    except Exception as e:
                        if _e is None:
                            _e = e
                        continue
                    else:
                        break
                else:  # Finished loop without breaking, i.e. error
                    self.log.critical("Unable to open JSON file")
                    raise _e
        else:
            if as_unicode:
                tmp = json.loads(path)
            else:
                _e = None
                for enc in ['utf-8', 'utf-16', 'utf-32']:
                    try:
                        with io.open(self.path, encoding=enc) as data_file:
                            tmp = json.load(data_file)
                    except Exception as e:
                        if _e is None:
                            _e = e
                        continue
                    else:
                        break
                else:  # Finished loop without breaking, i.e. error
                    self.log.critical("Unable to open JSON file")
                    raise _e
        self.allow_unsafe = allow_unsafe
        TTPObject.__init__(self, input_=tmp, parent=None)
        # Load a copy of the oxm of_13_fields
        self.OF = OpenFlow1_3_5()
        try:
            self.NDM_metadata = TTPMetadata(self.input_['NDM_metadata'], self)
            self.log.info("Processing the TTP: %s",
                          self.NDM_metadata.get_identifier())
        except KeyError:
            self.log.critical("Expected a unique ID in the TTP, missing"
                              " the NDM_metadata field")
        # Set initial values
        self.opt_tag_labels = defaultdict(list)
        self.tables_by_name = {}
        self.tables_by_number = {}
        self.groups_by_name = {}

        if 'security' in self.input_:
            self.security = TTPSecurity(self.input_['security'], self)
            self.log.info("Successfully loaded the security from the TTP")

        if 'identifiers' in self.input_:
            self.identifiers = TTPIdentifiers(self.input_['identifiers'], self)
            self.log.info("Successfully loaded identifiers - %s variables and"
                          " %s identifiers", len(self.identifiers.variables),
                          len(self.identifiers.identifiers))
        else:
            self.identifiers = TTPIdentifiers([], self)

        if "features" in self.input_:
            self.features = TTPFeatureList(self.input_['features'], self)
        else:
            self.features = TTPFeatureList([], self)

        if "group_entry_types" in self.input_:
            # We first enumerate the list names, so we can detect
            # a bad reference
            groups = self._flatten_metagroup(self.input_["group_entry_types"])
            for group in groups:
                self.groups_by_name[group['name']] = None
            # Now we fill out the groups
            for group_ in groups:
                group = TTPGroup(input_=group_, parent=self)
                self.groups_by_name[group.name] = group

        map_len = 0

        if 'flow_tables' not in self.input_:
            self.log.error("Missing flow_tables!")
            self.input_['flow_tables'] = []

        if 'table_map' not in self.input_:
            self.log.error("Missing table_map!")
            self.input_['table_map'] = {}

        if not isinstance(self.input_['flow_tables'], list):
            self.log.error("Flow_tables is expected to be a list.")
            self.input_['flow_tables'] = expect_list(
                self.input_['flow_tables'])

        tables_len = len(self.input_['flow_tables'])

        def __link_table(name, number):
            for table in self.input_["flow_tables"]:
                if table['name'] == name:
                    self.tables_by_number[number] = TTPTable(table, number,
                                                             self)
                    self.tables_by_name[name] = self.tables_by_number[number]
                    break
            else:
                self.log.critical("Unable to find table %s in flow_tables.",
                                  name)

        if isinstance(self.input_['table_map'], dict):
            for name, number in viewitems(self.input_['table_map']):
                try:
                    __link_table(name, int(number))
                    map_len += 1
                except (ValueError, LookupError):
                    self.log.critical("Unable to parse tablemap '%s': %s.",
                                      name, number)
        elif isinstance(self.input_['table_map'], list):
            for table_mapping in self.input_['table_map']:
                try:
                    if 'name' in table_mapping and 'number' in table_mapping:
                        __link_table(table_mapping['name'],
                                     int(table_mapping['number']))
                    else:
                        __link_table(table_mapping['name'],
                                     int(table_mapping['num']))
                    map_len += 1
                except (ValueError, LookupError):
                    self.log.critical("Unable to parse tablemap item %s",
                                      table_mapping)
        else:
            self.log.critical("Unable to parse the tablemap, format unknown.")

        if map_len != tables_len:
            self.log.critical("Mismatch between number of tables in the"
                              " table_map (%s) and flow_tables (%s).",
                              map_len, tables_len)

        # Replace goto's with real table, since we had not actually loaded the
        # tables yet :)
        for this_table in self.get_tables():
            tos = defaultdict(list)
            for that_table_name, flows in viewitems(this_table.tos):
                try:
                    that_table = self.find_table(that_table_name)
                except LookupError:
                    for flow in flows:
                        flow.log.critical("Cannot find the table %s referenced"
                                          " in GOTO in %s", that_table_name,
                                          this_table.name)
                    continue
                # Make sure we never go back in tables
                if this_table.number >= that_table.number:
                    for flow in flows:
                        flow.log.error("A GOTO in %s(%s) goes to %s(%s) which "
                                       "does not increase the table number. We"
                                       " have removed this!",
                                       this_table.name, this_table.number,
                                       that_table.name, that_table.number)
                    continue
                tos[that_table] = flows
                that_table.froms[this_table] = flows
            this_table.tos = tos

        self.log.info("Completed loading the TTP")
        if isinstance(self.log, logging.LoggerAdapter):
            if self.log.logger.filters and isinstance(
               self.log.logger.filters[-1], TTPIssueCollector):
                del self.log.logger.filters[-1]

    def print_tables(self):
        for table in self.get_tables():
            print(table.name, table.number)

    def find_table(self, table):
        """ Retrieves a TTPTable by name or number

            A TTPTable can also be passed as input in which case it is returned

            If not found raises a LookupError
        """
        if isinstance(table, TTPTable):
            return table
        if table in self.tables_by_name:
            return self.tables_by_name[table]
        try:
            return self.tables_by_number[int(table)]
        except ValueError:
            raise LookupError("Cannot find table " + str(table))

    def find_group(self, group):
        """ Retrieves a TTPGroup by name

            If not found raises a LookupError
        """
        if isinstance(group, TTPGroup):
            return group
        if not isinstance(group, string_types):
            raise LookupError("Expects a string when looking up a group")
        if group.startswith("<") and group.endswith(">"):
            return self.groups_by_name[group[1:-1]]
        return self.groups_by_name[group]

    def print_table(self, name):
        table = self.find_table(name)
        print("Displaying flows for the " + table.name + " table:")
        for flow in table.flow_mod_types:
            flow.print_flow(nesting='\t')
        if table.built_in_flow_mods:
            print("\tBuilt in Rules:")
            for bifm in table.built_in_flow_mods:
                bifm.print_flow(nesting='\t\t')

    def name2id(self, name):
        return self.tables_by_name[name].number

    def get_tables(self, sorted_=True):
        ret = [x for x in viewvalues(self.tables_by_name)]
        if sorted_:
            ret = sorted(ret, key=lambda a: a.number)
        return ret

    def get_groups(self):
        return [x for x in viewvalues(self.groups_by_name)]

    def collect_children(self, class_=TTPObject):
        """ Walk all children and collect them into a flat generator """
        for child in TTPObject.collect_children(self, class_):
            yield child
        for table in viewvalues(self.tables_by_name):
            for child in table.collect_children(class_):
                yield child
        if self.security is not None:
            for child in self.security.collect_children(class_):
                yield child
        if self.NDM_metadata is not None:
            for child in self.NDM_metadata.collect_children(class_):
                yield child
        if self.identifiers is not None:
            for child in self.identifiers.collect_children(class_):
                yield child
