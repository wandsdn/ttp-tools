""" Adds methods to fit OpenFlow rules into a Table Type Pattern

Adds the satisfies() and apply() methods to TTPObjects.

Satisfies: Takes a OpenFlow rule (or component (action, match etc.) and
checks if it satisfies the requirements of the Table Type Pattern.

Apply: Given a similar rule with the same matches, instructions,
actions but differing values. Fit the new rule in the same way as
another rule that satisfies() previously placed.

Usage:

This library patches the existing objects
import ttp_tools.ttp_satisfies

Then all TTPObjects are patched with the satisfies() and apply() methods.
Use ttp objects as usual.

from ttp_utils.TTP import TableTypePattern
...

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

from collections import defaultdict
import operator

from six import integer_types, viewitems, viewvalues
from six.moves import reduce
from ofequivalence.rule import Rule, ActionList, Group, Match, Bucket, Instructions

from . import TTP
from .ttp_util import extend_class, subclass, expect_list

lor = operator.or_
land = operator.and_


class Remaining(object):
    """ A class to collect all variations of a result """
    __slots__ = ("data",)

    def __init__(self, init=None):
        if init is not None:
            self.data = init
        else:
            self.data = {}

    def update(self, other):
        for k, v in viewitems(other):
            if k in self.data:
                self.data[k].update(v)
            else:
                self.data[k] = set(v)

    def __setitem__(self, item, value):
        if False and isinstance(value, set):
            if item in self.data:
                self.data[item].update(value)
            else:
                self.data[item] = set(value)
        else:
            if item in self.data:
                self.data[item].add(value)
            else:
                self.data[item] = set((value,))

    def __getitem__(self, item): return self.data.__getitem__(item)

    def __contains__(self, item): return self.data.__contains__(item)

    def __delitem__(self, item): return self.data.__delitem__(item)

    def __len__(self): return self.data.__len__()

    def __iter__(self): return self.data.__iter__()

    def iteritems(self): return self.data.iteritems()

    def iterkeys(self): return self.data.iterkeys()

    def itervalues(self): return self.data.itervalues()

    def viewitems(self): return self.data.viewitems()

    def viewvalues(self): return self.data.viewvalues()

    def viewkeys(self): return self.data.viewkeys()

    def items(self): return self.data.items()

    def values(self): return self.data.values()

    def keys(self): return self.data.keys()

    def __str__(self): return self.data.__str__()

    def __repr__(self): return self.data.__repr__()


@extend_class
class TTPList(TTP.TTPList):
    def _satisfies(self, item_in, build_out, final=True, filter_=None):
        """
        Checks the elements in the item_in list can be matched against our
        list of requirements considering the meta type (all, zero_or_more)
        etc in use.

        item_in: An item, which itself is hashable and compareable
        Our items in 'self' are expected to all contain the _satisfies method
        and return a list of remaining items in a dict.
        build_out: The set of item_ins so far in an installable format
        filter_: Allows items in this list to be skipped by returning True
                Expected to have the type lambda x: x->bool
        final: Final will return only those empty items, i.e. fully satisfied
        return: A dict of item_in: build_out pairs
        """

        # Our child can first check masks and then call super()
        remaining = Remaining({item_in: set(build_out)})
        # Now we've got rid of those with no chance, lets verify all special
        # conditions are meet
        # debug()
        if self.meta_type == 'all':
            """ Try match every match, if at any point the list of possible
                matches becomes empty we have failed """
            for item in self:
                if filter_ is not None and filter_(item):
                    continue
                tmp = Remaining()
                for ii, bo in viewitems(remaining):
                    tmp.update(item._satisfies(ii, bo, False))
                # We have applied to them all, and have run out of possible
                # placements. As all are required this means it cannot be done
                if not tmp:
                    return tmp
                remaining = tmp
                continue
        elif self.meta_type in ('zero_or_one', 'exactly_one'):
            initial = remaining
            results = Remaining()
            if self.meta_type == 'zero_or_one':
                results.update(initial)
            for item in self:
                if filter_ is not None and filter_(item):
                    continue
                for ii, bo in viewitems(initial):
                    results.update(item._satisfies(ii, bo, False))
            remaining = results
        elif self.meta_type in ('zero_or_more', 'one_or_more'):
            possible = {}
            for ii, bo in viewitems(remaining):
                possible[ii] = False
            """ With every possible remaining valid combo
                we optionally apply each instruction.
                We mark a successful vs unsuccessful match
                allowing us to filter out those that don't
                meet the one_or_more requirement. We note one
                could meet a one or more without changing the original
                by encountering an optional instruction at the next level
            """
            for item in self:
                if filter_ is not None and filter_(item):
                    continue
                """ Add a changed copy, this might overwrite an existing if so
                    it is set to True """
                tmp = Remaining()
                for ii, bo in viewitems(remaining):
                    tmp.update(item._satisfies(ii, bo, False))
                for i in tmp:
                    possible[i] = True
                remaining.update(tmp)
            if self.meta_type == 'one_or_more':
                remaining = Remaining({x: v for x, v in viewitems(remaining)
                                       if possible[x]})
        else:
            raise NotImplementedError("Bad meta type!!!")
        return remaining

    @staticmethod
    def apply(list_in, build_out, model):
        assert len(model.binding) == len(model)
        for m, b in zip(model, model.binding):
            b.apply(list_in, build_out, m)


@extend_class
class TTPAction(TTP.TTPAction):
    def _satisfies(self, actions, build_out, final=True):
        # Ignore the order for now
        # I think we still need to deal with the actions includes group case
        # :)
        if isinstance(build_out, set):
            r = Remaining()
            for i in build_out:
                r.update(self._satisfies(actions, i, final))
            return r

        if self.action == "SET_FIELD":
            if self.field == "$ALLOW_VLAN_TRANSLATION":
                return Remaining({actions: set((build_out,))})

        if actions is None:
            raise RuntimeError("I don't think this should happen")
        for action in actions:
            if self.action in ("GROUP",):
                # Groups are yet even more actions, so we can try to match
                # these
                try:
                    group = self.ttp.find_group(self.group_id)
                except KeyError:
                    self.log.warning("Could not find group %s, returning"
                                     " unsatisfiable", self.group_id)
                    return Remaining()
                return group._satisfies(actions, build_out, final=False)
            if self.action == action[0]:
                # Lets assume the action is valid for now
                if action[0] in ("COPY_TTL_OUT", "COPY_TTL_IN", "POP_VLAN",
                                 "DEC_MPLS_TTL", "DEC_NW_TTL", "POP_PBB"):
                    assert action[1] is None
                    tmp = actions.copy(remove=(action,))
                    tmp_build_out = build_out.copy(add=(action,))
                    tmp_build_out.binding += (self,)
                    return Remaining({tmp: set((tmp_build_out,))})
                if action[0] in ("SET_FIELD",):
                    if self.field == action[1][0]:
                        # Assume the value is valid
                        tmp = actions.copy(remove=(action,))
                        tmp_build_out = build_out.copy(add=(action,))
                        tmp_build_out.binding += (self,)
                        return Remaining({tmp: set((tmp_build_out,))})
                elif action[0] in ("OUTPUT",):
                    if ((not isinstance(self.port, integer_types)) or
                            self.port == action[1]):
                        tmp = actions.copy(remove=(action,))
                        tmp_build_out = build_out.copy(add=(action,))
                        tmp_build_out.binding += (self,)
                        return Remaining({tmp: set((tmp_build_out,))})
                else:
                    # Assume we are good
                    tmp = actions.copy(remove=(action,))
                    tmp_build_out = build_out.copy(add=(action,))
                    tmp_build_out.binding += (self,)
                    return Remaining({tmp: set((tmp_build_out,))})
        return Remaining()

    def apply(self, actions_in, build_out, model):
        for action in actions_in:
            if self.action in ("GROUP",):
                raise NotImplementedError(
                    "Applying group actions not yet implemented")
            if self.action == action[0]:
                if action[0] in ("COPY_TTL_OUT", "COPY_TTL_IN", "POP_VLAN",
                                 "DEC_MPLS_TTL", "DEC_NW_TTL", "POP_PBB"):
                    assert action[1] is None
                    build_out.append(*action)
                    actions_in.remove(action)
                    return
                if action[0] in ("SET_FIELD",):
                    if self.field == action[1][0]:
                        build_out.append(*action)
                        actions_in.remove(action)
                        return
                elif action[0] in ("OUTPUT",):
                    if ((not isinstance(self.port, integer_types)) or
                            self.port == action[1]):
                        build_out.append(*action)
                        actions_in.remove(action)
                        return
                else:  # Assume we are good
                    build_out.append(*action)
                    actions_in.remove(action)
                    return
        assert "Did not expect to reach here" == 0


@extend_class
class TTPActionList(TTP.TTPActionList):
    # Order matters but lets ignore that for now
    def _satisfies(self, actions, build_out, final=True):
        remaining = TTPList._satisfies(self, item_in=actions,
                                       build_out=build_out, final=final)
        if final:
            return Remaining({k: v for k, v in viewitems(remaining) if len(k) == 0})
        return remaining


@extend_class
class TTPBucket(TTP.TTPBucket):
    def _satisfies(self, actions, build_out, final=False):
        """
            actions: ActionList
            build_out: A tuple of buckets, or empty tuple
            final: Only return results where actions is empty
            return: A Remaining mapping of action to a set of tuples
        """
        if isinstance(build_out, set):
            ret = Remaining()
            for _build_out in build_out:
                ret.update(self._satisfies(actions, _build_out, final))
            return ret
        empty_bucket = Bucket()
        empty_bucket.ttp_link = self
        res = self.action_set._satisfies(actions, set((empty_bucket,)), final=final)
        remaining = Remaining()
        for k, vs in viewitems(res):
            remaining.update({k: {build_out + (v,) for v in vs}})
        if final:
            return Remaining({k: v for k, v in viewitems(remaining) if len(k) == 0})
        return remaining


@extend_class
class TTPGroup(TTP.TTPGroup):

    @staticmethod
    def split_output_actions(actions):
        """ Takes a set of actions and splits and returns separated portions

            actions: The actions to split
            return: a tuple containing:
                    1) a list of output actions and
                    2) a list of lists of actions corresponding to the
                       modification for each output
        """
        outputs = [x for x in actions if x[0] == "OUTPUT"]
        combinations = []

        for output in outputs:
            excluding_outputs = [x for x in outputs
                                 if x[0] == "OUTPUT" and x != output]
            new_act = actions.copy(remove=excluding_outputs)
            # Drop any actions applied after the output
            while new_act[-1][0] != "OUTPUT":
                new_act.remove(new_act[-1])
            combinations.append(new_act)
        assert len(outputs) == len(combinations)
        return outputs, combinations

    def _satisfies(self, actions, build_out, final=False):
        """ Build out is still a single item """
        if self.group_type == "INDIRECT":
            # Set of a bucket list i.e. a tuple
            ret = self.bucket_types._satisfies(actions, set(((),)),
                                               final=False)
            nret = Remaining()
            for unplaced, places in viewitems(ret):
                for buckets in places:
                    assert isinstance(buckets, tuple)
                    assert len(buckets) == 1
                    group = Group()
                    group.ttp_link = self
                    group.type_ = "INDIRECT"
                    group.buckets = buckets
                    tmp_build_out = build_out.copy(add=(("GROUP", group),))
                    tmp_build_out.binding += (self,)
                    nret[unplaced] = tmp_build_out
            return nret
        if self.group_type == "ALL":
            # We can repeat buckets as many times as is needed
            # But remember this is a copy so actions + output only
            # resolves the single output
            # TODO we are ignoring ordering and groups for now

            # Split out the OUTPUT parts
            outputs, combinations = self.split_output_actions(actions)

            def no_output(actions):
                excluding_outputs = [x for x in actions if x[0] != "OUTPUT"]
                new_act = actions.copy(remove=excluding_outputs)
                return new_act

            def get_output(actions):
                only_output = [x for x in actions if x[0] == "OUTPUT"]
                assert len(only_output) == 1
                return only_output[0]

            possible = []
            for bucket in self.bucket_types:
                # We might allow a couple of different
                # Bucket types, so we check each type
                set_remaining = defaultdict(list)
                for new_act in combinations:
                    # TODO Do we have to do this as a final, otherwise
                    # we might not be able to entirely remove the action
                    r = bucket._satisfies(new_act, set(((),)),
                                          final=False)
                    # Strip the list of buckets i.e. the tuple, and we will have just one Bucket
                    for places in viewvalues(r):
                        stripped_tuple = {buckets[0] for buckets in places}
                        places.clear()
                        places.update(stripped_tuple)

                    possible.append(r)
                    for k, _v in viewitems(possible[-1]):
                        for v in _v:
                            set_remaining[k].append((new_act, v))

            # TODO because we cannot return a half done one, this does not work
            # It is possible the level up could have two groups, one that
            # strips vlan and one that does not, and an output on each.
            # I think we really need to separate each output path to do this
            # properly
            l = len(outputs)
            results = Remaining()
            while l >= len(outputs) and len(set_remaining):
                most_maxed_out = max(set_remaining,
                                     key=lambda x: len(set_remaining[x]))
                items = set_remaining[most_maxed_out]
                l = len(items)
                acheived_outputs = set([get_output(x[0]) for x in items])
                if acheived_outputs == set(outputs):
                    g = Group()
                    g.ttp_link = self
                    g.type_ = "ALL"
                    g.buckets += tuple((x[1] for x in items))
                    tmp_build_out = build_out.copy(add=(("GROUP", g),))
                    tmp_build_out.binding += (self,)
                    results[most_maxed_out] = tmp_build_out
                del set_remaining[most_maxed_out]
            # debug()
            return results
        if self.group_type == "FF":
            #self.log.warning("We have not implemented fast fail over"
            #                 ", ignoring")
            return Remaining()
        if self.group_type == "SELECT":
            #self.log.warning("We have not implemented SELECT groups yet"
            #                 ", ignoring")
            return Remaining()
        raise NotImplementedError("satisfies() unknown group type " +
                                  self.group_type)

    def apply(self, act_in, build_out, model):
        if self.group_type == "INDIRECT":
            assert model[0] == 'GROUP'
            model = model[1]
            assert model.type_ == "INDIRECT"
            g = Group()
            g.ttp_link = self
            g.type_ = "INDIRECT"
            g.buckets += (Bucket(),)

            assert len(model.buckets) == 1

            # TODO, Ideally satisfies should link to the actual bucket type,
            # but that is not the case as buckets are stored as lists.

            # So to find the associated bucket type. Walk parents to find the
            # list from the actions applied.
            assert model.buckets[0].binding  # I guess an empty is valid but
                                             # would fail bucket here
            bucket = model.buckets[0].ttp_link
            assert bucket in self.bucket_types
            bucket.action_set.apply(act_in, g.buckets[0], model.buckets[0])

            assert len(g.buckets[0]) == len(model.buckets[0])

            build_out.append("GROUP", g)
            build_out.binding += (self,)
            return
        if self.group_type == "ALL":
            # This grabs the option that uses the most of the match up
            ret = self._satisfies(act_in, build_out)
            assert len(ret) == 1
            assert len(list(viewvalues(ret))[0]) == 1
            # Move the returned to act_in XXX ugly TODO
            while act_in:
                act_in.remove(act_in[0])
            for x in list(ret)[0]:
                act_in.append(x)
            no = list(list(viewvalues(ret))[0])[0]
            build_out.binding = no.binding
            build_out.append(*no[-1])
        else:
            raise NotImplementedError("apply() for group type " +
                                      self.group_type + " not implemented")


@extend_class
class TTPInstruction(TTP.TTPInstruction):
    def _satisfies(self, instructions, build_out, final=False):
        """
            instructions: Instructions, to be satisfied
            build_out: A set of Instructions representing currently
                       satisfied portions
            final: If final return only the fully satisfied results
        """
        if isinstance(build_out, set):
            r = Remaining()
            for x in build_out:
                r.update(self._satisfies(instructions, x, final))
            return r

        if self.instruction == "GOTO_TABLE":
            # For now always remove this :) TODO XXX
            if instructions.goto_table == self.table or True:
                nbuild_out = Instructions(build_out)
                assert nbuild_out.goto_table is None
                nbuild_out.goto_table = self.ttp.find_table(self.table).number
                nbuild_out.binding += (self,)
                cpy = Instructions(instructions)
                cpy.goto_table = None
                return Remaining({cpy: set((nbuild_out,))})
            else:
                return Remaining()
        elif self.instruction in ("APPLY_ACTIONS", "WRITE_ACTIONS"):
            merged_actions = ActionList(instructions.apply_actions)
            merged_actions += instructions.write_actions
            if self.instruction == "APPLY_ACTIONS":
                ret = self.actions._satisfies(merged_actions,
                                              set((build_out.apply_actions,)),
                                              False)
            else:
                ret = self.actions._satisfies(merged_actions,
                                              set((build_out.write_actions,)),
                                              False)
            rets = Remaining()
            for k, vs in viewitems(ret):
                cpy = Instructions(instructions)
                to_remove = []
                for x in cpy.apply_actions:
                    if x not in k:
                        to_remove.append(x)
                for x in to_remove:
                    cpy.apply_actions.remove(x)

                to_remove = []
                for x in cpy.write_actions:
                    if x not in k:
                        to_remove.append(x)
                for x in to_remove:
                    cpy.write_actions.remove(x)
                if self.instruction == "APPLY_ACTIONS":
                    for v in vs:
                        cpy_inst = Instructions(build_out)
                        cpy_inst.apply_actions = v
                        rets[cpy] = cpy_inst
                else:
                    for v in vs:
                        cpy_inst = Instructions(build_out)
                        cpy_inst.write_actions = v
                        rets[cpy] = cpy_inst
            return rets
        elif self.instruction == "METER":
            # IGNORE meters for now
            return Remaining({instructions: set((build_out,))})
        elif self.instruction == "CLEAR_ACTIONS":
            # Always add clear actions regardless of original
            nbuild_out = Instructions(build_out)
            assert nbuild_out.clear_actions is None
            nbuild_out.clear_actions = True
            nbuild_out.binding += (self,)
            cpy = Instructions(instructions)
            cpy.clear_actions = None
            return Remaining({cpy: set((nbuild_out,))})
        raise NotImplementedError("satisfies() instruction " +
                                  self.instruction + " not implemented")
        # TODO meta-data and meters etc

    def apply(self, inst_in, build_out, model):
        if self.instruction == "GOTO_TABLE":
            # We always allow any goto table do this
            assert build_out.goto_table is None
            inst_in.goto_table = None
            build_out.goto_table = self.ttp.find_table(self.table).number
        elif self.instruction in ("APPLY_ACTIONS", "WRITE_ACTIONS"):
            raise RuntimeError("not expected, call apply and write directly")
        elif self.instruction == "METER":
            raise NotImplementedError("apply() meter not implemented")
        elif self.instruction == "CLEAR_ACTIONS":
            assert inst_in.clear_actions is True
            inst_in.clear_actions = False
            build_out.clear_actions = True
        else:
            raise NotImplementedError("apply() " + self.instruction +
                                      " not implemented")

@extend_class
class TTPInstructionSet(TTP.TTPInstructionSet):
    def _satisfies(self, instructions, build_out, final=True):
        remaining = TTPList._satisfies(self, item_in=instructions,
                                       build_out=build_out, final=final)
        # if this is the final any result that has used all matches is valid
        if final:
            return Remaining({k: v for k, v in viewitems(remaining)
                              if k.empty()})
        return remaining

    def satisfies(self, instructions):
        return len(self._satisfies(instructions,
                                   set((Instructions(),)))) > 0


@extend_class
class TTPMatchSet(TTP.TTPMatchSet):
    required_mask = None
    optional_mask = None

    @subclass
    def __init__(base, self, *args, **kwargs):
        base(self, *args, **kwargs)
        self._make_masks()

    def get_masks(self):
        return (self.required_mask, self.optional_mask)

    def _make_masks(self):
        self.required_mask = 0
        self.optional_mask = 0
        opt_masks = []  # Children's masks
        req_masks = []  # Children's masks
        for match in self:
            r, o = match.get_masks()
            opt_masks.append(o)
            req_masks.append(r)
        # permissively merge based on meta
        # i.e. required should only include fields required in
        # all cases otherwise we will incorrectly filter these out
        if self.meta_type == 'all':
            """We still require all required fields from each match
               and optionally can include any optional fields.
            """
            self.required_mask = reduce(lor, req_masks, 0)
            self.optional_mask = reduce(lor, opt_masks, 0)
        elif self.meta_type in ('one_or_more', 'exactly_one'):
            """ At least one must be picked, a field is required if each match
                includes it. And all the others are optional.
            """
            if not req_masks:
                assert "Invalid request for one or more with 0 sized set" == 0
            self.required_mask = reduce(land, req_masks)
            self.optional_mask = (reduce(lor, req_masks, 0) |
                                  reduce(lor, opt_masks, 0))
        elif self.meta_type in ('zero_or_more', 'zero_or_one'):
            """ In the zero case nothing is required, therefore everything is
                optional """
            self.required_mask = 0
            self.optional_mask = (reduce(lor, req_masks, 0) |
                                  reduce(lor, opt_masks, 0))
        else:
            assert "Oooops we made a bad class" == 0
        # Ensure that optional don't overlap the required
        self.optional_mask &= ~self.required_mask

    def _satisfies(self, matches, build_out, final=True):
        """ A recursive version of matches which allows a partial match
            and returns a set of all remaining possible match combinations """
        # Check we have the required fields
        r_mask, o_mask = self.get_masks()
        # Check we set all fields which are required to be set by the TTP
        if (matches.required_mask & r_mask) != r_mask:
            return Remaining()
        # If this is the final, we must ensure the field set is empty
        # Check the fields are not encompassed by all compulsory and optional
        # it means we cannot represent the ryu_match
        if final and ((matches.required_mask & (o_mask | r_mask)) !=
                      matches.required_mask):
            return Remaining()

        def filter_(ttp_m):
            if isinstance(ttp_m, TTPMatch):
                # For now skip fields that are not in the spec, we can
                # probably set these to 0 anyway
                if not ttp_m.is_standard_field():
                    return True
            return False
        # TTPList knows all about meta and handles this for us
        remaining = TTPList._satisfies(self, item_in=matches,
                                       build_out=build_out, final=final,
                                       filter_=filter_)

        # if this is the final any result that has used all matches is valid
        if final:
            return Remaining({k: v for k, v in viewitems(remaining)
                              if len(k) == 0})
        return remaining

    def satisfies(self, match):
        """ Match: A Match object with all matches of the flow appended
        """
        return len(self._satisfies(match, Match())) > 0


@extend_class
class TTPFlow(TTP.TTPFlow):
    def satisfies_matches(self, flow_matches):
        return self.match_set.satisfies(flow_matches)

    def satisfies_instructions(self, flows_instructions):
        return self.instruction_set.satisfies(flows_instructions)

    def satisfies(self, flow):
        return self._satisfies(flow)

    def _satisfies(self, flow, final=True):
        rets = Remaining()
        ret = Rule()
        if self.priority is not None:
            ret.priority = self.priority
        else:
            ret.priority = flow.priority
        ret.table = self.walk_parents(TTP.TTPTable).number
        res_matches = self.match_set._satisfies(flow.match,
                                                set((Match(),)),
                                                final=final)
        if not res_matches:
            return Remaining()

        res_instructions = self.instruction_set._satisfies(
            flow.instructions, set((Instructions(),)), final=final)
        if not res_instructions:
            return Remaining()

        for mk, _mv in viewitems(res_matches):
            for mv in _mv:
                for ik, _iv in viewitems(res_instructions):
                    for iv in _iv:
                        nflow = flow.copy()
                        nflow.match = mk
                        nflow.instructions = ik
                        nflow_out = ret.copy()
                        nflow_out.match = mv
                        nflow_out.instructions = iv
                        rets[nflow] = nflow_out

        for v in viewvalues(rets):
            assert isinstance(v, set)
            for a in v:
                assert isinstance(a, Rule)
                assert isinstance(a.match, Match)
                assert isinstance(a.instructions, Instructions)
                assert isinstance(a.instructions.apply_actions, ActionList)
                assert isinstance(a.instructions.write_actions, ActionList)
                assert hasattr(a.instructions, "binding")
                assert hasattr(a.instructions.apply_actions, "binding")
                assert hasattr(a.instructions.write_actions, "binding")
                assert hasattr(a.match, "binding")
        return rets

    @staticmethod
    def apply(flow_in, model):
        """
            flow_in: A similar looking input flow, to place
            model: The original model placement, with binding information
            return a new placed flow
        """
        nf = Rule()
        flow_copy = flow_in.copy()
        flow_copy.instructions.clear_actions = model.instructions.clear_actions
        build_matches = nf.match
        for i in model.match.binding:
            i.apply(flow_copy.match, build_matches, model)

        build_inst = nf.instructions
        for i in model.instructions.binding:
            i.apply(flow_copy.instructions, build_inst, model)

        merged_actions = flow_copy.instructions.full_actions()
        build_apply = nf.instructions.apply_actions
        build_write = nf.instructions.write_actions
        TTPActionList.apply(merged_actions, build_apply,
                            model.instructions.apply_actions)
        """ BUGGY, removes items if they are not a 1<->1 match
        if len(build_apply):
            # debug()
            # Reorder these to match the original ordering (if we can)
            n_aa = ActionList()
            for a in flow_copy.instructions.full_actions():
                if a in build_apply:
                    n_aa.append(*a)

            n_aa.binding = build_apply.binding
            nf.instructions.apply_actions = n_aa
        """
        TTPActionList.apply(merged_actions, build_write,
                            model.instructions.write_actions)

        # If we feed in a split placement this won't be true
        #if not nf.instructions.full_actions().equiv_equal(flow_in.instructions.full_actions()):
        #    debug()

        nf.priority = model.priority
        nf.cookie = model.cookie
        nf.table = model.table
        return nf


@extend_class
class TTPMatch(TTP.TTPMatch):
    def satisfies_const(self, value, mask):
        """ Checks that a ryu match, has the const bits set to their
            correct values as listed in the TTP by const_value/mask.

            @return True if the ryu match meets any requirements
        """
        if not self.const_mask:
            # No const_value so we always match it
            return True
        # Our mask must include the same bits as the const_mask
        if mask is not None:
            if (mask & self.const_mask) != self.const_mask:
                return False
        # Check the value also match
        if (self.const_mask & value) != self.const_value:
            return False
        return True

    def satisfies_mask(self, mask):
        if self.mask is None:
            return True
        if mask is None:
            # No mask is the same as a fully matched mask
            return self.width_mask == self.mask
        if self.const_mask:
            return (self.const_mask | self.mask) == mask
        return self.mask == mask

    def satisfies_value(self, value, mask):
        if self.value is None:
            return True
        if mask is not None:
            return (self.value & mask) == (value & mask)
        return self.value == value

    def _satisfies(self, match_in, build_out, ignored):
        """
        match_in: A Match representing the unassigned portion of a match
        build_out: A set of Match already assigned, given the input
        return: A Remaining structure, mapping unassigned to the assigned
                portion
        """
        assert isinstance(match_in, Match)
        assert isinstance(build_out, set)
        assert not build_out or isinstance(next(iter(build_out)), Match)
        res = Remaining()
        if not self.is_required():
            res.update({match_in: build_out})
        if self.field_name in match_in:
            match = match_in[self.field_name]
            if self.satisfies(match[0], match[1]):
                tmp_match_in = match_in.copy(remove=((self.field_name,),))
                tmp_build_out = set()
                for m in build_out:
                    nm = m.copy(add=((self.field_name, match[0], match[1]),))
                    nm.binding += (self,)
                    tmp_build_out.add(nm)
                res.update({tmp_match_in: tmp_build_out})
        return res

    def apply(self, match_in, build_out, model):
        """ Apply this match """
        match = match_in[self.field_name]
        assert self.satisfies(match[0], match[1])
        del match_in[self.field_name]
        build_out.append(self.field_name, match[0], match[1])

    def is_prefix_mask(self, mask):
        if self.width_mask == -1:
            self.log.warning("Unable to check prefix as field width for %s"
                             " is unknown", self.field_name)
            return True
        highest_bit = (self.width_mask + 1) >> 1
        while highest_bit & mask == highest_bit:
            # switch off the highest bit if it is on
            mask &= ~highest_bit
            mask <<= 1
        return mask == 0

    def satisfies(self, value, mask):
        """ True if the value and mask meets all requirements, otherwise
            False indicating that the value and mask do not match
        """

        # Check the required constant bits are set to the correct values
        if not self.satisfies_const(value, mask):
            return False
        if not self.satisfies_mask(mask):
            return False
        if not self.satisfies_value(value, mask):
            return False
        if self.match_type == 'exact':
            if self.mask is not None:
                raise "Invalid combination of one of mask and match_type=exact"
            if mask is not None and mask & self.width_mask != self.width_mask:
                return False
            return True
        if self.match_type == 'all_or_exact':
            if self.mask is not None:
                raise "Invalid combination of one of mask and match_type=exact"
            if (mask is not None and
                    mask & self.width_mask not in (0, self.width_mask)):
                return False
            return True
        if self.match_type == 'prefix':
            if mask is None:
                return True
            mask &= self.width_mask
            return self.is_prefix_mask(mask)
        if self.match_type == 'mask':
            # Any mask matches an arbitrary mask
            return True
        raise ValueError("Bad match_type")


@extend_class
class TableTypePattern(TTP.TableTypePattern):
    def try_place_rules(self, table, fitting_flow):
        table = self.find_table(table)
        # Give expected values, i.e. one could say no VLAN
        # no TUNNEL_ID(i.e. =0), no METADATA(i.e. =0) etc.
        # we already ignore/assume a value of zero for experimental ($) fields
        implied_values = [('TUNNEL_ID', 0, None)]
        fitting_flow = fitting_flow.copy()
        fitting_flow.match = fitting_flow.match.copy(add=implied_values)

        # This returns 0->table in the results
        working_paths = table.get_reachable()
        # All paths should start with 0
        assert (len([path for path in working_paths if path[0] == 0]) ==
                len(working_paths))

        if len(working_paths) > 5:
            print("\t\tAttempting to place rule in table", table.name,
                  "checking", len(working_paths), "paths")
        else:
            print("\t\tAttempting to place rule in table", table.name,
                  "checking the following paths:", working_paths)

        # Find all possible (to, from) combinations
        # Then accept any path in which every to, from is meet
        new_paths = []

        def to_tofrom(path):
            return tuple([(path[i], path[i+1]) for i in range(0, len(path)-1)])

        for path in working_paths:
            new_paths.append(to_tofrom(path))

        to_from_set = set()
        for path in new_paths:
            to_from_set.update(path)
        can_make_it = defaultdict(list)

        for from_table, to_table in to_from_set:
            tos = self.find_table(from_table).tos[self.find_table(to_table)]
            for flow in tos:
                # Iterate all flows going to the next table, including bifms
                # We want a rule allowing all packets, however special fields
                # can be set to 0 and overlapping matches may be filtered to
                # only include parts relevant to this match
                res = flow._satisfies(fitting_flow, final=False)
                if res:
                    if flow.built_in:
                        can_make_it[(from_table, to_table)].append(flow)
                    else:
                        # Lets pick one, for now we use the most permissive
                        # In the case there are two or more only one is picked
                        picked, flow_out = max(viewitems(res),
                                               key=lambda k: len(k[0].match))
                        can_make_it[(from_table, to_table)].append(flow_out)

        valid_paths = []
        pure_paths = set(can_make_it)
        for path in new_paths:
            if set(path).issubset(pure_paths):
                index = new_paths.index(path)
                valid_paths.append(working_paths[index])

        res = {}
        for p in valid_paths:
            flow_opts = []
            for i in range(0, len(p)-1):
                flow_opts.append(can_make_it[(p[i], p[i+1])])
            res[p] = tuple(flow_opts)

        # Returns {path: [([flows],...), ([flows], ...) ]}
        return res

    def identify_match_flows(self, flow_matches, tables=None):
        """ Retrieve a list of TTPFlows which satisfy the flow_matches requirement

            flow_matches: A Match object
            tables: A list of tables (satisfying find_table) to check. If None
            or excluded or all tables are checked.
            Returns: A list of flow matches
        """
        ret = []
        if tables is None:
            tables = self.get_tables()

        for table in expect_list(tables):
            table = self.find_table(table)
            for flow in table.flow_mod_types:
                if flow.satisfies_matches(flow_matches):
                    ret.append(flow)
        return ret

    def satisfies_flow(self, flow_in, tables=None):
        """ Returns a list of places a rule can be installed which
            satisfies both the match and instruction set of a rule
            flow: The flow to try and fit
            tables: A filtered list of tables to check or none
            Return: A list of TTPFlows (excludes bifm)
        """
        # Narrow down to those that satisfy the match
        ret = []
        if tables is None:
            tables = self.get_tables()

        for table in expect_list(tables):
            table = self.find_table(table)
            for flow in table.flow_mod_types:
                if flow.satisfies(flow_in):
                    ret.append(flow)
        return ret
