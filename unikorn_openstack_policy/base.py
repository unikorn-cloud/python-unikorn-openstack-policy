# Copyright 2024 the Unikorn Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Defines Oslo Policy Rules.
"""

# pylint: disable=line-too-long

import itertools
import re

from oslo_policy import policy

rules = [
    # The domain manager has the role 'manager', as defined by
    # https://docs.scs.community/standards/scs-0302-v1-domain-manager-role/
    policy.RuleDefault(
        name='is_manager',
        check_str='role:manager',
        description='Rule for manager access',
    ),

    # A common helper to define that the user is a manager and the resource
    # target is in the same domain as the user is scoped to.
    policy.RuleDefault(
        name='is_project_manager',
        check_str='rule:is_manager and project_id:%(project_id)s',
        description='Rule for domain manager ownership',
    ),
]


def list_rules():
    """Implements the "oslo.policy.policies" entry point"""

    return rules


class MissingRuleException(Exception):
    """
    Raised when a rule cannot be resolved
    """


def _find_rule(name, rule_list):
    """Return a named rule if it exists or None"""

    for rule in rule_list:
        if rule.name == name:
            return rule

    raise MissingRuleException('unable to resolve referenced rule ' + name)


def _wrap_check_str(tokens):
    """If the check string is more than one token, wrap it in parenteses"""

    if len(tokens) > 1:
        tokens.insert(0, '(')
        tokens.append(')')

    return tokens


def _recurse_build_check_str(check_str, rule_list):
    """
    Given a check string, this does macro expansion of rule:roo strings
    removing and inlining them.
    """

    out = []

    for token in re.split(r'\s+', check_str):
        if token.isspace():
            continue

        # Handle leading parentheses.
        clean = token.lstrip('(')
        for _ in range(len(token) - len(clean)):
            out.append('(')

        # Handle trailing parentheses.
        token = clean

        clean = token.rstrip(')')
        trail = len(token) - len(clean)

        # If the token is a rule, then expand it.
        matches = re.match(r'rule:([\w_]+)', clean)
        if matches:
            rule = _find_rule(matches.group(1), rule_list)
            sub_check_str = _recurse_build_check_str(rule.check_str, rule_list)
            out.extend(_wrap_check_str(sub_check_str))
        else:
            out.append(clean)

        for _ in range(trail):
            out.append(')')

    return out


def _build_check_str(check_str, rule_list):
    """
    Given a check string, this does macro expansion of rule:roo strings
    removing and inlining them.
    """

    check_str = ' '.join(_recurse_build_check_str(check_str, rule_list))
    check_str = re.sub(r'\( ', '(', check_str)
    check_str = re.sub(r' \)', ')', check_str)
    return check_str


def inherit_rules(mine, theirs):
    """
    Given my rules, add any from openstack so we can use that as a source of truth.
    """

    expanded = []

    for rule in mine:
        try:
            inherited_rule = _find_rule(rule.name, theirs)

            check_str = _build_check_str(inherited_rule.check_str, theirs)

            expanded.append(policy.RuleDefault(
                name=rule.name,
                check_str=f'{rule.check_str} or ({check_str})',
                description=rule.description,
            ))
        except MissingRuleException:
            pass

    return itertools.chain(rules, expanded)

# vi: ts=4 et:
