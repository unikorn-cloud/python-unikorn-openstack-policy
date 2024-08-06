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

import re

from neutron.conf import policies
from oslo_policy import policy

rules = [
    # The domain manager has the role 'manager', as defined by
    # https://docs.scs.community/standards/scs-0302-v1-domain-manager-role/
    policy.RuleDefault(
        name='is_domain_manager',
        check_str='role:manager',
        description='Rule for manager access',
    ),

    # A common helper to define that the user is a manager and the resource
    # target is in the same domain as the user is scoped to.
    policy.RuleDefault(
        name='is_project_manager_owner',
        check_str='rule:is_domain_manager and project_id:%(project_id)s',
        description='Rule for domain manager ownership',
    ),

    # The domain manager can create and delete networks in its domain.
    # If the domain manager is able to create a network, it can also create provider networks.
    # Don't be naive enough here to assume the ability to provision a network is enough to
    # allow provider networks, if the prior rule changes, then we can open up a security hole.
    policy.RuleDefault(
        name='create_network',
        check_str='rule:is_project_manager_owner or rule:base_create_network',
        description='Create a network',
    ),
    policy.RuleDefault(
        name='delete_network',
        check_str='rule:is_project_manager_owner or rule:base_delete_network',
        description='Delete a network',
    ),
    policy.RuleDefault(
        name='create_network:segments',
        check_str='rule:is_project_manager_owner or rule:base_create_network:segments',
        description='Specify ``segments`` attribute when creating a network',
    ),
    policy.RuleDefault(
        name='create_network:provider:network_type',
        check_str='rule:is_project_manager_owner or rule:base_create_network:provider:physical_network',
        description='Specify ``provider:network_type`` when creating a network',
    ),
    policy.RuleDefault(
        name='create_network:provider:physical_network',
        check_str='rule:is_project_manager_owner or rule:base_create_network:provider:network_type',
        description='Specify ``provider:physical_network`` when creating a network',
    ),
    policy.RuleDefault(
        name='create_network:provider:segmentation_id',
        check_str='rule:is_project_manager_owner or rule:base_create_network:provider:segmentation_id',
        description='Specify ``provider:segmentation_id`` when creating a network',
    ),
]


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


def list_rules():
    """Implements the "oslo.policy.policies" entry point"""

    # For every defined rule, look for a corresponding one sourced directly
    # from neutron, this means we can augment the exact rule defined for a
    # specific version of neutron,
    network_rules = list(policies.list_rules())

    inherited_network_rules = []

    for rule in rules:
        try:
            network_rule = _find_rule(rule.name, network_rules)

            check_str = _build_check_str(network_rule.check_str, network_rules)

            inherited_network_rules.append(policy.RuleDefault(
                name='base_' + rule.name,
                check_str=check_str,
                description=rule.description,
            ))
        except MissingRuleException:
            pass

    return inherited_network_rules + rules


# vi: ts=4 et:
