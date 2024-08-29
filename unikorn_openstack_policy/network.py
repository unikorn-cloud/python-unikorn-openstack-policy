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

from neutron.conf import policies
from oslo_config import cfg
from oslo_policy import policy
from unikorn_openstack_policy import base

rules = [
    # The domain manager can create and delete networks in its domain.
    # If the domain manager is able to create a network, it can also create provider networks.
    # Don't be naive enough here to assume the ability to provision a network is enough to
    # allow provider networks, if the prior rule changes, then we can open up a security hole.
    policy.RuleDefault(
        name='create_network',
        check_str='rule:is_project_manager_owner',
        description='Create a network',
    ),
    policy.RuleDefault(
        name='delete_network',
        check_str='rule:is_project_manager_owner',
        description='Delete a network',
    ),
    policy.RuleDefault(
        name='create_network:segments',
        check_str='rule:is_project_manager_owner',
        description='Specify ``segments`` attribute when creating a network',
    ),
    policy.RuleDefault(
        name='create_network:provider:network_type',
        check_str='rule:is_project_manager_owner',
        description='Specify ``provider:network_type`` when creating a network',
    ),
    policy.RuleDefault(
        name='create_network:provider:physical_network',
        check_str='rule:is_project_manager_owner',
        description='Specify ``provider:physical_network`` when creating a network',
    ),
    policy.RuleDefault(
        name='create_network:provider:segmentation_id',
        check_str='rule:is_project_manager_owner',
        description='Specify ``provider:segmentation_id`` when creating a network',
    ),
]


def list_rules():
    """Implements the "oslo.policy.policies" entry point"""

    # For every defined rule, look for a corresponding one sourced directly
    # from neutron, this means we can augment the exact rule defined for a
    # specific version of neutron,
    return base.inherit_rules(rules, list(policies.list_rules()))


def get_enforcer():
    """Implements the "oslo.policy.enforcer" entry point"""

    enforcer = policy.Enforcer(conf=cfg.CONF)
    enforcer.register_defaults(list_rules())

    return enforcer

# vi: ts=4 et:
