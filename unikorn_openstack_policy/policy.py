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

from neutron.conf.policies import base
from oslo_policy import policy

rules = [
    # Base rule definitions must be exact copies of the base poilicy.
    policy.RuleDefault(
        name='base_create_network',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        description='Create a network',
    ),
    policy.RuleDefault(
        name='base_create_network:segments',
        check_str=base.ADMIN,
        description='Specify ``segments`` attribute when creating a network',
    ),
    policy.RuleDefault(
        name='base_create_network:provider:network_type',
        check_str=base.ADMIN,
        description='Specify ``provider:network_type`` when creating a network',
    ),
    policy.RuleDefault(
        name='base_create_network:provider:physical_network',
        check_str=base.ADMIN,
        description='Specify ``provider:physical_network`` when creating a network',
    ),
    policy.RuleDefault(
        name='base_create_network:provider:segmentation_id',
        check_str=base.ADMIN,
        description='Specify ``provider:segmentation_id`` when creating a network',
    ),
    policy.RuleDefault(
        name='base_delete_network',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        description='Delete a network',
    ),

    # The domain manager has the role 'manager', as defined by
    # https://docs.scs.community/standards/scs-0302-v1-domain-manager-role/
    policy.RuleDefault(
        name='is_domain_manager',
        check_str='role:manager',
        description='Rule for manager access',
    ),

    # The domain manager can create and delete networks in its domain.
    policy.RuleDefault(
        name='create_network',
        check_str='(rule:is_domain_manager and domain_id:%(domain_id)s) or rule:base_create_network',
        description='Create a network',
    ),
    policy.RuleDefault(
        name='delete_network',
        check_str='(rule:is_domain_manager and domain_id:%(domain_id)s) or rule:base_delete_network',
        description='Delete a network',
    ),

    # If the domain manager is able to create a network, it can also create provider networks.
    # Don't be naive enough here to assume the ability to provision a network is enough to
    # allow provider networks, if the prior rule changes, then we can open up a security hole.
    policy.RuleDefault(
        name='create_network:segments',
        check_str='(rule:is_domain_manager and domain_id:%(domain_id)s) or rule:base_create_network:segments',
        description='Specify ``segments`` attribute when creating a network',
    ),
    policy.RuleDefault(
        name='create_network:provider:network_type',
        check_str='(rule:is_domain_manager and domain_id:%(domain_id)s) or rule:base_create_network:provider:physical_network',
        description='Specify ``provider:network_type`` when creating a network',
    ),
    policy.RuleDefault(
        name='create_network:provider:physical_network',
        check_str='(rule:is_domain_manager and domain_id:%(domain_id)s) or rule:base_create_network:provider:network_type',
        description='Specify ``provider:physical_network`` when creating a network',
    ),
    policy.RuleDefault(
        name='create_network:provider:segmentation_id',
        check_str='(rule:is_domain_manager and domain_id:%(domain_id)s) or rule:base_create_network:provider:segmentation_id',
        description='Specify ``provider:segmentation_id`` when creating a network',
    ),
]

def list_rules():
    """Implements the "oslo.policy.policies" entry point"""
    return base.list_rules() + rules

# vi: ts=4 et:
