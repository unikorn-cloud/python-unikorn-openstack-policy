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
Unit tests for OpenStack policies.
"""

from oslo_policy import policy

from unikorn_openstack_policy import network
from unikorn_openstack_policy.tests import base

class ProjectAdminNetworkPolicyTests(base.PolicyTestsBase):
    """
    Checks policy enforcement for project scoped admin role.
    """

    # Request context.
    context = None

    def setUp(self):
        """Perform setup actions for all tests"""
        self.setup(network.get_enforcer())
        self.context = self.project_admin_context

    def test_create_network(self):
        """Admin can create networks"""
        self.assertTrue(self.enforce('create_network', self.target, self.context))
        self.assertTrue(self.enforce('create_network', self.alt_target, self.context))

    def test_create_network_segments(self):
        """Admin can specifiy network segments"""
        self.assertTrue(self.enforce('create_network:segments', self.target, self.context))
        self.assertTrue(self.enforce('create_network:segments', self.alt_target, self.context))

    def test_create_network_provider_network_type(self):
        """Admin can specify provider network types"""
        self.assertTrue(
                self.enforce('create_network:provider:network_type', self.target, self.context))
        self.assertTrue(
                self.enforce('create_network:provider:network_type', self.alt_target, self.context))

    def test_create_network_provider_physical_network(self):
        """Admin can specify provider physical networks"""
        self.assertTrue(
                self.enforce('create_network:provider:physical_network', self.target, self.context))
        self.assertTrue(
                self.enforce(
                    'create_network:provider:physical_network', self.alt_target, self.context))

    def test_create_network_provider_segmentation_id(self):
        """Admin can specify provider segmentation IDs"""
        self.assertTrue(
                self.enforce('create_network:provider:segmentation_id', self.target, self.context))
        self.assertTrue(
                self.enforce(
                    'create_network:provider:segmentation_id', self.alt_target, self.context))

    def test_delete_network(self):
        """Admin can delete networks"""
        self.assertTrue(self.enforce('delete_network', self.target, self.context))
        self.assertTrue(self.enforce('delete_network', self.alt_target, self.context))


class DomainAdminNetworkPolicyTests(ProjectAdminNetworkPolicyTests):
    """
    Checks policy enforcement for domain scoped admin role
    """

    def setUp(self):
        self.setup(network.get_enforcer())
        self.context = self.domain_admin_context


class ProjectManagerNetworkPolicyTests(base.PolicyTestsBase):
    """
    Checks policy enforcement for project scoped manager role
    """

    # Request context.
    context = None

    def setUp(self):
        """Perform setup actions for all tests"""
        self.setup(network.get_enforcer())
        self.context = self.project_manager_context

    def test_create_network(self):
        """Project manager can create networks in its domain"""
        self.assertTrue(self.enforce('create_network', self.target, self.context))
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network', self.alt_target, self.context)

    def test_create_network_segments(self):
        """Project manager can specifiy network segments"""
        self.assertTrue(self.enforce('create_network:segments', self.target, self.context))
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:segments', self.alt_target, self.context)

    def test_create_network_provider_network_type(self):
        """Project manager can specify provider network types"""
        self.assertTrue(
                self.enforce('create_network:provider:network_type', self.target, self.context))
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:provider:network_type', self.alt_target, self.context)

    def test_create_network_provider_physical_network(self):
        """Project manager can specify provider phyical networks"""
        self.assertTrue(
                self.enforce('create_network:provider:physical_network', self.target, self.context))
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:provider:physical_network', self.alt_target, self.context)

    def test_create_network_provider_segmentation_id(self):
        """Project manager can specify provider segmentation IDs"""
        self.assertTrue(
                self.enforce('create_network:provider:segmentation_id', self.target, self.context))
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:provider:segmentation_id', self.alt_target, self.context)

    def test_delete_network(self):
        """Project manager cannot create networks"""
        self.assertTrue(self.enforce('delete_network', self.target, self.context))
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'delete_network', self.alt_target, self.context)


class DomainManagerNetworkPolicyTests(base.PolicyTestsBase):
    """
    Checks policy enforcement for the manager role.
    """

    def setUp(self):
        """Perform setup actions for all tests"""
        self.setup(network.get_enforcer())
        self.context = self.domain_manager_context

    def test_create_network(self):
        """Domain manager cannot create networks"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network', self.target, self.context)
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network', self.alt_target, self.context)

    def test_create_network_segments(self):
        """Domain manager cannot specify network segments"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:segments', self.target, self.context)
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:segments', self.alt_target, self.context)

    def test_create_network_provider_network_type(self):
        """Domain manager cannot specify provider network types"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:provider:network_type', self.target, self.context)
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:provider:network_type', self.alt_target, self.context)

    def test_create_network_provider_physical_network(self):
        """Domain manager cannot specify provider phyical networks"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:provider:physical_network', self.target, self.context)
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:provider:physical_network', self.alt_target, self.context)

    def test_create_network_provider_segmentation_id(self):
        """Domain manager cannot specify provider segmentation IDs"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:provider:segmentation_id', self.target, self.context)
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:provider:segmentation_id', self.alt_target, self.context)

    def test_delete_network(self):
        """Domain manager cannot delete networks"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'delete_network', self.target, self.context)
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'delete_network', self.alt_target, self.context)


class ProjectMemberNetworkPolicyTests(base.PolicyTestsBase):
    """
    Checks policy enforcement for the member role.
    """

    def setUp(self):
        """Perform setup actions for all tests"""
        self.setup(network.get_enforcer())
        self.context = self.project_member_context

    def test_create_network(self):
        """Project member can create networks"""
        self.assertTrue(self.enforce('create_network', self.target, self.context))
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network', self.alt_target, self.context)

    def test_create_network_segments(self):
        """Project member cannot specifiy network segments"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:segments', self.target, self.context)

    def test_create_network_provider_network_type(self):
        """Project member cannot specify provider network types"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:provider:network_type', self.target, self.context)

    def test_create_network_provider_physical_network(self):
        """Project member cannot specify provider phyical networks"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:provider:physical_network', self.target, self.context)

    def test_create_network_provider_segmentation_id(self):
        """Project member cannot specify provider segmentation IDs"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:provider:segmentation_id', self.target, self.context)

    def test_delete_network(self):
        """Project member can delete networks"""
        self.assertTrue(self.enforce('delete_network', self.target, self.context))
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'delete_network', self.alt_target, self.context)


class DomainMemberNetworkPolicyTests(base.PolicyTestsBase):
    """
    Checks policy enforcement for the member role.
    """

    def setUp(self):
        """Perform setup actions for all tests"""
        self.setup(network.get_enforcer())
        self.context = self.domain_member_context

    def test_create_network(self):
        """Domain member cannot create networks"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network', self.target, self.context)

    def test_create_network_segments(self):
        """Domain member cannot specifiy network segments"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:segments', self.target, self.context)

    def test_create_network_provider_network_type(self):
        """Domain member cannot specify provider network types"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:provider:network_type', self.target, self.context)

    def test_create_network_provider_physical_network(self):
        """Domain member cannot specify provider phyical networks"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:provider:physical_network', self.target, self.context)

    def test_create_network_provider_segmentation_id(self):
        """Domain member cannot specify provider segmentation IDs"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:provider:segmentation_id', self.target, self.context)

    def test_delete_network(self):
        """Project member can delete networks"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'delete_network', self.target, self.context)

# vi: ts=4 et:
