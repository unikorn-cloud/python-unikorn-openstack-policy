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

import unittest
import uuid

from oslo_policy import policy
from oslo_config import cfg
from oslo_context.context import RequestContext

from unikorn_openstack_policy import get_enforcer

class NetworkPolicyTestsBase(unittest.TestCase):
    """
    Base functionality for all suites.
    """

    # pylint: disable=too-many-instance-attributes

    # This is static across all tests so needs configuring once.
    enforcer = None
    # The domain of the user, if scoped to it.
    domain_id = None
    # The project of the user, if scoped to it.
    project_id = None
    # Project scoped admin context.
    project_admin_context = None
    # Project scoped manager context.
    project_manager_context = None
    # Project scoped member context.
    project_member_context = None
    # Domain scoped admin context.
    domain_admin_context = None
    # Domain scoped manager context.
    domain_manager_context = None
    # Domain scoped member context.
    domain_member_context = None
    # Target that corresponds to the user's scope.
    target = None
    # Alternate target that isn't in the user's domain or project.
    alt_target = None

    def setUp(self):
        """Perform setup actions for all tests"""

        # Setup the configuration, which is required for policy file loading...
        cfg.CONF(args=[])

        self.enforcer = get_enforcer()
        self.enforcer.load_rules()

        # Set up share helper objects.
        self.domain_id = uuid.uuid4().hex
        self.project_id = uuid.uuid4().hex

        self._setup_project_scoped_personas()
        self._setup_domain_scoped_personas()

        self.target = {
                'domain_id': self.domain_id,
                'project_id': self.project_id,
        }
        self.alt_target = {
                'domain_id': uuid.uuid4().hex,
                'project_id': uuid.uuid4().hex,
        }

    def _setup_project_scoped_personas(self):
        """Create project scoped contexts"""
        self.project_admin_context = RequestContext(
                roles=['admin', 'member', 'reader'],
                project_id=self.project_id)
        self.project_manager_context = RequestContext(
                roles=['manager'],
                project_id=self.project_id)
        self.project_member_context = RequestContext(
                roles=['member', 'reader'],
                project_id=self.project_id)

    def _setup_domain_scoped_personas(self):
        """Create domain scoped contexts"""
        self.domain_admin_context = RequestContext(
                roles=['admin', 'member', 'reader'],
                domain_id=self.domain_id)
        self.domain_manager_context = RequestContext(
                roles=['manager'],
                domain_id=self.domain_id)
        self.domain_member_context = RequestContext(
                roles=['member', 'reader'],
                domain_id=self.domain_id)

    def enforce(self, action, target, context):
        """
        Wraps up common code for enforcement to reduce duplication.
        """

        rule = policy.RuleCheck('rule', action)

        return self.enforcer.enforce(rule=rule, target=target, creds=context, do_raise=True)


class ProjectAdminNeworkPolicyTests(NetworkPolicyTestsBase):
    """
    Checks policy enforcement for project scoped admin role.
    """

    # Request context.
    context = None

    def setUp(self):
        """Perform setup actions for all tests"""
        super().setUp()
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


class DomainAdminNeworkPolicyTests(ProjectAdminNeworkPolicyTests):
    """
    Checks policy enforcement for domain scoped admin role
    """

    def setUp(self):
        super().setUp()
        self.context = self.domain_admin_context


class ProjectManagerNetworkPolicyTests(NetworkPolicyTestsBase):
    """
    Checks policy enforcement for project scoped manager role
    """

    # Request context.
    context = None

    def setUp(self):
        """Perform setup actions for all tests"""
        super().setUp()
        self.context = self.project_manager_context

    def test_create_network(self):
        """Project manager cannot create networks"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network', self.target, self.context)

    def test_create_network_segments(self):
        """Project manager cannot specify network segments"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:segments', self.target, self.context)

    def test_create_network_provider_network_type(self):
        """Project manager cannot specify provider network types"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:provider:network_type', self.target, self.context)

    def test_create_network_provider_physical_network(self):
        """Project manager cannot specify provider phyical networks"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:provider:physical_network', self.target, self.context)

    def test_create_network_provider_segmentation_id(self):
        """Project manager cannot specify provider segmentation IDs"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:provider:segmentation_id', self.target, self.context)

    def test_delete_network(self):
        """Project manager cannot delete networks"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'delete_network', self.target, self.context)


class DomainManagerNeworkPolicyTests(NetworkPolicyTestsBase):
    """
    Checks policy enforcement for the manager role.
    """

    def setUp(self):
        """Perform setup actions for all tests"""
        super().setUp()
        self.context = self.domain_manager_context

    def test_create_network(self):
        """Domain manager can create networks in its domain"""
        self.assertTrue(self.enforce('create_network', self.target, self.context))
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network', self.alt_target, self.context)

    def test_create_network_segments(self):
        """Domain manager can specifiy network segments"""
        self.assertTrue(self.enforce('create_network:segments', self.target, self.context))
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:segments', self.alt_target, self.context)

    def test_create_network_provider_network_type(self):
        """Domain manager can specify provider network types"""
        self.assertTrue(
                self.enforce('create_network:provider:network_type', self.target, self.context))
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:provider:network_type', self.alt_target, self.context)

    def test_create_network_provider_physical_network(self):
        """Domain manager can specify provider phyical networks"""
        self.assertTrue(
                self.enforce('create_network:provider:physical_network', self.target, self.context))
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:provider:physical_network', self.alt_target, self.context)

    def test_create_network_provider_segmentation_id(self):
        """Domain manager can specify provider segmentation IDs"""
        self.assertTrue(
                self.enforce('create_network:provider:segmentation_id', self.target, self.context))
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'create_network:provider:segmentation_id', self.alt_target, self.context)

    def test_delete_network(self):
        """Domain manager cannot create networks"""
        self.assertTrue(self.enforce('delete_network', self.target, self.context))
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'delete_network', self.alt_target, self.context)


class ProjectMemberNeworkPolicyTests(NetworkPolicyTestsBase):
    """
    Checks policy enforcement for the member role.
    """

    def setUp(self):
        """Perform setup actions for all tests"""
        super().setUp()
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


class DomainMemberNeworkPolicyTests(NetworkPolicyTestsBase):
    """
    Checks policy enforcement for the member role.
    """

    def setUp(self):
        """Perform setup actions for all tests"""
        super().setUp()
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
