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

from unikorn_openstack_policy import compute
from unikorn_openstack_policy.tests import base

class ProjectAdminComputePolicyTests(base.PolicyTestsBase):
    """
    Checks policy enforcement for project scoped admin role.
    """

    # Request context.
    context = None

    def setUp(self):
        """Perform setup actions for all tests"""
        self.setup(compute.get_enforcer())
        self.context = self.project_admin_context

    def test_update_quota_sets(self):
        """Admin can update quota sets"""
        self.assertTrue(self.enforce(
            'os_compute_api:os-quota-sets:update', self.target, self.context))


class DomainAdminComputePolicyTests(ProjectAdminComputePolicyTests):
    """
    Checks policy enforcement for domain scoped admin role
    """

    def setUp(self):
        self.setup(compute.get_enforcer())
        self.context = self.domain_admin_context


class ProjectManagerComputePolicyTests(base.PolicyTestsBase):
    """
    Checks policy enforcement for project scoped manager role
    """

    # Request context.
    context = None

    def setUp(self):
        """Perform setup actions for all tests"""
        self.setup(compute.get_enforcer())
        self.context = self.project_manager_context

    def test_update_quota_sets(self):
        """Project manager can update quota sets"""
        self.assertTrue(self.enforce(
            'os_compute_api:os-quota-sets:update', self.target, self.context))
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'os_compute_api:os-quota-sets:update', self.alt_target, self.context)


class DomainManagerComputePolicyTests(base.PolicyTestsBase):
    """
    Checks policy enforcement for the manager role.
    """

    def setUp(self):
        """Perform setup actions for all tests"""
        self.setup(compute.get_enforcer())
        self.context = self.domain_manager_context

    def test_update_quota_sets(self):
        """Domain manager cannot update quota sets"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'os_compute_api:os-quota-sets:update', self.target, self.context)
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'os_compute_api:os-quota-sets:update', self.alt_target, self.context)


class ProjectMemberComputePolicyTests(base.PolicyTestsBase):
    """
    Checks policy enforcement for the member role.
    """

    def setUp(self):
        """Perform setup actions for all tests"""
        self.setup(compute.get_enforcer())
        self.context = self.project_member_context

    def test_update_quota_sets(self):
        """Project member cannot create quota sets"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'os_compute_api:os-quota-sets:update', self.target, self.context)


class DomainMemberComputePolicyTests(base.PolicyTestsBase):
    """
    Checks policy enforcement for the member role.
    """

    def setUp(self):
        """Perform setup actions for all tests"""
        self.setup(compute.get_enforcer())
        self.context = self.domain_member_context

    def test_update_quota_sets(self):
        """Domain member cannot create quota sets"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                'os_compute_api:os-quota-sets:update', self.target, self.context)

# vi: ts=4 et:
