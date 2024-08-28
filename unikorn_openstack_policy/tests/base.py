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

class PolicyTestsBase(unittest.TestCase):
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

    def setup(self, enforcer):
        """Perform setup actions for all tests"""

        # Setup the configuration, which is required for policy file loading...
        cfg.CONF(args=[])

        # We only expose our rules and rules we've directly inherited in the
        # enforcer defaults, so we need to add any base rules.
        self.enforcer = enforcer
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
