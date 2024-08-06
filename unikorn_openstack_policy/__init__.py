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
Base library entrypoints.
"""

import itertools

from oslo_config import cfg
from oslo_policy import policy

from unikorn_openstack_policy import network

def list_rules():
    """Implements the "oslo.policy.policies" entry point"""

    return itertools.chain(
        network.list_rules(),
    )


def get_enforcer():
    """Implements the "oslo.policy.enforcer" entry point"""

    enforcer = policy.Enforcer(conf=cfg.CONF)
    enforcer.register_defaults(list_rules())

    return enforcer

# vi: ts=4 et:
