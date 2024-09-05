# Unikorn OpenStack Policy Generator

![Unikorn Logo](https://raw.githubusercontent.com/unikorn-cloud/assets/main/images/logos/light-on-dark/logo.svg#gh-dark-mode-only)
![Unikorn Logo](https://raw.githubusercontent.com/unikorn-cloud/assets/main/images/logos/dark-on-light/logo.svg#gh-light-mode-only)

## Overview

Oslo policy generation and testing framework.

### Compute Service

We need the following to be allowed (non-root):

* Management of quotas

### Network Service

We need the following to be allowed (non-root):

* Management of quotas
* Provisioning of provider networks in managed projects

### Design

Problem with any service that isn't Keystone is, it has zero view of identity hierarchies.
When you create a network, for example, it infers the project from the token, and that's it.
There is no way to infer the domain and allow access at that level.

Our only option is to take our domain admin `manager` role, and apply that role to every project we create and manage.
Then, when we want to create a network, we need to create a token bound to that project.
Finally, we need to allow the `manager` to create provider networks in the project.

## Usage

You first need to create a non-admin role to perform all the necessary actions.
Unikorn already requires the [SCS domain admin](https://docs.scs.community/standards/scs-0302-v1-domain-manager-role/) functionality for reduced privilege user/project creation, so we use the same role.

The SCS policies limit the roles that can be applied to projects by the manager, and are incompatible with how unikorn needs to work so you will want to update the following line:

```diff
-"is_domain_managed_role": "'member':%(target.role.name)s or 'load-balancer_member':%(target.role.name)s"
+"is_domain_managed_role": "'member':%(target.role.name)s or 'load-balancer_member':%(target.role.name)s or 'manager':%(target.role.name)s"
```

You may also need to add a `_member_` role if you are using an old version of OpenStack and this is required by Neutron to function.

[Install](#installation) the policies we define in this library, though whatever mechanism your orchestration layer provides.

### Testing

As an admin account:

```bash
openstack role create manager
```

Assuming a `domain-manager` user has then been created in a `managed-domain` domain with the `manager` role on that domain, authenticate as that user scoped to the managed domain, then create a managed project:

```bash
openstack project create --domain managed-domain managed-project
```

Then to actually use the policies defined here you need to bind the `manager` role to the project:

```bash
openstack role add --user domain-manager --domain managed-domain --project managed-project manager
```

Reauthenticate as the `domain-manager` scoped to the `managed-project` and try creating a provider network, which should succeed.

> [!NOTE]
> This obviously requires VLAN provider network support by the platform.
> You may also verify everything works by performing some quota updates.

```bash
openstack network create --provider-network-type vlan --provider-physical-network physnet1 --provider-segment 666 my-provider-network
```

### Installation

> [!NOTE]
> Running the following will install all the necessary dependencies.
> This also includes any commands required for the the following sections.

```bash
python3 -m build
pip3 install dist/python_unikorn_openstack_policy-0.1.0-py3-none-any.whl
```

### Generating Policy Files

```bash
oslopolicy-policy-generator --namespace unikorn_openstack_policy_compute
oslopolicy-policy-generator --namespace unikorn_openstack_policy_network
```

## Development

### Coding Standards

You require 10/10 when running:

```bash
pylint unikorn_openstack_policy
```

### Testing

You must test everything works and get 100% pass rate when running:

```bash
python3 -m unittest discover
```
