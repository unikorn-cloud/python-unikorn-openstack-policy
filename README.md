# Unikorn OpenStack Policy Generator

![Unikorn Logo](https://raw.githubusercontent.com/unikorn-cloud/assets/main/images/logos/light-on-dark/logo.svg#gh-dark-mode-only)
![Unikorn Logo](https://raw.githubusercontent.com/unikorn-cloud/assets/main/images/logos/dark-on-light/logo.svg#gh-light-mode-only)

## Overview

Oslo policy generation and testing framework.

### Network Service

We need the following to be allowed (non-root):

* Provisioning of provider networks in managed projects

Problem with Neutron is, it has zero view of identity hierarchies.
When you create a network, for example, it infers the network from the token, and that's it.
There is no way to infer the domain also and allow access at that level.
This may, in fact, although not proven, go all the way back to Keystone not encoding this hierarchical information in the token.
Which then, basically, says that Keystone's encoding of scope in a token is totally stupid in the first place, and should be way more generalized, because having to re-authenticate in multiple scopes is a massive butt pain.

Then, after you consider the lack of decent support for scoped policies, there is the fact that provisioning with a specific project ID is not even handled by policies at all, but hard coded, then we are in a world of pain.

Our only remaining option is to take our domain admin `manager` role, and create a role on every project we create.
Then when we want to create a network, we need to create a token bound to that project.
Finally, we need to allow the `manager` to create provider networks in the project.

## Usage

You first need to create a non-admin role to perform all the necessary actions.
Unikorn already requires the [SCS domain admin](https://docs.scs.community/standards/scs-0302-v1-domain-manager-role/) functionality for reduced privilege user/project creation, so we use the same role.
As an admin account:

```bash
openstack role create manager
```

Assuming a user has then been created, with the `manager` role on a domain, authenticate as that user scoped to the managed domain, then create a project/user:

```bash
openstack project create --domain my-managed-domain my-project
openstack user create --domain my-managed-domain my-user
```

Then to actually provision a provider network you need to bind the `manager` role to the project:

```bash
openstack role add --user my-manager-user --domain my-managed-domain --project my-project manager
```

At this point, you must have [installed](#installation) the policies we define in this library, though whatever mechanism your orchestration layer provides.
Re-authenticate as the `manager` user, now scoped to the project, and create the network:

```bash
openstack network create --provider-network-type vlan --provider-physical-network physnet1 --provider-segment 666 my-provider-network
```

Then, after all that, take a step back and assess your life choices and whether you should be using OpenStack in the first place...

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
oslopolicy-policy-generator --namespace unikorn_openstack_policy
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
