# Unikorn OpenStack Policy Generator

![Unikorn Logo](https://raw.githubusercontent.com/unikorn-cloud/assets/main/images/logos/light-on-dark/logo.svg#gh-dark-mode-only)
![Unikorn Logo](https://raw.githubusercontent.com/unikorn-cloud/assets/main/images/logos/dark-on-light/logo.svg#gh-light-mode-only)

## Overview

Oslo policy generation and testing framework.

## Installation

[!NOTE]
> Running the following will install all the necessary dependencies.
> This also includes any commands required for the the following sections.

```bash
python3 -m build
pip3 install --upgrade dist/python_unikorn_openstack_policy-0.1.0-py3-none-any.whl
```

## Generating Policy Files

```bash
oslopolicy-sample-generator --namespace unikorn_openstack_policy
```
