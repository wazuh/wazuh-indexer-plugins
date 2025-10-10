# Wazuh Common Schema

## Overview

The Wazuh Common Schema is a derivation of the [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) (ECS) providing a common data schema for the different central components of Wazuh.

The Wazuh Common Schema is structured in modules. For a detailed list of the available fields in a module and their description, please refer to the `docs/` folder of the module. For example, [states-inventory-packages](states-inventory-packages/docs/).

## References

- [ECS repository](https://github.com/elastic/ecs)
- [ECS usage](https://github.com/elastic/ecs/blob/main/USAGE.md)
- [ECS field reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)

## Developer guide

Refer to the [WCS generator documentation](./generator/README.md) for details on how to generate and update the Wazuh Common Schema.
