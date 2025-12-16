## Wazuh template for stateless indices

This is the **base template** for all stateless indices. It contains the complete set of Elastic Common Schema (ECS) fields and serves as the foundation to avoid duplication across other stateless index types.

All other stateless index templates inherit and reference the field definitions from this template to maintain consistency and reduce redundancy across the creation of the indices process.

### Fields summary

For this stage, we are using all the fields of the ECS. Dynamic mode is temporarily set to `false` to avoid the creation of new fields while allowing the indexing of events containing fields not in the schema. These fields can be retrieved from the original event (`_source`).

- [ECS main mappings](https://github.com/elastic/ecs/blob/v9.1.0/schemas/subsets/main.yml)

The detail of the fields can be found in csv file [Stateless Fields](fields.csv).