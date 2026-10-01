## `wazuh-states-inventory-services` index data model

### Fields summary

The fields are based on:

- [Inventory - Services mappings](https://github.com/wazuh/wazuh-agent/issues/807#issuecomment-3212090933) (included in 4.14.0)
- [States Persistence](https://github.com/wazuh/wazuh/issues/29840#issuecomment-2937251736) (included in 5.0.0)

Based on osquery and ECS:

- [services table (Windows)](https://osquery.io/schema/5.16.0/#services).
- [systemd_units table (Linux)](https://osquery.io/schema/5.16.0/#systemd_units).
- [launchd table (macOS)](https://osquery.io/schema/5.16.0/#launchd)
- [Service fields](https://www.elastic.co/docs/reference/ecs/ecs-service).

The detail of the fields can be found in csv file [Inventory Services Fields](fields.csv).

### Transition table

| #   | Custom | ECS Field Name                          | Type        | Source                                                      | OS Availability         | Description                                                              |
| --- | ------ | --------------------------------------- | ----------- | ----------------------------------------------------------- | ----------------------- | ------------------------------------------------------------------------ |
| 1   | 0      | `service.id`                            | `keyword`   | `services.name` / `systemd_units.id` / `label`              | Windows / Linux / macOS | Service/job unique identifier (Windows name, systemd id, launchd label). |
| 2   | 0      | `service.name`                          | `keyword`   | `services.display_name` / `name`                            | Windows / macOS         | Display name (Windows) or plist filename (macOS).                        |
| 3   | 1      | `service.description`                   | `keyword`   | `services.description` / `systemd_units.description`        | Windows / Linux         | Description of the service/unit.                                         |
| 4   | 0      | `service.type`                          | `keyword`   | `services.service_type` / `process_type`                    | Windows / macOS         | Type of service: OWN_PROCESS, driver, intended process type.             |
| 5   | 0      | `service.state`                         | `keyword`   | `services.status` / `systemd_units.active_state` / runtime  | Windows / Linux / macOS | Current state: RUNNING, STOPPED, active, running, etc.                   |
| 6   | 1      | `service.sub_state`                     | `keyword`   | `systemd_units.sub_state`                                   | Linux                   | Low-level systemd substate.                                              |
| 7   | 1      | `service.enabled`                       | `keyword`   | `systemd_units.unit_file_state` / `disabled` (invert)       | Linux / macOS           | Whether the unit/job is enabled.                                         |
| 8   | 1      | `service.start_type`                    | `keyword`   | `services.start_type` / `run_at_load`                       | Windows / macOS         | Start type: AUTO_START, DEMAND_START, or run_at_load.                    |
| 9   | 1      | `service.restart`                       | `keyword`   | `keep_alive`                                                | macOS                   | Restart policy: always / on-failure / never.                             |
| 10  | 1      | `service.frequency`                     | `long`      | `start_interval`                                            | macOS                   | Run frequency in seconds.                                                |
| 11  | 1      | `service.starts.on_mount`               | `boolean`   | `start_on_mount`                                            | macOS                   | Launches every time a filesystem is mounted.                             |
| 12  | 1      | `service.starts.on_path_modified`       | `keyword[]` | `watch_paths`                                               | macOS                   | Launches on path modification.                                           |
| 13  | 1      | `service.starts.on_not_empty_directory` | `keyword[]` | `queue_directories`                                         | macOS                   | Launches when directories become non-empty.                              |
| 14  | 1      | `service.inetd_compatibility`           | `boolean`   | `inetd_compatibility`                                       | macOS                   | Run job as if launched from inetd.                                       |
| 15  | 0      | `process.pid`                           | `long`      | `services.pid` / runtime                                    | Windows / macOS         | Process ID of the running service/job.                                   |
| 16  | 0      | `process.executable`                    | `keyword`   | `services.path` / `systemd_units.fragment_path` / `program` | Windows / Linux / macOS | Path to the service executable or unit definition.                       |
| 17  | 0      | `process.args`                          | `keyword[]` | `program_arguments`                                         | macOS                   | Command line arguments for the service/job.                              |
| 18  | 0      | `process.user.name`                     | `keyword`   | `services.user_account` / `systemd_units.user` / `username` | Windows / Linux / macOS | User account running the service/job.                                    |
| 19  | 0      | `process.group.name`                    | `keyword`   | `groupname`                                                 | macOS                   | Group account running the job.                                           |
| 20  | 0      | `process.working_directory`             | `keyword`   | `working_directory`                                         | macOS                   | Working directory of the job.                                            |
| 21  | 1      | `process.root_directory`                | `keyword`   | `root_directory`                                            | macOS                   | Chroot directory before execution.                                       |
| 22  | 0      | `file.path`                             | `keyword`   | `systemd_units.source_path` / `path`                        | Linux / macOS           | Path to the generated unit or `.plist` definition file.                  |
| 23  | 0      | `service.address`                       | `keyword`   | `services.module_path`                                      | Windows                 | Path to the service DLL (ServiceDll).                                    |
| 24  | 0      | `log.file.path`                         | `keyword`   | `stdout_path`                                               | macOS                   | Redirect stdout to a file/pipe.                                          |
| 25  | 1      | `error.log.file.path`                   | `keyword`   | `stderr_path`                                               | macOS                   | Redirect stderr to a file/pipe.                                          |
| 26  | 1      | `service.exit_code`                     | `integer`   | `services.service_exit_code`                                | Windows                 | Service-specific exit code on failure.                                   |
| 27  | 1      | `service.win32_exit_code`               | `integer`   | `services.win32_exit_code`                                  | Windows                 | Win32 exit code on start/stop.                                           |
| 28  | 1      | `service.following`                     | `keyword`   | `systemd_units.following`                                   | Linux                   | Unit followed by this unit in systemd.                                   |
| 29  | 1      | `service.object_path`                   | `keyword`   | `systemd_units.object_path`                                 | Linux                   | D-Bus object path of the unit.                                           |
| 30  | 0      | `service.target.ephemeral_id`           | `keyword`   | `systemd_units.job_id`                                      | Linux                   | Job ID assigned by systemd.                                              |
| 31  | 0      | `service.target.type`                   | `keyword`   | `systemd_units.job_type`                                    | Linux                   | Type of systemd job.                                                     |
| 32  | 0      | `service.target.address`                | `keyword`   | `systemd_units.job_path`                                    | Linux                   | Path to job object.                                                      |
