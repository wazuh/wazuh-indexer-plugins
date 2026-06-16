# GitHub Actions Cost Analysis

Using the data exported from the GitHub Actions billing page of each repository. Confirm the exact billing period date range in the GitHub console before using projections.

Average time per run is total billed minutes divided by number of runs. For workflows with parallel jobs, billed minutes accumulate across all concurrent jobs, not wall-clock time.

| Runner | Specs | Rate |
|--------|-------|------|
| Standard | 2-core, ubuntu-24.04 | $0.008 per min |
| Larger (wz-linux-amd64, wz-linux-arm64) | 8-core, Ubuntu, confirmed from org runner settings | $0.032 per min |

Only **wazuh-indexer** uses the 8-core custom runners. All other repositories use the standard 2-core runner, confirmed by grepping workflow files across all repos.

---

## Cost Per Workflow

Grouped by repository, sorted by estimated cost within each group. Repository names are shortened for readability.

| Workflow | Repository | Runs | Avg Time | Total Min | Runner | Est. Cost |
|---------|-----------|------|---------|-----------|--------|-----------|
| 5_builderpackage_indexer.yml | indexer | 66 | 73.6 min | 4,857 | 8-core | $155.42 |
| dynamic/github-code-scanning/codeql | indexer | 53 | 15.5 min | 820 | 2-core | $6.56 |
| codeql-analysis.yml | indexer | 44 | 14.2 min | 626 | 2-core | $5.01 |
| 5_builderpackage_docker.yml | indexer | 1 | 104.0 min | 104 | 8-core | $3.33 |
| codeql.yml | indexer | 8 | 18.3 min | 146 | 2-core | $1.17 |
| 5_codequality_signed_commits.yml | indexer | 45 | 1.0 min | 45 | 2-core | $0.36 |
| 5_codequality_changelog.yml | indexer | 45 | 1.0 min | 45 | 2-core | $0.36 |
| 5_codequality_email.yml | indexer | 45 | 1.0 min | 45 | 2-core | $0.36 |
| 4_builderpackage_indexer.yml | indexer | 2 | 15.0 min | 30 | 2-core | $0.24 |
| dynamic/agents/copilot-pull-request-reviewer | indexer + plugins | 2 | 4.5 min | 9 | 2-core | $0.07 |
| 5_testunit_version.yml | indexer | 8 | 1.0 min | 8 | 2-core | $0.06 |
| 4_codequality_changelog.yml | indexer | 1 | 1.0 min | 1 | 2-core | $0.01 |
| 5_builderpackage_plugins_onpush.yml | plugins | 84 | 12.5 min | 1,052 | 2-core | $8.42 |
| 5_codequality_codeql.yml | plugins | 104 | 4.0 min | 415 | 2-core | $3.32 |
| 5_codequality_links.yml | plugins | 210 | 1.0 min | 214 | 2-core | $1.71 |
| 5_codequality_changelog.yml | plugins | 202 | 1.0 min | 202 | 2-core | $1.62 |
| 5_codequality_api_docs.yml | plugins | 186 | 1.0 min | 186 | 2-core | $1.49 |
| 5_builderpackage_schema.yml | plugins | 18 | 2.1 min | 37 | 2-core | $0.30 |
| codeql.yml | plugins | 6 | 4.2 min | 25 | 2-core | $0.20 |
| 5_codequality_email.yml | plugins | 18 | 1.0 min | 18 | 2-core | $0.14 |
| 5_codequality_signed_commits.yml | plugins | 18 | 1.0 min | 18 | 2-core | $0.14 |
| links.yml | plugins | 17 | 1.0 min | 17 | 2-core | $0.14 |
| 5_testintegration_gradlecheck.yml | plugins | 1 | 12.0 min | 12 | 2-core | $0.10 |
| 5_builderpackage_docs.yml | plugins | 10 | 1.0 min | 10 | 2-core | $0.08 |
| 5_builderpackage_security-analytics_onpush.yml | security-analytics | 33 | 7.7 min | 253 | 2-core | $2.02 |
| 5_testintegration_gradlecheck.yml | security-analytics | 15 | 11.4 min | 171 | 2-core | $1.37 |
| 5_codequality_email.yml | security-analytics | 32 | 1.0 min | 32 | 2-core | $0.26 |
| 5_codequality_changelog.yml | security-analytics | 32 | 1.0 min | 32 | 2-core | $0.26 |
| 5_codequality_signed_commits.yml | security-analytics | 32 | 1.0 min | 32 | 2-core | $0.26 |
| codeql.yml | security-analytics | 2 | 6.0 min | 12 | 2-core | $0.10 |
| 5_codequality_links.yml | security-analytics | 2 | 1.0 min | 2 | 2-core | $0.02 |
| 5_builderpackage_alerting_on_push.yml | alerting | 13 | 6.2 min | 81 | 2-core | $0.65 |
| 5_testintegration_gradlecheck.yml | alerting | 5 | 5.8 min | 29 | 2-core | $0.23 |
| 5_codequality_signed_commits.yml | alerting | 19 | 1.0 min | 19 | 2-core | $0.15 |
| 5_codequality_changelog.yml | alerting | 19 | 1.0 min | 19 | 2-core | $0.15 |
| codeql.yml | alerting | 2 | 7.5 min | 15 | 2-core | $0.12 |
| 5_codequality_email.yml | alerting | 15 | 1.0 min | 15 | 2-core | $0.12 |
| 5_builderpackage_alerting.yml | alerting | 2 | 6.0 min | 12 | 2-core | $0.10 |
| 5_codequality_links.yml | alerting | 7 | 1.0 min | 7 | 2-core | $0.06 |
| links.yml | alerting | 1 | 1.0 min | 1 | 2-core | $0.01 |
| 5_builderpackage_common_utils_on_push.yml | common-utils | 15 | 3.8 min | 57 | 2-core | $0.46 |
| 5_testunit_common_utils.yml | common-utils | 27 | 2.1 min | 56 | 2-core | $0.45 |
| 5_codequality_signed_commits.yml | common-utils | 24 | 1.0 min | 24 | 2-core | $0.19 |
| 5_codequality_changelog.yml | common-utils | 24 | 1.0 min | 24 | 2-core | $0.19 |
| 5_codequality_email.yml | common-utils | 16 | 1.0 min | 16 | 2-core | $0.13 |
| codeql.yml | common-utils | 2 | 4.0 min | 8 | 2-core | $0.06 |
| 5_codequality_links.yml | common-utils | 5 | 1.4 min | 7 | 2-core | $0.06 |
| 5_builderpackage_common_utils.yml | common-utils | 1 | 4.0 min | 4 | 2-core | $0.03 |
| 5_testintegration_gradlecheck.yml | common-utils | 1 | 3.0 min | 3 | 2-core | $0.02 |
| links.yml | common-utils | 1 | 1.0 min | 1 | 2-core | $0.01 |
| 5_builderpackage_notifications_onpush.yml | notifications | 9 | 18.1 min | 163 | 2-core | $1.30 |
| codeql.yml | notifications | 2 | 11.5 min | 23 | 2-core | $0.18 |
| dynamic/github-code-scanning/codeql | notifications | 22 | 1.0 min | 22 | 2-core | $0.18 |
| 5_codequality_changelog.yml | notifications | 20 | 1.0 min | 20 | 2-core | $0.16 |
| 5_codequality_email.yml | notifications | 20 | 1.0 min | 20 | 2-core | $0.16 |
| 5_codequality_signed_commits.yml | notifications | 20 | 1.0 min | 20 | 2-core | $0.16 |
| 5_testintegration_gradlecheck.yml | notifications | 1 | 10.0 min | 10 | 2-core | $0.08 |
| 5_codequality_links.yml | notifications | 2 | 1.0 min | 2 | 2-core | $0.02 |
| codeql.yml | reporting | 9 | 8.0 min | 72 | 2-core | $0.58 |
| 5_builderpackage_reporting_onpush.yml | reporting | 2 | 6.5 min | 13 | 2-core | $0.10 |
| 5_codequality_signed_commits.yml | reporting | 10 | 1.0 min | 10 | 2-core | $0.08 |
| 5_codequality_email.yml | reporting | 10 | 1.0 min | 10 | 2-core | $0.08 |
| 5_codequality_changelog.yml | reporting | 10 | 1.0 min | 10 | 2-core | $0.08 |
| 5_codequality_links.yml | reporting | 2 | 2.0 min | 4 | 2-core | $0.03 |
| dynamic/dependabot/dependabot-updates | all repos | 25 | 1.2 min | 29 | 2-core | $0.23 |
| 5_bumper_repository.yml | all repos | 9 | 1.2 min | 11 | 2-core | $0.09 |
| **TOTAL** | | | | **10,308** | | **$201.52** |

---

## Historical Consumption

| Repository | Total Runs | Total Minutes | Est. Cost |
|-----------|-----------|--------------|-----------|
| wazuh-indexer | 325 | 6,738 | $172.97 |
| wazuh-indexer-plugins | 882 | 2,218 | $17.74 |
| wazuh-indexer-security-analytics | 153 | 539 | $4.31 |
| wazuh-indexer-notifications | 99 | 283 | $2.26 |
| wazuh-indexer-common-utils | 121 | 205 | $1.64 |
| wazuh-indexer-alerting | 86 | 201 | $1.61 |
| wazuh-indexer-reporting | 48 | 124 | $0.99 |
| **Total** | **1,714** | **10,308** | **$201.52** |

Annualized estimate (using the one month export as a basis): **$2,418 per year**.
> This cost was taken from the historical before the new _skip on Draft PR_ criteria was implemented for our workflows.
