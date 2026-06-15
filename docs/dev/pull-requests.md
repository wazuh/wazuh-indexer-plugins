# Pull Requests

Standard procedures for creating, updating, and reviewing Pull Requests across the Wazuh Indexer repositories.

## PR lifecycle

```
┌──────────┐    ┌──────────────┐    ┌─────────────────┐    ┌───────┐
│  Draft   │───▶│ Local build  │───▶│ Ready for       │───▶│ Merge │
│  PR      │    │ & test       │    │ review (CI runs)│    │       │
└──────────┘    └──────────────┘    └─────────────────┘    └───────┘
```

### 1. Create the PR as Draft

All Pull Requests **must** be created in **Draft** status.

- Workflows **do not run on Draft PRs**. This is enforced across all repositories to avoid wasting GHA minutes on work in progress.
- Use Draft status freely while iterating on your changes.

### 2. Validate locally

Before marking the PR as ready:

- **Build** the project successfully.
- **Run the tests** locally and verify they pass.

This prevents avoidable CI failures that waste runner time and delay reviews.

### 3. Mark as Ready for Review

Once all changes are complete and locally validated:

1. Click **"Ready for review"** on the PR.
2. Move the linked issue to **Pending review**.

This is the moment workflows are triggered for the first time.

### 4. Address review feedback

- Push new commits to address reviewer comments.
- Re-request review after addressing all comments.

### 5. Merge

Once the PR is approved and CI passes, it can be merged. Use **squash merge** for single-purpose PRs to keep a clean history.

## Body template

Use the following template when creating a Pull Request:

```markdown
## Description

<!-- Brief description of the changes and the reasoning behind them. -->

Resolves #<issue_number>

## Checklist

- [ ] ...
```

### Guidelines for the body

- **Link the related issue** using `Resolves #<number>` so it auto-closes on merge.
- **Describe _why_**, not just _what_. The diff shows what changed; the description should explain the motivation.

## Updating a PR

- Push additional commits on top of the branch. Avoid amending or rebasing published commits during review.
- If CI fails after pushing new commits, investigate and fix before requesting re-review.

## Reviewing a PR

- **Check the linked issue** to understand the context and acceptance criteria.
- **Review the description and checklist** before reading the code.
- Focus feedback on correctness, clarity, and maintainability.
- Use GitHub's suggestion feature for small fixes to speed up the process.
- Approve only when you are confident the changes are correct and complete.

## Changelog

Every PR is expected to include a changelog entry. The `5_codequality_changelog.yml` workflow enforces this.

- If the linked issue belongs to a **private repository**, do not add a changelog entry. Apply the **`skip-changelog`** label to bypass the check.
- If the PR is linked to a public issue but genuinely does not require a changelog update, apply the **`skip-changelog`** label as well.

## Best practices

- **Keep PRs small and focused.** One issue per PR whenever possible.
- **Write descriptive commit messages.** They should explain _why_, not just _what_.
- **Do not trigger CI unnecessarily.** Keep PRs in Draft until ready; validate locally first.
