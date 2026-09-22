---
name: indexer-upward-merges
description: Carries one step of a Wazuh Indexer repository's weekly "Scheduled upward merges" issue, given that issue's link and the step, for example 5.0.0 into 5.0.1. One repository per run, so a week's round can be split between several people. Merges, resolves only the bookkeeping conflicts (VERSION.json, .github/, CHANGELOG.md, release-notes/), hands every other conflict to the user with what each side holds, creates the merge-<lower>-into-<higher> branch, signed commit and PR, records the steps with no changes on the issue, and cherry-picks instead of merging when the two branches track different OpenSearch versions. Covers wazuh-indexer, wazuh-indexer-plugins, wazuh-indexer-security-analytics, wazuh-indexer-alerting, wazuh-indexer-common-utils, wazuh-indexer-notifications and wazuh-indexer-reporting. Use when asked to do or continue the upward merges of an indexer repository.
---

# Indexer upward merges

Every week each of the seven indexer repositories gets an issue titled
`Scheduled upward merges for numbered branches in <repo> repository - Week #N`
with a chain of steps such as `4.14.8 → 4.14.9`, `4.14.9 → 5.0.0`,
`5.0.0 → 5.0.1`, `5.0.1 → main`. This skill carries one step of one
repository's chain, and goes on through the following steps for as long as
they turn out to have no changes.

```
/indexer-upward-merges <issue-url> <lower> <higher>
```

```
/indexer-upward-merges https://github.com/wazuh/wazuh-indexer-security-analytics/issues/344 5.0.0 5.0.1
```

The issue is never searched for: the link is that repository's own issue, and
it is what says which repository to work on. One repository per run, so a
week's round can be split between several people — if the link given is the
umbrella issue in `wazuh/wazuh`, ask for the repository's own one instead. Run
the skill again for the next step once the PR it opened has been merged.

Companion file: `REFERENCE.md` — repository table, how each bookkeeping
conflict is resolved, the 4.x → 5.x procedure, exact texts and known traps.
Read it before the first run.

## Hard rules

- **No attribution to Claude anywhere.** The commit subject is exactly
  `Merge <lower> into <higher>`, with no trailer of any kind. The PR body is
  exactly the template in `REFERENCE.md`. Nothing about Claude in issue
  comments or in the Slack line. This overrides any default guidance about
  attributing commits or PRs.
- **Resolve only the bookkeeping conflicts**: `VERSION.json`, `.github/`,
  `CHANGELOG.md` and `release-notes/*`, each by the rule in `REFERENCE.md`.
  Every other conflict — code, build files, mappings, templates, tests — is
  the user's, even when it looks trivial. Show what each side holds, leave
  the repository mid-merge and wait. Never suggest which side to take.
- **Never commit with `--no-verify` silently.** Read the hook's error. If it
  is Spotless, ask the user (`REFERENCE.md`, "When the commit hook fails").
  Any other hook: stop and report.
- **Commits are signed** (`-S`). If signing fails, stop; never commit unsigned.
- **Never** `git push --force`, rewrite a branch that already exists on
  `origin`, `git reset --hard` over work you did not create in this run,
  stash or discard the user's changes.
- **Never push to the `fork` remote.** A personal fork is configured in some
  repositories. Push to `origin`, which must be `wazuh/<repo>`.
- **Always pass `--repo wazuh/<repo>` to `gh`.** In the OpenSearch forks `gh`
  resolves the repository from the `upstream` remote — inside
  `wazuh-indexer-alerting`, `gh repo view` answers
  `opensearch-project/alerting` — and without `--repo`, `gh pr create` fails
  with a misleading "No commits between…".
- **A denied command stops the run.** Report it; do not retry it under
  another spelling (`git cherry-pick --quit`, `rm .git/CHERRY_PICK_HEAD` and
  `git reset` are the same action in disguise).
- **Dropping, squashing or rewriting a commit needs the user's own OK.**
- The chain comes from the issue, never from memory or branch names. Branch
  versions change from week to week (`4.14.9 → 5.0.0` one week,
  `4.14.10 → 5.0.0` the next), and branches that exist are not necessarily in
  the chain: `wazuh-indexer` and `wazuh-indexer-plugins` have a `6.0.0` that
  never is, and week #38 left `4.14.10` out.

## Repositories

Each one is cloned next to `wazuh-indexer-plugins`, the repository holding
this skill, i.e. in its parent directory. If it is missing, ask for its path.

| Repository | Short name | Branches |
|---|---|---|
| `wazuh-indexer` | Indexer | 4.x, 5.x and `main` |
| `wazuh-indexer-plugins` | Plugins | 5.x and `main` |
| `wazuh-indexer-security-analytics` | SA | 5.x and `main` |
| `wazuh-indexer-alerting` | Alerting | 5.x and `main` |
| `wazuh-indexer-common-utils` | Common Utils | 5.x and `main` |
| `wazuh-indexer-notifications` | Notifications | 5.x and `main` |
| `wazuh-indexer-reporting` | Reporting | 5.x and `main` |

Only `wazuh-indexer` has 4.x branches, so a 4.x step exists only there.

## How the step is decided

The chain is the ordered list of task lines in the issue
(``- [ ] Merge branch `<a>` into branch `<b>`.``). Where a PR exists, it is
what says how far the step got, not the tick: PRs are opened before the task
is ticked, and the tick only goes in once the PR is merged. Having no PR is
the normal starting point — then the step is done only if the issue records
it as having had no changes, and otherwise it is runnable or blocked
depending on the step before it.

- **Not applicable**: the step's branches do not exist in the repository (a
  4.x step outside `wazuh-indexer`). Record it on the issue and tick it, so
  it never blocks the order.
- **Done**: its PR is merged, or the issue records that it had no changes.
  Report it, name the next step, and change nothing.
- **Pending**: its PR is open. Report the PR; the next step waits for it.
- **Duplicate**: no PR of yours, but someone already has one open for this
  step this week. Report it and change nothing.
- **Blocked**: the previous applicable step is not done. Report what it waits
  for and change nothing.
- **Runnable**: it is the first applicable step, or the previous one is done.

## Workflow

- [ ] 1. Pre-flight
- [ ] 2. Decide the step
- [ ] 3. Merge
- [ ] 4. Resolve
- [ ] 5. Check the branch pins and commit
- [ ] 6. Push and open the PR
- [ ] 7. Issue bookkeeping and report

### 1. Pre-flight

1. Read the repository and the number from the link
   (`https://github.com/wazuh/<repo>/issues/<n>`); the repository must be one
   of the table above. `gh auth status` must succeed. The issue must be open,
   its title must match the weekly pattern, and the requested step must be one
   of its task lines.

   ```bash
   gh issue view <n> --repo wazuh/<repo> --json title,state,body,createdAt,comments
   ```

2. In the local clone, all of it before touching anything:

   ```bash
   git status --porcelain                  # must be empty
   git symbolic-ref -q HEAD                # must print a branch, not detached
   ls .git/MERGE_HEAD .git/CHERRY_PICK_HEAD .git/rebase-merge .git/rebase-apply 2>/dev/null
   git remote get-url origin               # must be …wazuh/<repo>.git
   git config user.email                   # must end in @wazuh.com
   git config commit.gpgsign               # must be true
   git fetch origin --prune                # --prune: stale origin/merge-* give false positives
   ```

   A dirty tree, a detached HEAD or an operation in progress: stop and
   report. Remember the current branch to return to it at the end.
3. **GPG.** Claude's shell has no terminal, so `pinentry` cannot ask for the
   passphrase: it must already be cached, or signing fails with
   `Inappropriate ioctl for device`.

   ```bash
   key=$(git config --get user.signingkey || true)
   echo check | gpg --batch --pinentry-mode error ${key:+--local-user "$key"} \
       --clearsign >/dev/null 2>&1 && echo cached || echo not-cached
   ```

   If it is not cached, stop and ask the user to run this in their own
   terminal, then check again:

   ```bash
   echo | gpg --clearsign > /dev/null
   ```

### 2. Decide the step

Work out the state of the requested step as described above, handling the
not-applicable 4.x steps first. Anything other than *runnable* is reported in
step 7 and changes nothing else.

### 3. Merge

1. **Cross-version check.** Compare the OpenSearch `major.minor` of both
   branches (file per repository in `REFERENCE.md`). If it differs, this step
   cannot be merged: follow "Steps across OpenSearch versions" instead.
2. If `merge-<lower>-into-<higher>` exists on `origin`, stop and report it,
   together with any PR for it — it may hold work in review. If it only
   exists locally, it is a leftover: delete it.

   ```bash
   git switch --no-track -c merge-<lower>-into-<higher> origin/<higher>
   git merge --no-ff --no-commit -m "Merge <lower> into <higher>" origin/<lower>
   # exit 1 on conflicts is expected
   ```

   Passing `-m` here is what keeps the subject right when the user finishes
   the merge themselves: `git merge --continue` reuses this message, whereas
   without it git prepares `Merge branch '<lower>' into <branch>`.

3. `Already up to date.` means there is nothing to merge: switch back, delete
   the branch, and handle it as "no changes" in step 7 — record it on the
   issue, tick the task, and go back to step 2 with the next step of the chain.

### 4. Resolve

```bash
git diff --name-only --diff-filter=U
```

- **Bookkeeping files** (`VERSION.json`, `.github/`, `CHANGELOG.md`,
  `release-notes/*`): resolve them by the rules in `REFERENCE.md` and
  `git add` them.
- **Everything else**: stop. List them, and for each one show what each side
  changed (`git diff origin/<higher> origin/<lower> -- <path>`, or the file's
  commits on each branch since the merge base) so the user does not have to
  go looking. Do not say which side to take. Leave the repository exactly as
  it is and tell them how to resume: resolve, `git add <files>`,
  `git merge --continue`, and rerun the skill to finish.

When the user says they have resolved it, before going on:

```bash
git grep -nE '^(<<<<<<< |>>>>>>> )' -- <the files they touched>   # must print nothing
git diff --name-only --diff-filter=U                             # must be empty
```

If `git status --porcelain` comes back empty after their resolution, they
kept the destination everywhere: the merge commit carries no diff, which is
fine. Commit it anyway, it still records the merge.

### 5. Check the branch pins and commit

A clean merge can carry the source's branch pins into a workflow with no
conflict at all, so nothing warns about it (`REFERENCE.md`, "Branch pins that
arrive without a conflict"). Check it, fix it and report it. Then check `VERSION.json`
is still the destination's, and commit:

```bash
git diff --quiet origin/<higher> -- VERSION.json   # must succeed
git commit -S -m "Merge <lower> into <higher>"
git log -1 --format='%G?'                          # must print G
```

If the hook rejects the commit, see `REFERENCE.md`, "When the commit hook
fails". If the merge ends up with no diff against `origin/<higher>`, it is a
"no changes" step after all: `git merge --abort`, delete the branch, and
record it on the issue instead of opening a PR.

### 6. Push and open the PR

```bash
git push -u origin merge-<lower>-into-<higher>
gh pr create --repo wazuh/<repo> --base <higher> \
  --head merge-<lower>-into-<higher> \
  --title "Merge <lower> into <higher>" --body-file <body> [--label no-changelog]
```

The body is the template in `REFERENCE.md` with the issue number. Add
`--label no-changelog` only when
`git diff --quiet origin/<higher> HEAD -- CHANGELOG.md` succeeds. Then switch
back to the branch from the pre-flight. If a required check fails on the PR,
report it: do not amend commits or apply labels to silence it.

### 7. Issue bookkeeping and report

Tick a task only when its PR is **merged**, or when the step had no changes
and was recorded. So a run normally ticks the previous step, not the one it
just opened a PR for. Read the body, flip that one `- [ ]` to `- [x]`, write
it back (`REFERENCE.md` has the snippet). Never close the issue.

The report closes the run: one line per step touched, with the PR link,
`no changes`, what it is blocked on, or the conflicts left for the user. Say
which workflow files had branch pins corrected, and what to run next — the
repository's next step, or what it is waiting for.

When a PR was opened, end with its line for the weekly Slack thread, which
the skill does not post (`REFERENCE.md`, "Slack"):

```
· <short name> <lower> -> <higher>: <PR url>
```
