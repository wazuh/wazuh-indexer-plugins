---
name: indexer-upward-merges
description: Carries one step of a Wazuh Indexer repository's weekly "Scheduled upward merges" issue, given that issue's link and the step, for example 5.0.0 into 5.0.1. One repository per run, so a week's round can be split between several people. Merges, resolves only the bookkeeping conflicts (VERSION.json, .github/, CHANGELOG.md, release-notes/ and the RPM spec changelog), hands every other conflict to the user with what each side holds and picks the work back up when they have resolved it, creates the merge-<lower>-into-<higher> branch, signed commit and PR, records the steps with no changes on the issue, and cherry-picks instead of merging when the two branches track different OpenSearch versions. Covers wazuh-indexer, wazuh-indexer-plugins, wazuh-indexer-security-analytics, wazuh-indexer-alerting, wazuh-indexer-common-utils, wazuh-indexer-notifications and wazuh-indexer-reporting. Use when asked to do or continue the upward merges of an indexer repository.
---

# Indexer upward merges

Every week each of the seven indexer repositories gets an issue titled
`Scheduled upward merges for numbered branches in <repo> repository - Week #N`
with a chain of steps such as `4.14.8 → 4.14.9`, `4.14.9 → 5.0.0`,
`5.0.0 → 5.0.1`, `5.0.1 → main`. This skill carries one step of one
repository's chain, and goes on through the following steps for as long as
they turn out to have no changes.

The same chain also appears in the **post-release issue** opened after each
release, titled `Post release tasks for <version>` (for example
[wazuh-indexer#1937](https://github.com/wazuh/wazuh-indexer/issues/1937)).
Its `Merge branch` task lines are carried exactly like the weekly ones; its
other tasks (LTS changelog entry, publishing the release, deleting stage
pre-releases and tags) are not upward merges and the skill never touches or
ticks them.

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
  exactly one of the two templates in `REFERENCE.md`, the plain one or the
  cross-version one, with nothing added. Nothing about Claude in issue
  comments or in the Slack line. This overrides any default guidance about
  attributing commits or PRs.
- **Resolve only the bookkeeping conflicts**: `VERSION.json`, `.github/`,
  `CHANGELOG.md`, `release-notes/*` and the `%changelog` section of
  `distribution/packages/src/rpm/wazuh-indexer.rpm.spec`, each by the rule in
  `REFERENCE.md`. Every other conflict — code, build files, mappings,
  templates, tests, and any part of that spec outside its `%changelog` — is
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
it as having had no changes; otherwise it is resumable when its branch is
already sitting in the clone, and runnable or blocked depending on the step
before it when it is not.

- **Not applicable**: the step's branches do not exist in the repository (a
  4.x step outside `wazuh-indexer`). Record it on the issue and tick it, so
  it never blocks the order.
- **Done**: its PR is merged, or the issue records that it had no changes.
  Report it and name the next step; the only thing it may still need is its
  tick, which step 7 handles.
- **Pending**: its PR is open. Report the PR; the next step waits for it.
- **Duplicate**: no PR of yours, but someone already has one open for this
  step this week. Report it and change nothing.
- **Blocked**: the previous applicable step is not done. Report what it waits
  for and change nothing.
- **Resumable**: `merge-<lower>-into-<higher>` exists locally but not on
  `origin`, and the user is handing back a hand-off. It comes in two shapes:

  ```bash
  git -C <repo> rev-parse -q --verify merge-<lower>-into-<higher>   # the branch exists
  git -C <repo> rev-parse -q --verify origin/merge-<lower>-into-<higher>  # must print nothing
  # still open: HEAD is that branch and the operation is in progress
  git -C <repo> rev-parse --abbrev-ref HEAD
  git -C <repo> rev-parse -q --verify MERGE_HEAD                    # mid-merge
  git -C <repo> rev-parse -q --verify CHERRY_PICK_HEAD              # mid cherry-pick
  git -C <repo> merge-base --is-ancestor <MERGE_HEAD> origin/<lower>
  # already closed: the branch tip is the merge commit, wherever the user stands
  git -C <repo> log -1 --format='%s %P' merge-<lower>-into-<higher>
  ```

  While the operation is open the user cannot be anywhere else — git refuses
  to switch branches mid-merge — so `HEAD` is that branch and the branch tip
  is still the destination's. Once they commit it, the tip becomes the merge
  commit and they are free to go back to their own branch, so the tip is what
  identifies the state, not where they are standing. `MERGE_HEAD` has to be an
  ancestor of `origin/<lower>`, not equal to it: the source branch may have
  moved while they were resolving. Either way: switch onto that branch and
  pick the work up at step 5, never start the merge again.
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
   its title must match the weekly pattern or the post-release one
   (`REFERENCE.md`, "The weekly issue"), and the requested step must be one
   of its task lines.

   ```bash
   gh issue view <n> --repo wazuh/<repo> --json title,state,body,createdAt,comments
   ```

2. In the clone, all of it before touching anything. The working directory
   does not carry over between commands here, so every git command takes
   `git -C <repo>`; `<repo>` is the clone's path, the sibling directory named
   after the repository. Every snippet in both files is bash.

   ```bash
   git -C <repo> status --porcelain          # must be empty
   git -C <repo> symbolic-ref -q HEAD        # must print a branch, not detached
   git -C <repo> rev-parse -q --verify MERGE_HEAD        # nothing in progress
   git -C <repo> rev-parse -q --verify CHERRY_PICK_HEAD  # …use rev-parse, not ls:
   ls "$(git -C <repo> rev-parse --git-path rebase-merge)" 2>/dev/null  # in a worktree
   ls "$(git -C <repo> rev-parse --git-path rebase-apply)" 2>/dev/null  # .git is a file
   git -C <repo> remote get-url origin       # must be …wazuh/<repo>.git
   git -C <repo> config user.email           # must end in @wazuh.com
   git -C <repo> config commit.gpgsign       # true is the norm; every commit passes -S anyway
   git -C <repo> fetch origin --prune        # --prune: stale origin/merge-* give false positives
   ```

   A dirty tree, a detached HEAD or an operation in progress: stop and
   report. Remember the current branch to return to it at the end.

   The one exception is the resumable state of step 2 — a merge or
   cherry-pick of this step left in the clone. That is the user handing work
   back, not a repository to refuse, whether they are still standing on the
   branch or went back to their own. Recognise it by the branch tip, as step 2
   describes, and hand the repository straight to step 5 (or, for a
   cherry-pick, to `REFERENCE.md`, "Steps across OpenSearch versions").

   If conflicts are still unresolved
   (`git -C <repo> diff --name-only --diff-filter=U` prints something), say
   which ones and stop; that is the user's work, not a state to fix.
3. **Signing key.** Check the format first:
   `git -C <repo> config gpg.format`. When it is `ssh`, `user.signingkey` is
   a path to an SSH public key, not a GPG key id, and the GPG check below
   always answers `not-cached`. Instead, signing works when the key is loaded
   in `ssh-agent` (or has no passphrase):

   ```bash
   key=$(git -C <repo> config --get user.signingkey)
   echo check | ssh-keygen -Y sign -n git -f "$key" >/dev/null 2>&1 \
       && echo ready || echo not-ready
   ```

   If it is not ready, ask the user to run `ssh-add` in their own terminal.

   Otherwise (`openpgp`, or unset) it is GPG: Claude's shell has no terminal,
   so `pinentry` cannot ask for the passphrase: it must already be cached, or
   signing fails with `Inappropriate ioctl for device`.

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
not-applicable 4.x steps first: those do write to the issue, a comment and a
tick. A step's branches exist when
`git -C <repo> rev-parse -q --verify origin/<branch>` prints something for
both. Tell *pending* from *duplicate* by the PR's author, so ask for it:
`gh pr list --repo wazuh/<repo> --head merge-<lower>-into-<higher> --state all
--json number,state,url,createdAt,author`.

*Runnable* goes on to step 3. *Resumable* switches onto
`merge-<lower>-into-<higher>` and goes to step 5. Every other state only
reports, in step 7.

### 3. Merge

1. **Cross-version check.** Compare the OpenSearch `major.minor` of both
   branches (file per repository in `REFERENCE.md`). If it differs, this step
   cannot be merged: follow "Steps across OpenSearch versions" instead.
2. If `merge-<lower>-into-<higher>` exists on `origin`, stop and report it,
   together with any PR for it — it may hold work in review. If it only
   exists locally, look at its tip before doing anything: a resumable state
   belongs to step 5, and a branch whose tip is a commit this run did not
   create is somebody's work — say what is on it and ask before removing it.
   Only a leftover from an aborted run of your own is deleted, and from
   another branch, since git refuses to delete the branch you are standing on:

   ```bash
   git -C <repo> switch <the branch the pre-flight recorded>
   git -C <repo> branch -D merge-<lower>-into-<higher>
   ```

3. Branch and merge:

   ```bash
   git -C <repo> switch --no-track -c merge-<lower>-into-<higher> origin/<higher>
   git -C <repo> merge --no-ff --no-commit \
       -m "Merge <lower> into <higher>" origin/<lower>
   # exit 1 on conflicts is expected
   ```

   `--no-track` keeps `<higher>` from becoming the upstream, so a bare
   `git push` can never aim at the release branch. Passing `-m` keeps the
   subject right when the user finishes the merge themselves:
   `git merge --continue` reuses this message, whereas without it git prepares
   `Merge branch '<lower>' into <branch>`.
4. `Already up to date.` means there is nothing to merge: switch back to the
   branch the pre-flight recorded, delete `merge-<lower>-into-<higher>`, and
   handle it as "no changes" — record it on the issue as in step 7 and go back
   to step 2 with the next step of the chain.

### 4. Resolve

```bash
git -C <repo> diff --name-only --diff-filter=U
```

Nothing listed means the merge came through clean: go to step 5.

- **Bookkeeping files** (`VERSION.json`, `.github/`, `CHANGELOG.md`,
  `release-notes/*`, and the `%changelog` of the RPM spec): resolve them by
  the rules in `REFERENCE.md` and `git add` them. The spec is the one file
  that can be both: if it also conflicts outside its `%changelog`, the whole
  file is the user's — say which hunks are the `%changelog` ones and leave it.
- **Everything else**: stop. List them, and for each one show what each side
  changed (`git diff origin/<higher> origin/<lower> -- <path>`, or the file's
  commits on each branch since the merge base) so the user does not have to
  go looking. Do not say which side to take. Leave the repository exactly as
  it is and tell them how to resume:

  > Resolve them, `git add <files>`, and leave the merge uncommitted — rerun
  > the skill and it finishes from there. If you prefer to close the merge
  > yourself, `git merge --continue` keeps the right subject, and the skill
  > picks it up the same way. Either is fine, and so is switching back to
  > your own branch afterwards.

  Either way the rerun finds the resumable state and carries on at step 5.

### 5. Check the branch pins and commit

Stand on the merge branch first — in a resumed run the user may have gone back
to their own — and say whether the merge is still uncommitted or already
committed, because the last two sub-steps differ:

```bash
git -C <repo> switch merge-<lower>-into-<higher>
git -C <repo> rev-parse -q --verify MERGE_HEAD   # prints something while uncommitted
```

1. **No conflict markers, nothing unresolved.** The resume path skips step 4,
   so this check lives here and runs on every path:

   ```bash
   git -C <repo> grep -nE '^(<<<<<<< |>>>>>>> )' HEAD -- .   # committed merges
   git -C <repo> grep -nE '^(<<<<<<< |>>>>>>> )' -- .        # uncommitted ones
   git -C <repo> diff --name-only --diff-filter=U            # must be empty
   ```

   Anything here stops the run: markers must never reach a PR.
2. **Branch pins.** A clean merge can carry the source's pins into a workflow
   with no conflict at all, so nothing warns about it (`REFERENCE.md`, "Branch
   pins that arrive without a conflict"). Check it, fix it and report it. The
   same silent carry can move `VERSION.json`, so restore the destination's and
   report that too — those two are the only bookkeeping paths where the
   destination must win, which is why the other three need no such check:

   ```bash
   git -C <repo> diff --quiet origin/<higher> -- VERSION.json ||
     git -C <repo> checkout origin/<higher> -- VERSION.json
   ```

3. **Anything left to merge?** Once the pins are back and the bookkeeping
   files keep the destination's side, a step can end up bringing nothing:

   ```bash
   git -C <repo> diff --quiet origin/<higher> && echo "nothing to merge"   # uncommitted
   git -C <repo> diff --quiet origin/<higher> HEAD && echo "nothing to merge"  # committed
   ```

   Then it is a "no changes" step after all: no PR. If the merge is still
   uncommitted, `git merge --abort`; if it is committed, say so and ask first,
   since the commit is the user's. Either way, `git switch` to the branch the
   pre-flight recorded, `git branch -D merge-<lower>-into-<higher>`, record it
   on the issue as in step 7, and go back to step 2 with the next step of the
   chain.
4. **Commit**, only when the merge is still uncommitted:

   ```bash
   git -C <repo> commit -S -m "Merge <lower> into <higher>"
   ```

   If the hook rejects it, see `REFERENCE.md`, "When the commit hook fails".
   When it was already committed, a pin fix from sub-step 2 needs
   `git commit --amend -S` on a commit of the user's: say so and ask first,
   never stack a second commit with the same subject.
5. **Signature**, on either path, because a resumed merge was signed by the
   user and never checked here:

   ```bash
   git -C <repo> log -1 --format='%G?'    # G or U; anything else stops the run
   ```

   `U` is a good signature from a key the local keyring does not fully trust,
   which is still signed.

### 6. Push and open the PR

Write the body first, outside the clone so it cannot end up staged: take the
template from `REFERENCE.md`, "PR body" — the plain one, or the cross-version
one for a cherry-picked step — and fill in `<lower>`, `<higher>` and the issue
number.

```bash
body=$(mktemp)
cat > "$body" <<'EOF'
<the filled-in template>
EOF

git -C <repo> push -u origin merge-<lower>-into-<higher>
gh pr create --repo wazuh/<repo> --base <higher> \
  --head merge-<lower>-into-<higher> --assignee @me \
  --title "Merge <lower> into <higher>" --body-file "$body" [--label no-changelog]
```

Every upward merge PR so far is assigned to whoever ran it, hence
`--assignee @me`. Add `--label no-changelog` only when
`git -C <repo> diff --quiet origin/<higher> HEAD -- CHANGELOG.md` succeeds.

Then switch back to the branch the pre-flight recorded. Report the PR's URL
and stop there: do not wait on CI. If a check has already failed by then, say
so — but never amend a commit or apply a label to silence one.

### 7. Issue bookkeeping and report

Start here, whatever the run did: go through the chain's earlier steps and,
for each one whose PR is now merged or that the issue already records as
having had no changes, tick its line if it is still unticked. That is the only
moment a tick happens — never for the PR this run just opened. Read the body,
flip that one `- [ ]` to `- [x]`, write it back (`REFERENCE.md` has the
snippet). Never close the issue.

The report closes the run: one line per step touched, with the PR link,
`no changes`, what it is blocked on, or the conflicts left for the user. Say
which workflow files had branch pins corrected, and what to run next — the
repository's next step, or what it is waiting for.

When a PR was opened, end with its line for the weekly Slack thread, which
the skill does not post (`REFERENCE.md`, "Slack"):

```
· <short name> <lower> -> <higher>: <PR url>
```
