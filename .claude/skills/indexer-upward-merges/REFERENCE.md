# Indexer upward merges — reference

Details behind `SKILL.md`: where things live, how each bookkeeping conflict is
resolved, the procedure for steps across OpenSearch versions, the exact texts,
and the traps that already cost time.

## Repositories

| Repository | Fork of | OpenSearch version is declared in |
|---|---|---|
| `wazuh-indexer` | `opensearch-project/OpenSearch` | `buildSrc/version.properties` (`opensearch = 3.6.0`) |
| `wazuh-indexer-plugins` | — (Wazuh's own) | `plugins/content-manager/build.gradle` (`opensearch_version`) |
| `wazuh-indexer-security-analytics` | `opensearch-project/security-analytics` | `build.gradle` (`opensearch_version`; ignore `commons/build.gradle`) |
| `wazuh-indexer-alerting` | `opensearch-project/alerting` | `build.gradle` (`opensearch_version`) |
| `wazuh-indexer-common-utils` | `opensearch-project/common-utils` | `build.gradle` (`opensearch_version`) |
| `wazuh-indexer-notifications` | `opensearch-project/notifications` | `notifications/build.gradle` (`opensearch_version`) |
| `wazuh-indexer-reporting` | `opensearch-project/reporting` | `build.gradle` (`opensearch_version`) |

Read it without checking anything out:

```bash
git show origin/<branch>:<file> | grep -E 'opensearch(_version)?\s*='
```

Only `major.minor` matters. As of September 2026 every 4.x branch of
`wazuh-indexer` is on OpenSearch 2.19 and every 5.x branch and `main` of all
seven repositories is on 3.6, so the only step across versions is the
4.x → 5.x one of `wazuh-indexer`. Compare versions anyway instead of trusting
branch names. `wazuh-indexer-plugins` is not a fork of anything: its branches
share one history, so a plain merge is always right there.

Each repository's product version is the `version` field of `VERSION.json`.
`main` carries the next minor (`5.1.0` today), which is what makes it the top
of the chain, but branch and PR names always use branch names, never versions.

## The weekly issue

- The issue arrives as a link to that repository's own issue, never searched
  for. Read it with
  `gh issue view <n> --repo wazuh/<repo> --json title,state,body,createdAt,comments`.
  One repository per run is what lets the week's round be split between
  several people, each taking some repositories.
- There is also an umbrella issue in `wazuh/wazuh`, titled
  `Scheduled upward merges for numbered branches - Week #<N>`, listing every
  repository of every team with a link to its own issue; the indexer ones are
  the seven under `@wazuh/devel-xdrsiem-indexer`. It is where the links come
  from, but it is not what the skill takes: if it is given, ask for the
  repository's own issue instead.
- Each repository's issue is opened by the `wazuhci` bot, labelled
  `level/subtask`, `request/operational` and `type/maintenance`, and must be
  open, titled
  `Scheduled upward merges for numbered branches in <repo> repository - Week #<N>`.
  Anything else: stop and tell the user. Never open or close an issue.
- Task lines, in chain order: ``- [ ] Merge branch `<lower>` into branch `<higher>`.``
  The requested step must be one of them. The chain can leave out branches
  that exist (`6.0.0`, and week #38 skipped `4.14.10`).
- A step's PR belongs to this week when it was created after the issue. Branch
  names repeat every week, so always filter by date:
  `gh pr list --repo wazuh/<repo> --head merge-<lower>-into-<higher> --state all --json number,state,url,createdAt`.

Tick a task only once its PR is merged, or once a step with no changes has
been recorded. Use a literal replacement, since branch names contain dots:

```bash
old="- [ ] Merge branch \`$lower\` into branch \`$higher\`."
new="- [x] Merge branch \`$lower\` into branch \`$higher\`."
body=$(gh issue view "$issue" --repo "wazuh/$repo" --json body --jq .body)
[[ $body == *"$old"* ]] || { echo "task line not found"; exit 1; }
out=$(mktemp)                       # outside the clone, never inside it
printf '%s\n' "${body/"$old"/"$new"}" > "$out"
gh issue edit "$issue" --repo "wazuh/$repo" --body-file "$out"
```

Issue comments, word for word (read the comments first and never post one
twice):

| Situation | Comment |
|---|---|
| The repository has no 4.x branches | ``This repo does not have `4.x` so I'll start with `5.x` branches`` |
| A merge step with no changes | ``No changes needed from `<lower>` to `<higher>` `` |
| A cross-version step where nothing applies | ``No changes need to be migrated from `<lower>` to `<higher>` `` |

## PR body

Title `Merge <lower> into <higher>`, base `<higher>`, and this body with
nothing added before or after it:

```markdown
## Description

This PR merges changes from branch `<lower>` into branch `<higher>`

Related to #<issue>
```

A cross-version step uses this second template instead, the convention set by
[#1933](https://github.com/wazuh/wazuh-indexer/pull/1933), and nothing is added
to that one either:

```markdown
## Description

This PR merges changes from branch `<lower>` into branch `<higher>`

Related to #<issue>

## Proposed Changes

This link is not a plain `git merge`. `<lower>` tracks OpenSearch <x.y> and
`<higher>` tracks <x.y>, so merging the branches conflicts in thousands of
files. It is carried the way the previous merges of this kind were, by
cherry-picking the part of `<lower>` that applies to `<higher>`.

Cherry-picked: <sha> <subject>
Left out: <sha> <subject> (<why>)
```

The only label is `no-changelog`, and only when the merge does not touch
`CHANGELOG.md`. It exists in all seven repositories.

## Resolving the bookkeeping conflicts

These five are the only conflicts the skill resolves. Anything else belongs to
the user, however trivial it looks — a workflow is bookkeeping, a build file
is not.

| Path | Resolution |
|---|---|
| `VERSION.json` | Keep the destination's: `git checkout origin/<higher> -- VERSION.json`. Each branch owns its version and stage, and taking the incoming one downgrades the branch. |
| `.github/**` | Keep the destination's. Every branch pins its workflows to its own actions and sibling repositories, so the destination's file is the right one by definition. A genuine workflow improvement that has to travel upwards goes in its own PR, not inside a merge. |
| `CHANGELOG.md` | Union, keeping the destination's structure: its version headings and its `## Prior versions` section stay, and the incoming entries go under the matching `### Added` / `### Changed` / `### Fixed` / `### Removed` heading, with no duplicates. `tools/changelog_sync.sh` rewrites this file on bumps, so the two branches can be structurally different; the destination's shape wins. |
| `release-notes/*` | Additive lists — same union treatment. Only some repositories have them (not `wazuh-indexer` or `wazuh-indexer-plugins`). |
| `distribution/packages/src/rpm/wazuh-indexer.rpm.spec`, `%changelog` only | Union of the entries, and **the incoming side wins an entry both sides have** — this is the one rule that is not destination-wins. Release dates are corrected on the lower line and have to travel up. Anything in that spec outside `%changelog` is the user's. |

The spec's `%changelog` is worth a worked example, because it is the one that
inverts the rule and it conflicts in the plain merges of `wazuh-indexer`: all
three of week #38 hit it (#1929, #1930, #1931), and in #1929 it was the only
conflict in that file even though the merge changed 35 other lines of it.
In #1930 the destination (`5.0.1`) carried its own `5.0.1` entry and `4.14.8`
dated `Wed Sep 02 2026`; the source (`5.0.0`) had no `5.0.1` entry and `4.14.8`
dated `Wed Sep 23 2026`, the correction #1933 had just brought over from the
4.x line. The resolution keeps both: the destination's `5.0.1` entry and the
source's corrected `4.14.8` line. Destination-wins would have stranded that
correction below `main` for good.

In a cross-version step this is a judgement call instead, not a rule: #1933
took the `4.14.8` date from the 4.x line but deliberately left the `4.14.7` one
alone, because `5.0.0` already carried the corrected value.

After resolving them, and before staging anything else:

```bash
git grep -nE '^(<<<<<<< |>>>>>>> )' -- <the resolved files>   # must print nothing
```

## Branch pins that arrive without a conflict

A merge can carry the source's branch pins into a workflow **without any
conflict**: the source changed the reference lines, the destination changed
other lines of the same file, and git combines both sides happily. Nothing
warns about it, so check it before committing, with the merge still uncommitted:

```bash
for f in $(git diff --name-only origin/<higher> -- .github); do
    [ -f "$f" ] && grep -q -F "@<lower>" "$f" && echo "$f"
done
```

For each file it prints, read `git diff origin/<higher> -- <file>`. When the
only thing that moved are references to the source branch, take the
destination's file back and say so in the report:

```bash
git checkout origin/<higher> -- <file>
```

This is not hypothetical: in reporting's `5.0.1 → main` of September 2026 four
workflows came through cleanly and would have put seven `@5.0.1` references
into `main`. With the destination's files kept, that step turned out to have
no changes at all.

## When the commit hook fails

Where a repository ships `tools/pre-commit` (today `wazuh-indexer-plugins`,
`-security-analytics`, `-alerting` and `-common-utils`) and the user has copied
it into `.git/hooks` **and made it executable**, committing runs
`./gradlew spotlessCheck` over the whole tree. Without the execute bit git
ignores it and only prints `hint: The '.git/hooks/pre-commit' hook was ignored
because it's not set as executable`, so the same clone can behave differently
from another one. Read the output before reacting. Spotless is unmistakable:

```
> Task :spotlessJavaCheck FAILED
The following files had format violations:
      src/main/java/.../SigmaMitre.java
Run './gradlew :spotlessApply' to fix these violations.
```

Any other hook failure: stop and report it. For Spotless, take the file list
from that output and say which of those files are byte-identical to the source
branch (`git diff origin/<lower> -- <path>` is empty), because those violations
came in with the merge rather than from this branch. Then ask the user to
choose:

- **`--no-verify`** — commit the merge as it stands. Right when the violations
  are inherited: in `wazuh-indexer-plugins`, `-security-analytics` and
  `-common-utils`, `gradle/formatting.gradle` sets `enforceCheck false` under
  GitHub Actions, so Spotless never blocks CI there. Check the repository's own
  configuration before repeating that:
  `git -C <repo> grep -n "enforceCheck\|GITHUB_ACTIONS" origin/<higher> -- gradle/formatting.gradle`.
- **Apply Spotless** — commit the merge with `--no-verify` first, so the merge
  commit stays exactly what was resolved, then `./gradlew spotlessApply` and a
  second signed commit on top, which passes the hook by itself. Show the extent
  first: with `ratchetFrom 'origin/main'` it reformats every file that differs
  from `main`, not only the ones that failed.

Worth knowing when the user asks why this keeps happening: that ratchet is also
why the violations only show up during a merge. While `main` lags, the week's
files differ from it and are in scope; once the upward merges land, they match
`main` again and Spotless stops seeing them. In SA the scope was 13 Java files
before `main` caught up and 1 afterwards.

## Steps across OpenSearch versions

The 4.x → 5.x step of `wazuh-indexer` (for example `4.14.10 → 5.0.0`) cannot be
merged. Merging OpenSearch 2.19 into 3.6 conflicts in thousands of files —
2,493 when `4.14.9` was tried against `5.0.0` in September 2026 — and their
common ancestor is from 2022. It is carried by cherry-picking the few changes
that apply, as in #1706, #1784, #1802 and #1933.

1. **Candidates.** Everything on the source that was never reviewed for this
   destination: the union of two lists, because the source branch changes
   between rounds and is not linear (`4.14.10` does not contain the tip of
   `4.14.9`). Never use `<last sync>..origin/<lower>` as a range.

   ```bash
   last_sync=$(git log --first-parent origin/<higher> -E \
     --grep='^Merge 4\.[0-9.]+ into ' -1 --format='%cI %s')
   since=${last_sync%% *}
   prev_lower=$(sed -nE 's/^[^ ]+ Merge (4\.[0-9.]+) into .*/\1/p' <<<"$last_sync")

   # a) new on the source since that sync
   git log --first-parent origin/<lower> --after="$since" --reverse \
     --format='%h %cs %s  parents=%p'
   # b) only when prev_lower differs from <lower>: what the new source has
   #    and the previous one never had
   git log --first-parent "origin/$prev_lower..origin/<lower>" --reverse \
     --format='%h %cs %s  parents=%p'
   ```

   If there is no such marker on the destination, ask the user where to start.
   Do not guess, and never fall back to the repository's first commit.
   `--first-parent` is essential: it follows the branch's own mainline. Without
   it the list explodes into upstream OpenSearch commits — in the
   `4.14.9 → 5.0.0` step of week #38, 4 commits with it against 201 without,
   and 198 with `--no-merges`. List (b) is not optional either: when the step
   moved from `4.14.9` to `4.14.10` it held `Bump 4.14.10 branch (#1911)`,
   whose `%changelog` entry is exactly the kind of change that applies, and the
   date window alone missed it.
2. **Filter.** Leave out any commit with two parents (`parents=` shows two
   SHAs): it is an upstream bump of the 4.x line, such as
   `Migrate 4.14.8 to 2.19.6 (#1825)`, and cherry-picking it would drag in the
   history this whole procedure exists to avoid. Name it in the report anyway.
   Mark the commits whose `(#PR)` already appears in
   `git log --first-parent origin/<higher> --format=%s`, and the squashed
   upward merges into the source, which bundle commits from earlier rounds. If
   the list holds more than about fifteen commits, the base is wrong: stop and
   ask.
3. **Stop** and present the list. What usually applies: the `%changelog`
   entries of `distribution/packages/src/rpm/wazuh-indexer.rpm.spec` that 4.x
   bumps add. What does not: `VERSION.json` changes, features that already have
   their own 5.x implementation, and dates 5.x has already corrected. #1933's
   description is the model. Which commits of a 4.x line apply to a 5.x line is
   a judgement call, so never pick before the user says so.
4. **Nothing applies**: post the "no changes need to be migrated" comment, tick
   the task, and carry on with the next step.
5. **Something applies**: run the branch checks of `SKILL.md` step 3 — on
   `origin` it means work in review, locally it may be a resumable state or
   somebody's work — and then:

   ```bash
   git -C <repo> switch --no-track -c merge-<lower>-into-<higher> origin/<higher>
   git -C <repo> cherry-pick -S -x <sha>       # one at a time, oldest first
   ```

   `--no-track` for the same reason as in a plain merge: without it a bare
   `git push` aims at the release branch. `-x` records where each commit came
   from, which makes the next round's bookkeeping easier. An empty commit
   needs `--allow-empty` or is left out.

   On a conflict, stop and hand the repository over exactly as a merge
   conflict is handed over in `SKILL.md` step 4; a bump usually applies only
   in part, the spec line and not `VERSION.json`. The user resolves,
   `git add`s and either leaves it or runs `git cherry-pick --continue`, and
   the rerun finds `CHERRY_PICK_HEAD` on that branch, which is the resumable
   state for this path: carry on from here rather than starting over. If their
   resolution leaves `git status --porcelain` empty, that commit contributes
   nothing: `git cherry-pick --skip` and say so.
6. Show `git diff --stat origin/<higher>`, wait for the user's OK, and finish
   with `SKILL.md` steps 6 and 7 — same push, same `gh pr create` with
   `--assignee @me`, the cross-version PR body, and the same tick rule.

## Slack

The skill posts nothing. It ends with one line per PR opened, which the user
collects with the other repositories' lines and posts themselves:

```
· SA 5.0.0 -> 5.0.1: https://github.com/wazuh/wazuh-indexer-security-analytics/pull/347
```

Use the short name from the repository table, mention no one, and no line for
a step that ended with no changes. They go in the week's thread of channel
`devel-xdrsiem-indexer-div-1` (`C05K3JSPDLP`), under the parent message
`Hilo de los Upwards :thread:`: one thread per week, not per day.

## GPG

Claude's shell has no terminal, and `pinentry-curses` needs one, so signing
works only while the passphrase is in `gpg-agent`'s cache. By default the cache
lasts 10 minutes from the last use, and at most 2 hours. For a comfortable run
the user can raise both in `~/.gnupg/gpg-agent.conf` and reload the agent. That
is personal configuration: recommend it, never change it.

```
default-cache-ttl 3600
max-cache-ttl 14400
```

```bash
gpg-connect-agent reloadagent /bye
```

## Known traps

- **The destination is not always the older side.** Previous merge PRs
  sometimes carry an extra commit that lives only on the destination, so a
  conflict can hold a real fix on either side. `main` kept a javadoc fix from
  #340 that `5.0.1` never had, which is why `PercolateRuleEvaluator.java`
  conflicted in SA #348. Never assume the incoming side is the newer one.
- **Squash merges freeze the merge base.** When an upward PR is merged with
  squash, the next PR lists every source commit since the last real merge
  commit, dozens of them, even though their content is already there. The diff
  is what counts, not the commit list. PRs merged with "Create a merge commit"
  (#347, #348) move the base forward.
- **`git rev-list --count HEAD..origin/<lower>` proves nothing**: any merge
  commit makes it zero. To see what a merge really left behind, use
  `git diff --stat HEAD origin/<lower>`, which after a correct merge lists only
  what the destination owns: workflows, `VERSION.json`, the Gradle version
  fallback and `main`'s PR template.
- **Existing pin drift is not the merge's business.** SA's `5.0.1` pinned the
  alerting publisher action to `@5.0.0` in `codeql.yml`. Report it; do not fix
  it inside the merge.
- **`git switch -c <b> origin/<x>` without `--no-track`** sets `<x>` as the
  upstream, so a bare `git push` could aim at the release branch.
- **No empty PRs.** A step with nothing to merge is recorded on the issue, not
  pushed as an empty commit
  ([alerting#158](https://github.com/wazuh/wazuh-indexer-alerting/issues/158)).
  A step with no changes usually makes the ones above it empty too, but verify
  each one.

## References

- Weekly issue: [wazuh-indexer#1925](https://github.com/wazuh/wazuh-indexer/issues/1925) (week #38),
  umbrella [wazuh#39206](https://github.com/wazuh/wazuh/issues/39206) (week #37).
- Plain merges: [wazuh-indexer#1931](https://github.com/wazuh/wazuh-indexer/pull/1931),
  [SA#347](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/347),
  [SA#348](https://github.com/wazuh/wazuh-indexer-security-analytics/pull/348),
  [plugins#1594](https://github.com/wazuh/wazuh-indexer-plugins/pull/1594).
- Cross-version: [wazuh-indexer#1933](https://github.com/wazuh/wazuh-indexer/pull/1933),
  [#1802](https://github.com/wazuh/wazuh-indexer/pull/1802).
- Branch naming `merge-<ORIGIN>-into-<DESTINATION>` is stated in the issue body.
