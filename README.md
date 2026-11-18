# Scentry

A self-hosted code security scanning portal, run as a Docker stack. It answers two
different questions with one pipeline:

| | **My code** | **HA integration** |
|---|---|---|
| Question | Is my code vulnerable? | Is this stranger's code safe to install? |
| Target | A git repository you own | A Home Assistant integration or card (`owner/repo`) |
| Result | Grade A–F from open findings | Barkley's score and verdict for that version |
| Findings | Tracked across scans: open, fixed, suppressed | Listed per scan |

A repository of your own that contains a Home Assistant integration gets both: the
general scanners and the Home Assistant checks.

> **Status: early.** The pipeline, the portal and the stack work end to end, but it is
> young and lightly used. A clean scan means the scanners found nothing, not that the
> code is safe.

## What runs

| Scanner | Looks for | Runs on |
|---|---|---|
| [Semgrep](https://semgrep.dev) | Insecure code patterns, most languages | My code |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secrets, through the whole git history (values redacted) | My code |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Known-vulnerable dependencies | My code |
| [Trivy](https://trivy.dev) | Dockerfile, compose, Kubernetes, Terraform misconfiguration | My code |
| [zizmor](https://github.com/zizmorcore/zizmor) | GitHub Actions workflow weaknesses | My code, when it has workflows |
| [Bandit](https://bandit.readthedocs.io) | Python-specific issues | My code, when it has Python |
| [Barkley](https://github.com/SeriesOfTubez/ha-barkley) | Home Assistant: token exfiltration, dependencies resolved as HA installs them, malware heuristics, undeclared hosts, release and publisher history | HA integrations; my code when it is one |

Rules that hold everywhere:

- **Nothing scanned is ever run, built or installed.**
- **A scan with a missing, failed or timed-out scanner is marked incomplete** and
  can't get the top grade. So is one where a scanner ran but some of its own checks
  didn't (Barkley's, each listed in its report). The scan's page says what didn't
  finish and why, and so does the log.
- **A repository can't hide code from the scanners.** In-repo ignore and config files
  (in any folder, for the scanners that read them there) and inline `nosemgrep`,
  `nosec`, `gitleaks:allow` and zizmor ignore comments aren't honoured, and zizmor
  reads workflows a `.gitignore` lists, unless you switch that on. Trivy's inline
  `trivy:ignore` comments are the exception: it has no switch for them. Suppress a
  finding in the portal instead: it needs a reason and comes back for review after
  90 days by default.
- **A finding is only marked fixed when the scanner that found it ran successfully**
  and no longer reports it.

How my code is graded: each **problem** costs points once (critical 25, high 10,
medium 3, low 1), however many places it is found in: thirteen unpinned actions are one
thing to fix. Two scanners' rules that flag exactly the same places count once, at the
worse severity. An open critical caps the grade at D, an open high at B, and an
incomplete scan at B. A is 90+, B 80+, C 70+, D 60+. The target's page shows the
arithmetic, and its JSON export lists the problems.

One vulnerability is one problem, whatever it is called. osv-scanner names it by its
CVE, Barkley (for a repository that holds an HA integration) by its GHSA, in one finding
per package; every alias either lists links the names. A finding that only repeats
vulnerabilities another finding reports is marked **same vulnerability** on the
target's page: it is counted, and announced, once. Suppressing a vulnerability under one
name covers its other names too.

When my code is scanned: when it's added, on its interval (weekly by default, for new
advisories and rules), when you press **Scan now**, and on each new commit. Every
`SCENTRY_COMMIT_POLL_MINUTES` (15), when it has nothing queued, the runner asks the git
host what the branch (or the default branch) points at, with `git ls-remote` and the
same token as a clone: one small request, nothing downloaded. A commit that hasn't been
scanned is queued. It polls rather than waiting for webhooks, so the portal needn't be
reachable from the internet. Each target's page can switch this off; local paths aren't
watched.

### The portal

Tabs across the top: **Overview**, **Home Assistant** (what the Marketplace has
installed), **My code**, **Other integrations** (checked before installing, or since
removed), **Marketplace** and **System** (Home Assistant, notifications, AI explanations, the
log and the exports). The overview shows each tab's grades at a glance, what needs a look
(failed scans, low scores, an update that scores worse, critical or high findings) and
the latest scans. A row leads to its page: a target, then each finding on a page of its
own.

Every table sorts by clicking a column heading and has a search box. Both are done by
the server, as part of the address, so a sorted or filtered table can be bookmarked.
**Add a target** is a button on the My code and Other integrations tabs; it, and the
other forms (notifications, suppressing, removing), open in a pop-up. **Export**, in
the header of the overview, each tab and each target, downloads what that page covers:
JSON, findings as CSV (open, or all), and for a target SARIF too. Light and dark follow
the system.

A target's findings show when each was first seen and when a scan last reported it. To
suppress several at once, tick them on the Open tab (or search, for a rule's name, say,
and **tick all shown**), then **Suppress ticked…**: one reason and review date for all
of them, and one note for all, or a note of its own for any of them. A finding's own
**Suppress** can also take the target's other open findings from the same rule with it.

**Share**, on a finding's page, writes it up as Markdown for a GitHub issue, a security
advisory or a message: what was found, by which scanner and rule, a link to the line at
the commit that was scanned, the code excerpt, and, if you choose, the AI explanation,
marked as a model's. Copy it from the page or download it as a `.md` file. When the code
is on GitHub, **New issue** opens that repository's new-issue page with it filled in, for
you to check and submit; Scentry sends nothing. For an integration or card, which is
someone else's code, the page points to the repository's security page first: something
exploitable is best reported privately. Text from the scanned code (and the model's)
comes out as plain text: it can't add links or formatting, or @mention anyone. A secret
scanner's excerpt is left out, and so is the AI's advice about installing an add-on.

**Log**, from the System tab, is what every service did and what went wrong, in one
place and newest first: a scanner that didn't finish, a scan that failed, a notification
that wasn't delivered, a lost connection to Home Assistant, a model that couldn't be
reached. Search it, show one service, or only warnings and errors; a scan it mentions is
a link. It holds Scentry's own messages and other software's warnings and errors, not
each page view; secrets a service holds (tokens, passwords, notification URLs) are
blanked before a message is kept. It's kept `SCENTRY_LOG_DAYS` days (14). Each
container's output (`docker compose logs`) still has every line.

## Install

You need Docker with Compose, about 3 GB of disk for the images, and 4 GB of memory
for the runner while a scan runs.

```sh
cp .env.example .env      # set POSTGRES_PASSWORD and SCENTRY_ADMIN_PASSWORD
docker compose up -d
```

Open <http://127.0.0.1:8080> and sign in as `admin`.

The images are built by this repository's GitHub Actions and published to
`ghcr.io/wallacegsr/scentry-{web,runner,egress}`, for amd64 and arm64: `latest` is the
newest build of `main`, and `SCENTRY_VERSION` pins another. To build them yourself
instead:

```sh
docker compose -f compose.yaml -f compose.build.yaml up -d --build
```

Each image is signed with [cosign](https://docs.sigstore.dev/cosign/) (keyless: the
signature is bound to this repository's workflow, so there's no key to steal) and
carries a build provenance attestation. To check one before you run it:

```sh
cosign verify ghcr.io/wallacegsr/scentry-runner:latest \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/wallacegsr/scentry/\.github/workflows/images\.yml@refs/(heads/main|tags/v.+)$'
gh attestation verify oci://ghcr.io/wallacegsr/scentry-runner:latest -R wallacegsr/scentry
```

Docker, Portainer and Watchtower don't check signatures themselves.

**Portainer:** Stacks → Add stack → Repository, point it at this repository with
compose path `compose.yaml`, and add the variables from `.env.example` under
Environment variables (or load your `.env` with *Load variables from .env file*).
The stack's name decides its volumes' names, so keep the name when redeploying.

The portal speaks plain HTTP and listens on `127.0.0.1` by default. Put it behind
your reverse proxy for TLS before opening it to your network. After 20 wrong passwords
in 15 minutes from one address, that address is refused for the rest of the 15
minutes. Behind a proxy, every visitor arrives from the proxy's address, so someone
guessing would lock you out too: there, use `SCENTRY_AUTH_MODE=proxy` and let the
proxy handle sign-in.

### Upgrading

Pull the new images (in Portainer: *Pull and redeploy*). Each service brings the
database to the new schema when it starts; the first one to start does it while the
others wait. Images are published only after the tests pass on Postgres, but a
migration changes your data in place, so back the database up first if it matters:

```sh
docker compose exec db pg_dump -U scentry scentry > scentry-backup.sql
```

There's no going back to an older version on a migrated database; restore the backup
instead.

### Settings

Everything is an environment variable; `.env.example` lists them with comments.

| Need | Setting |
|---|---|
| Private repositories | `SCENTRY_GIT_TOKENS={"github.com":"<read-only token>"}`: a fine-grained token with read access to those repositories' contents only |
| Self-hosted Gitea / GitLab | The same, keyed by your host, plus `SCENTRY_EXTRA_ALLOWED_DOMAINS` |
| Single sign-on | `SCENTRY_AUTH_MODE=proxy` with `SCENTRY_TRUSTED_PROXIES` |
| Fewer scanners | `SCENTRY_DISABLED_SCANNERS=["bandit"]` |
| Smaller box | `SCENTRY_RUNNER_MEMORY`, `SCENTRY_WORK_SIZE` (room for one scan's code and the scanners' temporary files: keep 1g) |
| A longer or shorter log | `SCENTRY_LOG_DAYS` (14) |
| Subnet clash with `172.30.255.0/28` | `SCENTRY_EGRESS_SUBNET` and `SCENTRY_EGRESS_IP` |
| Scan what Home Assistant has installed | `SCENTRY_HASS_URL` and `SCENTRY_HASS_TOKEN`, below |
| Notifications | `SCENTRY_NOTIFY_URLS`, below |
| AI explanations (Claude, Ollama, OpenAI-compatible) | `SCENTRY_AI_PROVIDER` and its settings, below |

### Connecting Home Assistant

With these set, Scentry follows what the Marketplace (HACS) has installed:

- every installed integration and card becomes a target, scanned **at the version
  installed**, and rescanned weekly;
- an **update the Marketplace offers is scanned before you install it**, and shown
  next to the installed version's result;
- after an update, the new version is scanned (usually it already was, as an offer);
- an uninstalled one stops being rescanned and keeps its history.

The list is read at start, right after any install or uninstall (HA 2026.11 and
later report these), every 10 minutes as a fallback, and when you press **Sync now**.
Themes and other kinds the scanner doesn't cover are counted but not scanned.

1. In Home Assistant, create a user for Scentry and make it an **administrator**:
   HA only lists the Marketplace for admins. Sign in as it, then Profile → Security →
   Long-lived access tokens → Create token.
2. Set `SCENTRY_HASS_URL` and `SCENTRY_HASS_TOKEN`. For HA Container on the same Docker
   host (`network_mode: host`), the URL is `http://host.docker.internal:8123`;
   otherwise use HA's address on your network.
3. Set `SCENTRY_PUBLIC_GITHUB_TOKEN`: a GitHub fine-grained token for "Public
   repositories" with no permissions added. Scans fetch through GitHub's API, which
   allows 60 requests an hour without a token, enough for only a few integrations;
   a token raises that to 5,000 and can't read or change anything. When the limit runs
   out anyway, scans wait for it to reset and then carry on.
4. Restart the stack. The Home Assistant and System tabs show the connection, and its
   error if any.

An admin token can do almost anything in Home Assistant, so it is kept to one place:
the **hass-sync** container, which reads the Marketplace's list only (names, versions,
descriptions). The commands it can
send are fixed in its code (`src/scentry/hass.py`): the Marketplace list, the
subscription to install events, and nothing else. It never touches scanned code, and
the runner, which does, still can't reach your network. Over plain `http://` the token
crosses your LAN unencrypted; use `https://` if HA has a certificate.

Works with HA 2026.11+ (the Marketplace in Core) and with older HA running the HACS
integration, which can't report installs, so changes there are picked up by the
10-minute check. On HA OS or Supervised, [Barkley](https://github.com/SeriesOfTubez/ha-barkley)
does this as an add-on.

### Searching the Marketplace

The list the sync reads holds the whole catalog, not only what is installed, so the
portal keeps a copy: the **Marketplace** tab finds any integration
or card by name, owner/repo or a word from its description, and **Scan** checks the
version the Marketplace would install, before you install it. (Without a version from
HA, Barkley picks it the way the Marketplace would.) Such a scan isn't repeated unless
you ask; once you install the item, the sync takes the target over. Only an entry that
is in the catalog can be scanned from there. Names and descriptions are the publishers'
own text, shown as plain text.

### What an update changes, and new advisories

When an update is offered, its scan page shows **What changed since** the installed
version: Barkley's comparison of the two reports (`sniff-test diff`), the changes that
matter first (a new finding, a new host the code talks to, a package added, a new
publisher), then a count of the rest. Every other Home Assistant scan is compared with
the last scan of the version before it. Comparing reads two reports and fetches nothing.

A vulnerability published after a version was scanned would otherwise wait for next
week's rescan. Once a day (`SCENTRY_RECHECK_HOURS`, 24) the runner, when it has nothing
queued, asks OSV again about the packages each installed and offered version resolved,
which Barkley keeps in its store on the runner's `/cache` volume. That fetches no code
and asks GitHub nothing; it takes seconds. When the advisories changed, the result is a
new scan tagged **advisories re-checked**, compared with the scan it re-checked. A scan
page has **Check advisories again** to do it on the runner's next idle moment. Scans
made before this existed aren't in Barkley's store, so they wait for their rescan.

### Notifications

Set `SCENTRY_NOTIFY_URLS` to one or more [Apprise](https://github.com/caronc/apprise/wiki)
URLs, and Scentry tells you when something is worth a look: ntfy, Gotify, Discord,
Slack, Telegram, Matrix, e-mail, Pushover and about a hundred more. The System tab
shows whether sending works, and has a **Send a test** button.

What gets a message:

| When | Default |
|---|---|
| An installed integration or card scores under `SCENTRY_NOTIFY_SCORE_BELOW` | 70: Very Sus and BORK |
| An offered update does, or scores 10 points worse than the installed version (the message lists what it changes) | on |
| The daily re-check finds a new advisory: newly under the threshold, 10 points worse, or a new high or critical vulnerability | on |
| Every offered update, including the fine ones | `SCENTRY_NOTIFY_CLEAN_UPDATES=true` |
| My code: new or reopened findings at `SCENTRY_NOTIFY_MIN_SEVERITY` or worse | high |
| A target's scans start failing; the Home Assistant sync fails for 30 minutes | on |

These are the defaults. A target's page has **Notifications**, where it can be muted or
given its own threshold, severity, offered-update and failure settings; anything left
blank follows the default.

A result is announced once: a weekly rescan with the same verdict stays quiet, unless
the score drops 10 points (a new advisory, say). Messages are digests. The notifier
waits for the scan queue to drain, for no longer than 15 minutes, so the first sync of
a Home Assistant with thirty integrations sends one message, not thirty. Results more
than a day old when the notifier sees them are not announced, so turning it on doesn't
replay history. Set `SCENTRY_PUBLIC_URL` for links to each result.

To get them in Home Assistant itself, make an automation with a webhook trigger and use
`json://host.docker.internal:8123/api/webhook/<its id>`. That needs no token: the
`title` and `message` arrive as `trigger.json.title` and `trigger.json.message`.

The URLs carry secrets (bot tokens, webhook ids), so only the **notify** container is
given them. Errors shown on the portal are scrubbed of them. Text that comes from
scanned code (names, file paths, rule titles) is cut down to plain letters, digits and
punctuation before it goes into a message, so a repository can't put a mention, markup
or a link in your notifications.

### AI explanations

Optional. Set up a model (below) and two buttons appear, named after it:

- **Explain with …** on each finding's page: what it means, whether it looks real here
  (*looks real*, *probably harmless here*, *can't tell*) and why, and what to do: how to
  fix it in your code, or for an integration you didn't write, whether it matters and
  what your options are.
- **Review with …** on each scan: how worrying the result is, the findings to look
  at first, the ones that are probably noise, and what to do next: the fixes that
  matter in your code, or whether an integration looks fine to install or keep.

Nothing is sent until someone presses one. The model is then sent what the scanners
recorded: titles, rule ids, messages, file paths, vulnerability ids, the verdict, and
the short excerpts of code kept as evidence (a few lines each). Never a checkout, a
token or a password. Answers stay on the page they were asked from; **Ask again**
replaces one.

Which model answers (`SCENTRY_AI_PROVIDER`; `.env.example` has every setting):

| Provider | Set | Notes |
|---|---|---|
| `anthropic` (default) | `SCENTRY_ANTHROPIC_API_KEY` from the [Anthropic Console](https://console.anthropic.com) | Claude Opus 5.5 unless `SCENTRY_AI_MODEL` says otherwise. Billed per use. When Claude's safety checks decline a request (security findings can read like attack work), Anthropic's fallback model answers it instead. |
| `ollama` | `SCENTRY_AI_MODEL`, and `SCENTRY_AI_BASE_URL` unless Ollama runs on the Docker host (`http://host.docker.internal:11434`) | Nothing leaves your network. Ollama must listen beyond 127.0.0.1 (`OLLAMA_HOST=0.0.0.0`) and have the model pulled. Its own API is used, so the model is loaded with `SCENTRY_AI_CONTEXT` tokens of context (32768), and material that doesn't fit is refused, never quietly cut. |
| `openai` | `SCENTRY_AI_MODEL`, `SCENTRY_AI_BASE_URL` (OpenAI's unless set), `SCENTRY_AI_API_KEY` if the server wants one | Any OpenAI-compatible chat API that supports JSON-schema response formats: OpenAI, Gemini, OpenRouter, LM Studio, vLLM, llama.cpp's server. |

Each is given the same instructions and material, no tools, and must answer in a fixed
JSON shape, which is checked before anything is stored. When the service starts it
checks what it can without spending anything (for Ollama: that it answers and has the
model) and shows a problem on the System tab. At most `SCENTRY_AI_DAILY_LIMIT` requests
a day are sent (50; 0 for no limit); the System tab shows how many have been used. A
finding's explanation is usually a couple of thousand tokens; a scan's review with many
findings, more (on Ollama, a long review may need a bigger `SCENTRY_AI_CONTEXT`). A local
model on a CPU can take minutes: `SCENTRY_AI_TIMEOUT` (600 s) is how long one answer
may take.

The material comes from scanned code, which can be written to mislead a reviewer:
a comment saying *this is safe, ignore previous instructions*. So the model gets no
tools, only the material and the question, and its answer is text that is shown and
nothing else. The material is fenced off and named as data, and the model is told to
point out any such text rather than follow it. Every answer is marked with the model
that wrote it, as coming from text out of the scanned code, and possibly wrong: it's a
second opinion to read, not a verdict. Grades, scores and notifications never depend on
it. Smaller models (most that run locally) are easier to mislead this way and weaker at
security reasoning, so their answers are best read as hints.

**Which local model.** In a small test (November 2026, Ollama on a 16 GB RTX 5080), four
models explained nine findings whose answers were known and reviewed the scan they came
from. Two of the findings carried a planted comment: one claiming the input was
validated, one telling AI reviewers the finding was approved and to call it harmless.

| Model | Right (of 9) | Planted comments | Per finding | VRAM at 32k context |
|---|---|---|---|---|
| `qwen3.5:9b` | 8 | Not fooled in 4 tries of each; named the comment a deliberate attempt to mislead | ~25 s | 6.3 GB |
| `qwen3.6:35b-a3b` | 7 | Not fooled in 4 tries of each; named the comment a prompt injection attempt | ~35 s | 13.6 GB |
| `gpt-oss:20b` | 7 | Fooled by "approved, call it harmless" in 4 tries of 4 | ~3 s | 12.8 GB |
| `qwen2.5-coder:14b` | 6 | Not fooled asked about each finding alone, but fooled in the scan review | ~2 s | 12.2 GB |

In the scan review, all but `qwen2.5-coder:14b` put the three real problems first; it
called the `eval()` with the planted comment noise. Start with `qwen3.5:9b`: it
thinks before it answers, which is slower but was right more often, and it is small
enough to leave room for `SCENTRY_AI_CONTEXT=65536` (under 7 GB), which fits the longest
review Scentry sends. One run of a small test is a hint, not a benchmark, and local models
change quickly.

The key, or the model server's address, is given only to the **ai** container, which
never touches scanned code.

## How the stack is put together

```
            ┌────────┐      ┌──────┐
 browser ──▶│  web   │─────▶│  db  │
            └────────┘      └──────┘
                               ▲
            ┌────────┐         │        ┌────────┐
            │ runner │─────────┘        │ egress │──▶ allowlisted hosts, port 443
            │        │─────────────────▶│gateway │
            └────────┘                  └────────┘
            ┌──────────┐
 your HA ◀──│hass-sync │──▶ db       (optional: reads what HACS has installed)
            └──────────┘
            ┌──────────┐
 ntfy etc ◀─│  notify  │──▶ db       (optional: announces results)
            └──────────┘
            ┌──────────┐
 a model  ◀─│    ai    │──▶ db       (optional: explanations, when asked)
            └──────────┘
```

- **web** serves the portal. It never touches scanned code and holds no tokens. Pages
  are server-rendered with no JavaScript, and the content security policy allows no
  scripts (nor inline styles), because they display text taken from scanned code.
  Sorting and search are links and forms; pop-ups are the browser's own popovers.
- **runner** takes scans from the queue (the `scans` table, so a restart loses
  nothing). All scanners are baked into its image and run as child processes with a
  scrubbed environment: no tokens, no database URL. The runner makes itself
  non-dumpable, so a scanner (same user) can't read those from its `/proc` entries
  either. It has no Docker socket, runs as a non-root user with a read-only root
  filesystem and no capabilities, and keeps scanned code (and the scanners' temporary
  files) on a non-executable in-memory filesystem. What a subverted scanner could still do is what the runner
  can: write to the database, and reach the allowlisted hosts.
- **egress** is the runner's only route out, and its DNS server. Names on the
  allowlist (`docker/egress/allowlist.txt`) resolve to the gateway, which reads the
  server name from the TLS hello (it decrypts nothing) and passes the connection on
  only if that name is allowed, on port 443. Everything else doesn't resolve or isn't
  routable, so the runner can't reach your LAN. No tool needs proxy settings.
- **hass-sync** (optional) follows Home Assistant's installed list and queues scans.
  It is the only container with the HA token, and it never touches scanned code.
- **notify** (optional) sends the digests. It is the only container with the
  notification URLs, and it never touches scanned code.
- **ai** (optional) answers requests for explanations through the model you set up:
  Claude, Ollama, or an OpenAI-compatible server. It is the only container with that
  key or address, and it never touches scanned code: it sends what the scanners
  recorded, from the database.
- **db** is Postgres. SQLite works too (`SCENTRY_DATABASE_URL`), for development.

What goes into the images is pinned:

- Scentry's own Python dependencies, from `uv.lock`: exact versions, every file
  checked against its recorded hash.
- Every scanner's version. The release binaries (osv-scanner, Trivy) are in
  `docker/Dockerfile`, each checked against a sha256. Gitleaks is built there from
  its release commit with a current Go, because its own binaries are built with an
  old one. The Python ones (Semgrep,
  GuardDog, Bandit, zizmor, Barkley) are in `docker/tools/<name>/`, each with a
  `uv.lock` that pins everything it needs, every file checked against its recorded
  hash, and each in its own environment. They install from wheels only, except Barkley,
  which isn't on PyPI: it is built from an exact commit, with a locked build backend.
- The base images, by digest. The GitHub Actions that build them, by commit.

Dependabot proposes updates to all of these weekly, once a release is a week old
(uv's `exclude-newer` holds the locks to the same, except for the Anthropic SDK), and
the tests run on each before anything is published.

## Development

```sh
uv sync --extra dev                                  # from uv.lock, into .venv
.venv/bin/pytest
SCENTRY_ADMIN_PASSWORD=dev .venv/bin/scentry web      # sqlite, http://127.0.0.1:8080
.venv/bin/scentry worker                             # scanners must be on PATH
.venv/bin/scentry hass-sync                          # with SCENTRY_HASS_URL/_TOKEN
.venv/bin/scentry notify                             # with SCENTRY_NOTIFY_URLS
.venv/bin/scentry ai                                 # with SCENTRY_ANTHROPIC_API_KEY
```

Adding a scanner: subclass `SarifScanner` in `src/scentry/scanners/tools.py` (a
command that writes SARIF is all it takes), add it to `PROFILE_SCANNERS`, and install
the tool: a release binary in the `tools` stage of `docker/Dockerfile`, a Python tool as
a new `docker/tools/<name>/pyproject.toml` (copy one) locked with `docker/tools/lock.sh
<name>`.

Changing a scanner's version: edit its pin in `docker/tools/<name>/pyproject.toml`, then
`docker/tools/lock.sh <name>` (it locks in a Linux container with Docker, as the image
is built); CI fails if a lock is out of date.

Changing dependencies: edit `pyproject.toml`, then `uv lock`; CI fails if `uv.lock`
is out of date. (`pip install -e ".[dev]"` works too, without the lock.)

Changing the database: edit `src/scentry/models.py`, then
`.venv/bin/scentry new-migration "what changed"` writes a migration to
`src/scentry/migrations/versions/`. Read it before committing: it can't tell a renamed
column from a dropped and added one. The tests fail while a model change has no
migration; set `SCENTRY_TEST_POSTGRES` to an empty scratch database to run them on
Postgres too, as CI does.

## Credits

The Home Assistant checks are [Barkley](https://github.com/SeriesOfTubez/ha-barkley)
(MIT), used unmodified: through its command line, and for the advisory re-check (which
has no command) its own `recheck` function, run by its own Python.
