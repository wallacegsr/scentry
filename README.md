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

> **Status: early scaffold.** The pipeline, the portal and the stack work end to end,
> but see [Not built yet](#not-built-yet). A clean scan means the scanners found
> nothing, not that the code is safe.

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
  can't get the top grade.
- **A repository can't hide code from the scanners.** In-repo ignore files and inline
  `nosemgrep` / `nosec` comments aren't honoured unless you switch that on. Suppress a
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
your reverse proxy for TLS before opening it to your network.

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
| Private repositories | `SCENTRY_GIT_TOKENS={"github.com":"<read-only token>"}` |
| Self-hosted Gitea / GitLab | The same, keyed by your host, plus `SCENTRY_EXTRA_ALLOWED_DOMAINS` |
| Single sign-on | `SCENTRY_AUTH_MODE=proxy` with `SCENTRY_TRUSTED_PROXIES` |
| Fewer scanners | `SCENTRY_DISABLED_SCANNERS=["bandit"]` |
| Smaller box | `SCENTRY_RUNNER_MEMORY`, `SCENTRY_WORK_SIZE` |
| Subnet clash with `172.30.255.0/28` | `SCENTRY_EGRESS_SUBNET` and `SCENTRY_EGRESS_IP` |
| Scan what Home Assistant has installed | `SCENTRY_HASS_URL` and `SCENTRY_HASS_TOKEN`, below |
| Notifications | `SCENTRY_NOTIFY_URLS`, below |

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
4. Restart the stack. The front page shows the connection, and its error if any.

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
portal keeps a copy: **Search the Marketplace** on the front page finds any integration
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
Slack, Telegram, Matrix, e-mail, Pushover and about a hundred more. The front page
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
```

- **web** serves the portal. It never touches scanned code and holds no tokens. Pages
  are server-rendered with no JavaScript, and the content security policy allows no
  scripts, because they display text taken from scanned code.
- **runner** takes scans from the queue (the `scans` table, so a restart loses
  nothing). All scanners are baked into its image and run as child processes with a
  scrubbed environment: no tokens, no database URL. It has no Docker socket, runs as a
  non-root user with a read-only root filesystem and no capabilities, and keeps
  scanned code on a non-executable in-memory filesystem.
- **egress** is the runner's only route out, and its DNS server. Names on the
  allowlist (`docker/egress/allowlist.txt`) resolve to the gateway, which reads the
  server name from the TLS hello (it decrypts nothing) and passes the connection on
  only if that name is allowed, on port 443. Everything else doesn't resolve or isn't
  routable, so the runner can't reach your LAN. No tool needs proxy settings.
- **hass-sync** (optional) follows Home Assistant's installed list and queues scans.
  It is the only container with the HA token, and it never touches scanned code.
- **notify** (optional) sends the digests. It is the only container with the
  notification URLs, and it never touches scanned code.
- **db** is Postgres. SQLite works too (`SCENTRY_DATABASE_URL`), for development.

What goes into the images is pinned:

- Scentry's own Python dependencies, from `uv.lock`: exact versions, every file
  checked against its recorded hash.
- Every scanner's version, in `docker/Dockerfile`. Release binaries are checked against
  a sha256, and Barkley is installed from an exact commit. (The scanners' own Python
  dependencies are resolved when the image is built, within what each scanner allows.)
- The base images, by digest. The GitHub Actions that build them, by commit.

Dependabot proposes updates to all of these weekly, and the tests run on each before
anything is published.

## Development

```sh
uv sync --extra dev                                  # from uv.lock, into .venv
.venv/bin/pytest
SCENTRY_ADMIN_PASSWORD=dev .venv/bin/scentry web      # sqlite, http://127.0.0.1:8080
.venv/bin/scentry worker                             # scanners must be on PATH
.venv/bin/scentry hass-sync                          # with SCENTRY_HASS_URL/_TOKEN
.venv/bin/scentry notify                             # with SCENTRY_NOTIFY_URLS
```

Adding a scanner: subclass `SarifScanner` in `src/scentry/scanners/tools.py` (a
command that writes SARIF is all it takes), add it to `PROFILE_SCANNERS`, and install
the tool in the `tools` stage of `docker/Dockerfile`.

Changing dependencies: edit `pyproject.toml`, then `uv lock`; CI fails if `uv.lock`
is out of date. (`pip install -e ".[dev]"` works too, without the lock.)

Changing the database: edit `src/scentry/models.py`, then
`.venv/bin/scentry new-migration "what changed"` writes a migration to
`src/scentry/migrations/versions/`. Read it before committing: it can't tell a renamed
column from a dropped and added one. The tests fail while a model change has no
migration; set `SCENTRY_TEST_POSTGRES` to an empty scratch database to run them on
Postgres too, as CI does.

## Not built yet

- Merging the same vulnerability reported under different ids (CVE / GHSA).
- Scanning on new commits; scans run on a per-target interval.
- Optional AI review and explanations.
- Hash-locked Python dependencies for the scanners themselves (their own versions are
  pinned).

## Credits

The Home Assistant checks are [Barkley](https://github.com/SeriesOfTubez/ha-barkley)
(MIT), used unmodified: through its command line, and for the advisory re-check (which
has no command) its own `recheck` function, run by its own Python.
