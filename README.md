# 🚀 go-wire
BSV Blockchain Wire Protocol

<table>
  <thead>
    <tr>
      <th>CI&nbsp;/&nbsp;CD</th>
      <th>Quality&nbsp;&amp;&nbsp;Security</th>
      <th>Docs&nbsp;&amp;&nbsp;Meta</th>
      <th>Community</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td valign="top" align="left">
        <a href="https://github.com/bsv-blockchain/go-wire/releases">
          <img src="https://img.shields.io/github/release-pre/bsv-blockchain/go-wire?logo=github&style=flat" alt="Latest Release">
        </a><br/>
        <a href="https://github.com/bsv-blockchain/go-wire/actions">
          <img src="https://img.shields.io/github/actions/workflow/status/bsv-blockchain/go-wire/run-tests.yml?branch=master&logo=github&style=flat" alt="Build Status">
        </a><br/>
		<a href="https://github.com/bsv-blockchain/go-wire/actions">
          <img src="https://github.com/bsv-blockchain/go-wire/actions/workflows/codeql-analysis.yml/badge.svg?style=flat" alt="CodeQL">
        </a><br/>
        <a href="https://github.com/bsv-blockchain/go-wire/commits/master">
		  <img src="https://img.shields.io/github/last-commit/bsv-blockchain/go-wire?style=flat&logo=clockify&logoColor=white" alt="Last commit">
		</a>
      </td>
      <td valign="top" align="left">
        <a href="https://goreportcard.com/report/github.com/bsv-blockchain/go-wire">
          <img src="https://goreportcard.com/badge/github.com/bsv-blockchain/go-wire?style=flat" alt="Go Report Card">
        </a><br/>
		<a href="https://codecov.io/gh/bsv-blockchain/go-wire">
          <img src="https://codecov.io/gh/bsv-blockchain/go-wire/branch/master/graph/badge.svg?style=flat" alt="Code Coverage">
        </a><br/>
		<a href="https://scorecard.dev/viewer/?uri=github.com/bsv-blockchain/go-wire">
          <img src="https://api.scorecard.dev/projects/github.com/bsv-blockchain/go-wire/badge?logo=springsecurity&logoColor=white" alt="OpenSSF Scorecard">
        </a><br/>
		<a href=".github/SECURITY.md">
          <img src="https://img.shields.io/badge/security-policy-blue?style=flat&logo=springsecurity&logoColor=white" alt="Security policy">
        </a>
      </td>
      <td valign="top" align="left">
        <a href="https://golang.org/">
          <img src="https://img.shields.io/github/go-mod/go-version/bsv-blockchain/go-wire?style=flat" alt="Go version">
        </a><br/>
        <a href="https://pkg.go.dev/github.com/bsv-blockchain/go-wire?tab=doc">
          <img src="https://pkg.go.dev/badge/github.com/bsv-blockchain/go-wire.svg?style=flat" alt="Go docs">
        </a><br/>
        <a href=".github/AGENTS.md">
          <img src="https://img.shields.io/badge/AGENTS.md-found-40b814?style=flat&logo=openai" alt="AGENTS.md rules">
        </a><br/>
        <a href="Makefile">
          <img src="https://img.shields.io/badge/Makefile-supported-brightgreen?style=flat&logo=probot&logoColor=white" alt="Makefile Supported">
        </a><br/>
		<a href=".github/dependabot.yml">
          <img src="https://img.shields.io/badge/dependencies-automatic-blue?logo=dependabot&style=flat" alt="Dependabot">
        </a>
      </td>
      <td valign="top" align="left">
        <a href="https://github.com/bsv-blockchain/go-wire/graphs/contributors">
          <img src="https://img.shields.io/github/contributors/bsv-blockchain/go-wire?style=flat&logo=contentful&logoColor=white" alt="Contributors">
        </a><br/>
        <a href="https://github.com/sponsors/bsv-blockchain">
          <img src="https://img.shields.io/badge/sponsor-BSV-181717.svg?logo=github&style=flat" alt="Sponsor">
        </a>
      </td>
    </tr>
  </tbody>
</table>

<br/>

## 🗂️ Table of Contents
* [What's Inside](#-whats-inside)
* [Installation](#-installation)
* [Documentation](#-documentation)
* [Examples & Tests](#-examples--tests)
* [Benchmarks](#-benchmarks)
* [Code Standards](#-code-standards)
* [AI Compliance](#-ai-compliance)
* [Maintainers](#-maintainers)
* [Contributing](#-contributing)
* [License](#-license)

<br/>

## 🧩 What's Inside
Package wire implements the bitcoin wire protocol.  A comprehensive suite of
tests with 100% test coverage is provided to ensure proper functionality.

This package has intentionally been designed so it can be used as a standalone
package for any projects needing to interface with bitcoin peers at the wire
protocol level.

<br/>

## 📦 Installation

**go-wire** requires a [supported release of Go](https://golang.org/doc/devel/release.html#policy).
```shell script
go get -u github.com/bsv-blockchain/go-wire
```

<br/>

## 📚 Documentation

- **API Reference** – Dive into the godocs at [pkg.go.dev/github.com/bsv-blockchain/go-wire](https://pkg.go.dev/github.com/bsv-blockchain/go-wire)
- **Usage Examples** – Browse practical patterns either the [examples directory](examples) or view the example functions
- **Benchmarks** – Check the latest numbers in the [benchmark results](#benchmark-results)
- **Test Suite** – Review both the [unit tests](common_test.go) and [fuzz tests](wire_fuzz_test.go) (powered by [`testify`](https://github.com/stretchr/testify))

<br/>

<details>
<summary><strong><code>Repository Features</code></strong></summary>
<br/>

* **Continuous Integration on Autopilot** with [GitHub Actions](https://github.com/features/actions) – every push is built, tested, and reported in minutes.
* **Pull‑Request Flow That Merges Itself** thanks to [auto‑merge](.github/workflows/auto-merge-on-approval.yml) and hands‑free [Dependabot auto‑merge](.github/workflows/dependabot-auto-merge.yml).
* **One‑Command Builds** powered by battle‑tested [Make](https://www.gnu.org/software/make) targets for linting, testing, releases, and more.
* **First‑Class Dependency Management** using native [Go Modules](https://github.com/golang/go/wiki/Modules).
* **Uniform Code Style** via [gofumpt](https://github.com/mvdan/gofumpt) plus zero‑noise linting with [golangci‑lint](https://github.com/golangci/golangci-lint).
* **Confidence‑Boosting Tests** with [testify](https://github.com/stretchr/testify), the Go [race detector](https://blog.golang.org/race-detector), crystal‑clear [HTML coverage](https://blog.golang.org/cover) snapshots, and automatic uploads to [Codecov](https://codecov.io/).
* **Hands‑Free Releases** delivered by [GoReleaser](https://github.com/goreleaser/goreleaser) whenever you create a [new Tag](https://git-scm.com/book/en/v2/Git-Basics-Tagging).
* **Relentless Dependency & Vulnerability Scans** via [Dependabot](https://dependabot.com), [Nancy](https://github.com/sonatype-nexus-community/nancy), and [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck).
* **Security Posture by Default** with [CodeQL](https://docs.github.com/en/github/finding-security-vulnerabilities-and-errors-in-your-code/about-code-scanning), [OpenSSF Scorecard](https://openssf.org), and secret‑leak detection via [gitleaks](https://github.com/gitleaks/gitleaks).
* **Automatic Syndication** to [pkg.go.dev](https://pkg.go.dev/) on every release for instant godoc visibility.
* **Polished Community Experience** using rich templates for [Issues & PRs](https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/configuring-issue-templates-for-your-repository).
* **All the Right Meta Files** (`LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`, `SECURITY.md`) pre‑filled and ready.
* **Code Ownership** clarified through a [CODEOWNERS](.github/CODEOWNERS) file, keeping reviews fast and focused.
* **Zero‑Noise Dev Environments** with tuned editor settings (`.editorconfig`) plus curated *ignore* files for [VS Code](.editorconfig), [Docker](.dockerignore), and [Git](.gitignore).
* **Label Sync Magic**: your repo labels stay in lock‑step with [.github/labels.yml](.github/labels.yml).
* **Friendly First PR Workflow** – newcomers get a warm welcome thanks to a dedicated [workflow](.github/workflows/pull-request-management.yml).
* **Standards‑Compliant Docs** adhering to the [standard‑readme](https://github.com/RichardLitt/standard-readme/blob/master/spec.md) spec.
* **Instant Cloud Workspaces** via [Gitpod](https://gitpod.io/) – spin up a fully configured dev environment with automatic linting and tests.
* **Out‑of‑the‑Box VS Code Happiness** with a preconfigured [Go](https://code.visualstudio.com/docs/languages/go) workspace and [`.vscode`](.vscode) folder with all the right settings.
* **Optional Release Broadcasts** to your community via [Slack](https://slack.com), [Discord](https://discord.com), or [Twitter](https://twitter.com) – plug in your webhook.
* **AI Compliance Playbook** – machine‑readable guidelines ([AGENTS.md](.github/AGENTS.md), [CLAUDE.md](.github/CLAUDE.md), [.cursorrules](.cursorrules), [sweep.yaml](.github/sweep.yaml)) keep ChatGPT, Claude, Cursor & Sweep aligned with your repo’s rules.
* **Pre-commit Hooks for Consistency** powered by [pre-commit](https://pre-commit.com) and the [.pre-commit-config.yaml](.pre-commit-config.yaml) file—run the same formatting, linting, and tests before every commit, just like CI.
* **DevContainers for Instant Onboarding** – Launch a ready-to-code environment in seconds with [VS Code DevContainers](https://containers.dev/) and the included [.devcontainer/devcontainer.json](.devcontainer/devcontainer.json) config.

</details>

<details>
<summary><strong><code>Library Deployment</code></strong></summary>
<br/>

This project uses [goreleaser](https://github.com/goreleaser/goreleaser) for streamlined binary and library deployment to GitHub. To get started, install it via:

```bash
brew install goreleaser
```

The release process is defined in the [.goreleaser.yml](.goreleaser.yml) configuration file.

To generate a snapshot (non-versioned) release for testing purposes, run:

```bash
make release-snap
```

Then create and push a new Git tag using:

```bash
make tag version=x.y.z
```

This process ensures consistent, repeatable releases with properly versioned artifacts and citation metadata.

</details>

<details>
<summary><strong><code>Makefile Commands</code></strong></summary>
<br/>

View all `makefile` commands

```bash script
make help
```

List of all current commands:

<!-- make-help-start -->
```text
bench                 ## Run all benchmarks in the Go application
build-go              ## Build the Go application (locally)
citation              ## Update version in CITATION.cff (use version=X.Y.Z)
clean-mods            ## Remove all the Go mod cache
coverage              ## Show test coverage
diff                  ## Show git diff and fail if uncommitted changes exist
generate              ## Run go generate in the base of the repo
godocs                ## Trigger GoDocs tag sync
govulncheck-install   ## Install govulncheck
help                  ## Display this help message
install-go            ## Install using go install with specific version
install-releaser      ## Install GoReleaser
install               ## Install the application binary
lint                  ## Run the golangci-lint application (install if not found)
release-snap          ## Build snapshot binaries
release-test          ## Run release dry-run (no publish)
release               ## Run production release (requires github_token)
run-fuzz-tests        ## Run fuzz tests for all packages
tag-remove            ## Remove local and remote tag (use version=X.Y.Z)
tag-update            ## Force-update tag to current commit (use version=X.Y.Z)
tag                   ## Create and push a new tag (use version=X.Y.Z)
test-ci-no-race       ## CI test suite without race detector
test-ci-short         ## CI unit-only short tests
test-ci               ## CI full test suite with coverage
test-no-lint          ## Run only tests (no lint)
test-short            ## Run tests excluding integration
test-unit             ## Runs tests and outputs coverage
test                  ## Run lint and all tests
uninstall             ## Uninstall the Go binary
update-linter         ## Upgrade golangci-lint (macOS only)
update-releaser       ## Reinstall GoReleaser
update                ## Update dependencies
vet                   ## Run go vet
```
<!-- make-help-end -->

</details>

<details>
<summary><strong><code>GitHub Workflows</code></strong></summary>
<br/>

| Workflow Name                                                                | Description                                                                                                            |
|------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------|
| [auto-merge-on-approval.yml](.github/workflows/auto-merge-on-approval.yml)   | Automatically merges PRs after approval and all required checks, following strict rules.                               |
| [check-for-leaks.yml](.github/workflows/check-for-leaks.yml)                 | Runs [gitleaks](https://github.com/gitleaks/gitleaks) to detect secrets on a daily schedule.                           |
| [clean-runner-cache.yml](.github/workflows/clean-runner-cache.yml)           | Removes GitHub Actions caches tied to closed pull requests.                                                            |
| [codeql-analysis.yml](.github/workflows/codeql-analysis.yml)                 | Analyzes code for security vulnerabilities using [GitHub CodeQL](https://codeql.github.com/).                          |
| [delete-merged-branches.yml](.github/workflows/delete-merged-branches.yml)   | Deletes feature branches after their pull requests are merged.                                                         |
| [dependabot-auto-merge.yml](.github/workflows/dependabot-auto-merge.yml)     | Automatically merges [Dependabot](https://github.com/dependabot) PRs that meet all requirements.                       |
| [pull-request-management.yml](.github/workflows/pull-request-management.yml) | Labels PRs by branch prefix, assigns a default user if none is assigned, and welcomes new contributors with a comment. |
| [release.yml](.github/workflows/release.yml)                                 | Builds and publishes releases via [GoReleaser](https://goreleaser.com/intro/) when a semver tag is pushed.             |
| [run-tests.yml](.github/workflows/run-tests.yml)                             | Runs linter, Go tests and dependency checks on every push and pull request.                                            |
| [scorecard.yml](.github/workflows/scorecard.yml)                             | Runs [OpenSSF](https://openssf.org/) Scorecard to assess supply chain security.                                        |
| [stale.yml](.github/workflows/stale.yml)                                     | Warns about (and optionally closes) inactive issues and PRs on a schedule or manual trigger.                           |
| [sync-labels.yml](.github/workflows/sync-labels.yml)                         | Keeps GitHub labels in sync with the declarative manifest at [`.github/labels.yml`](./.github/labels.yml).             |

</details>

<details>
<summary><strong><code>Updating Dependencies</code></strong></summary>
<br/>

To update all dependencies (Go modules, linters, and related tools), run:

```bash
make update
```

This command ensures all dependencies are brought up to date in a single step, including Go modules and any tools managed by the Makefile. It is the recommended way to keep your development environment and CI in sync with the latest versions.

</details>

<details>
<summary><strong><code>Pre-commit Hooks</code></strong></summary>
<br/>

Set up the optional [pre-commit](https://pre-commit.com) hooks to run the same formatting, linting, and tests defined in [AGENTS.md](.github/AGENTS.md) before every commit:

```bash
pip install pre-commit
pre-commit install
```

The hooks are configured in [.pre-commit-config.yaml](.pre-commit-config.yaml) and mirror the CI pipeline.

</details>

<br/>

## 🧪 Examples & Tests

All unit tests and [examples](examples) run via [GitHub Actions](https://github.com/bsv-blockchain/go-wire/actions) and use [Go version 1.24.x](https://go.dev/doc/go1.24). View the [configuration file](.github/workflows/run-tests.yml).

Run all tests:

```bash script
make test
```

<br/>

## ⚡ Benchmarks

Run the Go [benchmarks](wire_benchmark_test.go):

```bash script
make bench
```

<br/>

### Benchmark Results

| Benchmark          | Iterations |      ns/op |    B/op | allocs/op |
|--------------------|-----------:|-----------:|--------:|----------:|
| WriteVarInt1       | 39,459,027 |      29.66 |       0 |         0 |
| WriteVarInt3       | 20,199,483 |      58.82 |       0 |         0 |
| WriteVarInt5       | 19,839,806 |      60.09 |       0 |         0 |
| WriteVarInt9       | 20,289,205 |      58.85 |       0 |         0 |
| ReadVarInt1        | 34,616,506 |      34.46 |       0 |         0 |
| ReadVarInt3        | 16,991,710 |      70.22 |       0 |         0 |
| ReadVarInt5        | 17,296,663 |      69.03 |       0 |         0 |
| ReadVarInt9        | 17,292,540 |      68.81 |       0 |         0 |
| ReadVarStr4        | 19,168,129 |      61.24 |       8 |         2 |
| ReadVarStr10       | 17,873,167 |      66.25 |      32 |         2 |
| WriteVarStr4       | 26,292,486 |      44.63 |       8 |         1 |
| WriteVarStr10      | 24,418,180 |      48.74 |      16 |         1 |
| ReadOutPoint       | 28,408,053 |      41.95 |       0 |         0 |
| WriteOutPoint      | 37,229,792 |      31.65 |       0 |         0 |
| ReadTxOut          | 11,092,542 |     108.00 |       0 |         0 |
| WriteTxOut         | 19,576,215 |      61.21 |       0 |         0 |
| ReadTxIn           |  8,187,141 |     148.00 |       0 |         0 |
| WriteTxIn          | 12,787,064 |      93.58 |       0 |         0 |
| DeserializeTxSmall |  2,368,681 |     510.50 |     208 |         5 |
| SerializeTx        |  4,343,654 |     277.00 |       0 |         0 |
| ReadBlockHeader    |  7,429,682 |     160.40 |       0 |         0 |
| WriteBlockHeader   |  7,074,567 |     169.20 |      12 |         3 |
| DecodeGetHeaders   |    198,742 |    5896.00 |   20480 |         2 |
| DecodeHeaders      |      2,761 |  431936.00 |  229380 |         2 |
| DecodeGetBlocks    |    197,142 |    5944.00 |   20480 |         2 |
| DecodeAddr         |      8,107 |  144051.00 |   89730 |      1002 |
| DecodeInv          |        464 | 2573857.00 | 2203667 |         2 |
| DecodeNotFound     |        463 | 2583316.00 | 2203666 |         2 |
| DecodeMerkleBlock  |    736,904 |    1598.00 |    4368 |         3 |
| TxHash             |  2,120,943 |     566.40 |     256 |         2 |
| DoubleHashB        |  6,433,498 |     186.70 |      32 |         1 |
| DoubleHash         |  6,658,620 |     182.00 |       0 |         0 |

> These benchmarks reflect fast, allocation-free lookups for most retrieval functions, ensuring optimal performance in production environments.
> Performance benchmarks for the core functions in this library, executed on an Apple M1 Max (ARM64).

<br/>

## 🛠️ Code Standards
Read more about this Go project's [code standards](.github/CODE_STANDARDS.md).

<br/>

## 🤖 AI Compliance
This project documents expectations for AI assistants using a few dedicated files:

- [AGENTS.md](.github/AGENTS.md) — canonical rules for coding style, workflows, and pull requests used by [Codex](https://chatgpt.com/codex).
- [CLAUDE.md](.github/CLAUDE.md) — quick checklist for the [Claude](https://www.anthropic.com/product) agent.
- [.cursorrules](.cursorrules) — machine-readable subset of the policies for [Cursor](https://www.cursor.so/) and similar tools.
- [sweep.yaml](.github/sweep.yaml) — rules for [Sweep](https://github.com/sweepai/sweep), a tool for code review and pull request management.

Edit `AGENTS.md` first when adjusting these policies, and keep the other files in sync within the same pull request.

<br/>

## 👥 Maintainers
| [<img src="https://github.com/icellan.png" height="50" alt="Siggi Oskarsson" />](https://github.com/icellan) |
|:------------------------------------------------------------------------------------------------------------:|
|                                     [Siggi](https://github.com/icellan)                                      |

<br/>

## 🤝 Contributing
View the [contributing guidelines](.github/CONTRIBUTING.md) and please follow the [code of conduct](.github/CODE_OF_CONDUCT.md).

### How can I help?
All kinds of contributions are welcome :raised_hands:!
The most basic way to show your support is to star :star2: the project, or to raise issues :speech_balloon:.
You can also support this project by [becoming a sponsor on GitHub](https://github.com/sponsors/bsv-blockchain) :clap:
or by making a [**bitcoin donation**](https://gobitcoinsv.com/#sponsor?utm_source=github&utm_medium=sponsor-link&utm_campaign=go-wire&utm_term=go-wire&utm_content=go-wire) to ensure this journey continues indefinitely! :rocket:

[![Stars](https://img.shields.io/github/stars/bsv-blockchain/go-wire?label=Please%20like%20us&style=social&v=1)](https://github.com/bsv-blockchain/go-wire/stargazers)

<br/>

## 📝 License

[![License](https://img.shields.io/github/license/bsv-blockchain/go-wire.svg?style=flat&v=1)](LICENSE)
