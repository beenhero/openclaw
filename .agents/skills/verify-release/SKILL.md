---
name: verify-release
description: "Verify regular or extended-stable OpenClaw releases against the exact publication surfaces, workflow identities, package provenance, smoke tests, and live Gateway behavior expected for that release track."
---

# Verify Release

Use this when asked whether an OpenClaw release is fully released, published,
promoted, smoke-tested, or live-verified. This is a verification skill, not a
publish skill; use `$release-openclaw-maintainer` before changing release state.

## Rules

- Resolve short suffixes like `.27` to the concrete CalVer version from the
  current date/context, then say the resolved version.
- Resolve the release track before choosing checks. Regular beta/stable uses a
  GitHub Release and the orchestrated platform graph. Extended-stable uses the
  canonical `extended-stable/YYYY.M.33` branch, npm `extended-stable`, and only
  the surfaces named by the current release policy. Never fail one track for an
  artifact owned only by the other.
- Verify live state. Do not trust local checkout state, release notes, or old
  memory as current truth.
- If the checkout is dirty or divergent, use it only for scripts/reference.
  For version metadata, fetch from GitHub release/tag or unpack the tag tarball
  under `/tmp`.
- Never print secrets. Use inherited live keys only for scoped smoke commands.
- Keep the final terse: `yes/no`, evidence bullets, caveats, cleanup.

## Regular beta/stable checks

Use these checks only for the regular orchestrated release track.

1. GitHub release:
   - `gh release view v<VERSION> --repo openclaw/openclaw --json tagName,name,publishedAt,isDraft,isPrerelease,targetCommitish,url,body,assets`
   - Confirm stable releases are not draft/prerelease.
   - Confirm release body has npm, CI, plugin npm, ClawHub, mac/appcast evidence
     links when expected.
   - Confirm assets expected for stable mac releases are uploaded: zip, dmg,
     dSYM, dependency evidence, immutable full-validation manifest,
     postpublish evidence, and stable-main closeout manifest.
   - Download each immutable evidence asset and its `.sha256` companion, then
     verify the checksum before trusting the release record.
2. Root npm:
   - `npm view openclaw@<VERSION> version dist-tags.latest dist.tarball dist.integrity time.<VERSION> --json`
   - `latest` must equal `<VERSION>` for stable.
   - Record tarball, integrity, publish time.
   - Confirm the release postpublish evidence records
     `npmRegistrySignaturesVerified: true` and
     `npmProvenanceAttestationMatched: true`.
3. Plugin publish set:
   - Get exact tag metadata from GitHub, not the local checkout when dirty:
     download `https://api.github.com/repos/openclaw/openclaw/tarball/v<VERSION>`
     into `/tmp/openclaw-v<VERSION>-src`.
   - Count `extensions/*/package.json` with
     `openclaw.release.publishToNpm === true` and
     `openclaw.release.publishToClawHub === true`.
   - Compare expected counts to workflow job counts:
     `gh api repos/openclaw/openclaw/actions/runs/<RUN>/jobs --paginate`.
   - Each expected npm plugin must have version `<VERSION>` and
     `dist-tags.latest === <VERSION>`.
4. ClawHub:
   - Check the Plugin ClawHub Release workflow conclusion and publish job count.
   - Use OpenClaw itself for live registry proof:
     `openclaw plugins search <known-plugin> --json`.
   - Install one official plugin from ClawHub in an isolated HOME:
     `openclaw plugins install clawhub:@openclaw/matrix --pin`.
     Prefer `matrix` unless that plugin is not in the expected set.
5. Release workflows:
   - Verify conclusions for release notes evidence links:
     Full Release Validation, OpenClaw Release Checks, OpenClaw NPM Release,
     Plugin NPM Release, Plugin ClawHub Release, mac preflight/validation/publish
     when stable mac assets are expected.
   - For stable, verify `OpenClaw Stable Main Closeout` succeeded and its
     manifest records the matching release tag, current rollback drill, stable
     soak, and blocking performance evidence.
   - Summarize only relevant successful/failed jobs; ignore routine skipped
     optional lanes unless the release body promised them.

## Extended-stable checks

Extended-stable has no GitHub Release ledger. Reconstruct it from live tag,
workflow, registry, provenance, and image state.

1. Identity:
   - Require final `v<VERSION>` with patch `>= 33`, no prerelease/correction
     suffix, and containment in `extended-stable/YYYY.M.33`. Tip equality is
     required only for an active candidate; later patches advance the branch.
   - Read metadata from the tag. Root and every npm-publishable official plugin
     must declare `<VERSION>`.
   - Require the Git tag and no published GitHub Release.
2. Workflow chain:
   - Find successful preflight, complete Full Release Validation, plugin npm,
     and core publish runs on the canonical branch and release SHA.
   - Require validation `rerun_group=all`, `release_profile=stable`, blocking
     soak/performance evidence, and the saved successful attempt.
   - Require core publish to reference those three run IDs and attempt; bind its
     manifest, workflow ref, and prepared tarball digest to the release SHA.
3. Registry inventory:
   - Require both `openclaw@<VERSION>` and `openclaw@extended-stable` to return
     `<VERSION>`; `latest` is irrelevant.
   - From preflight `corePackageTarballs`, verify every prepared core package at
     its exact version and selector.
   - From the tag, derive every `publishToNpm === true` official plugin and
     compare its exact version/selector with the plugin plan, jobs, and complete
     readback. Never infer inventory from changed paths.
4. Provenance and install:
   - Run `node --import tsx scripts/openclaw-npm-postpublish-verify.ts <VERSION>`
     from trusted current tooling. Require registry signatures and npm
     provenance for the canonical branch, plus publish/preflight digest binding
     to the release SHA. Preserve output and workflow URLs.
5. Docker:
   - Require the tag-triggered run to verify exact default, slim, browser, and
     architecture images plus attestations in GHCR and Docker Hub.
   - Require only the three `extended-stable*` aliases to resolve to those
     digests; regular aliases must not move. Alias repair requires a successful
     current-main `Docker Channel Promotion` for the exact tag, with no rebuild.
6. Recovery and exclusions:
   - Reuse existing immutable versions. Repair only root with the generated
     command; use approved credential-isolated tooling for prepared-core/plugin
     selectors, then repeat full readback.
   - Do not require ClawHub, native apps, mobile, website, private dist-tags,
     regular `latest`, or a GitHub Release unless policy adds that surface.

## Shared live smoke

After the track-specific publication checks pass:

1. Published package smoke:
   - In `/tmp`, isolated HOME:
     `npm exec --yes --package openclaw@<VERSION> -- openclaw --version`.
   - Run at least one harmless command that touches the published CLI surface,
     for example `plugins --help` or `gateway --help`.
2. Dev Gateway live model smoke:
   - Use temp HOME/workspace, not the user's normal state:
     `HOME=/tmp/openclaw-release-smoke/home OPENCLAW_WORKSPACE=/tmp/openclaw-release-smoke/work pnpm openclaw --dev gateway run --auth none --force --verbose`.
   - Health check via CLI: `openclaw --dev gateway health --json`.
   - Run one Gateway-backed agent turn with inherited `OPENAI_API_KEY`, short
     prompt, explicit session key, JSON output, and a known-available model.
   - If the configured default model fails as unavailable, record that caveat
     and retry with the newest known-good OpenAI model instead of declaring the
     release failed.
   - Stop the gateway and verify the port is not listening.

## Caveats To Report

- Dist-tag caveat: stable `latest` is release truth; if optional `beta` mirrors
  still point at a beta version, report it as a caveat, not a stable-release
  blocker, unless the user asked to verify beta promotion.
- Track caveat: state which release track was resolved and which publication
  surfaces are intentionally absent. For extended-stable, never describe the
  absence of regular-release artifacts as incomplete publication.
- Divergent checkout caveat: say when local source SHA differs from release tag
  or origin and which live sources were used instead.
- Smoke caveat: distinguish Gateway-backed agent success from local embedded
  fallback. A valid Gateway smoke has health OK plus gateway log/run id for the
  agent call.
