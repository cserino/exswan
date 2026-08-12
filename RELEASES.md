# Releases

ExSwan contains two independent Hex packages. Each package has its own version, changelog, GitHub release, and Hex release.

## Version policy

The packages follow Semantic Versioning. Before 1.0, a minor version can contain breaking changes. A patch version must remain compatible with the current minor line.

The `0.x` series is alpha software. APIs and behavior can change as WebAuthn compatibility work continues. Release notes must identify breaking changes and security-relevant changes.

Package tags include the package name:

- `exswan-v0.1.0`
- `exswan_plug-v0.1.0`

## Initial alpha release

The repository starts with version `0.1.0` in both package files. Bootstrap that release once, before release-please manages later versions:

1. Replace `Unreleased` in both `0.1.0` changelog headings with the release date.
2. Run `make release-check` from a clean checkout.
3. Commit the release state to `main`.
4. Create the signed tags `exswan-v0.1.0` and `exswan_plug-v0.1.0` on that commit, then push them.
5. Create a GitHub prerelease for each tag. Approve the `exswan` Hex deployment first. Approve `exswan_plug` only after Hex shows `exswan` version `0.1.0`.

Do not change `.release-please-manifest.json` during this bootstrap. It records the versions that release-please will treat as the starting point for later releases.

## Release preparation

[release-please](https://github.com/googleapis/release-please) maintains versions and changelogs from Conventional Commit messages. Manifest mode lets each package release independently.

The workflow uses `GITHUB_TOKEN` by default. In repository Actions settings, allow GitHub Actions to create pull requests. If release PRs must trigger other workflows automatically, add a fine-grained `RELEASE_PLEASE_TOKEN` secret with access limited to this repository and permission to write contents and pull requests.

Use these commit types for package changes:

- `fix`: a compatible bug fix;
- `feat`: a compatible feature;
- `feat!` or a `BREAKING CHANGE:` footer: a breaking change;
- `docs`, `test`, `build`, `ci`, `chore`, and `refactor`: no release unless the commit includes a release-relevant footer.

Scope commits when it improves clarity, for example `fix(exswan): reject an invalid RP ID hash`.

When release-please opens a release PR:

1. Review the version for every changed package.
2. Edit the generated changelog so it explains user impact, migration steps, and security effects.
3. Confirm that a new `exswan_plug` version depends on an `exswan` version that already exists on Hex or will publish first.
4. Run `make release-check` from a clean checkout.
5. Merge the release PR only after CI passes.

Merging the release PR creates a package-specific tag and GitHub release. The publish workflow then uses that immutable tag.

## Hex publication

The `Publish Hex package` workflow publishes the package selected by the release tag. Configure a GitHub environment named `hex.pm`, add `HEX_API_KEY` as an environment secret, and require a maintainer's approval for that environment.

Use a Hex API key limited to `api:write`. If the packages belong to a Hex organization, use an organization key instead of a personal key.

For the first release, trigger the publish workflow manually from the GitHub release tag. This keeps the final publish step deliberate while the automation is new. After the workflow has completed successfully for both packages, automatic publication from later GitHub releases is reasonable.

Publish `exswan` before `exswan_plug`. Hex cannot publish `exswan_plug` until its declared `exswan` dependency is available.

## Recovery

Hex permits a new release to be reverted for a limited period. Do not replace a release to hide a normal defect. Revert a release only for a serious packaging or security problem, then publish a new patch version with a clear explanation.

If automation fails after creating a GitHub release, fix or rerun the publish workflow against the same tag. Do not move or recreate a published tag.
