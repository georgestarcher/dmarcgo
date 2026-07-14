# Wiki maintenance

> **Navigation guide, not a versioned contract.** This page tracks `dmarcgo` v2. Repository source and the publishing workflow define the wiki content.

## Canonical source

The Markdown files under
[`docs/wiki`](https://github.com/georgestarcher/dmarcgo/tree/main/docs/wiki)
are the only editable source. Do not edit the rendered GitHub wiki directly
after its initial bootstrap page has been created.

## Change workflow

1. Edit the repository source in a normal pull request.
2. Run `make wiki-check` locally.
3. Let pull-request CI validate navigation, required sections, repository links,
   filenames, and common sensitive-data markers.
4. Merge only after normal review and CI.
5. The trusted `main` workflow replaces the wiki contents deterministically and
   publishes only when source changed.

## Security boundary

Pull requests receive read-only repository access and never publish. Publishing
runs only for trusted `main` or a manually dispatched trusted revision, uses the
workflow's short-lived GitHub token, and requests write permission only in the
publish job. The repository keeps normal wiki editing restricted to
collaborators.

## Initial bootstrap and manual recovery

GitHub does not create the wiki Git repository until an initial page exists.
An administrator creates a temporary `Home` page once, then runs the trusted
publish workflow to replace it from canonical source. If automated publication
is unavailable, an authorized maintainer may run `scripts/publish_wiki.sh`
locally with their existing Git credentials. Do not add a long-lived wiki token
or personal access token to pull-request workflows.

## Privacy review

Wiki examples must remain synthetic. Never add real report contents, source IPs,
private domains, record-name inventories, campaign details, contacts,
credentials, local paths, or private provider overlays.

## Authoritative references

- [GitHub wiki publishing workflow](https://github.com/georgestarcher/dmarcgo/blob/main/.github/workflows/wiki.yml)
- [Wiki validation script](https://github.com/georgestarcher/dmarcgo/blob/main/scripts/check_wiki.py)
- [Agent guide](https://github.com/georgestarcher/dmarcgo/blob/main/AGENTS.md)
- [GitHub: adding or editing wiki pages](https://docs.github.com/en/communities/documenting-your-project-with-wikis/adding-or-editing-wiki-pages)
- [GitHub: wiki sidebars and footers](https://docs.github.com/en/communities/documenting-your-project-with-wikis/creating-a-footer-or-sidebar-for-your-wiki)
- [GitHub: automatic token authentication](https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication)
- [GitHub: secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
