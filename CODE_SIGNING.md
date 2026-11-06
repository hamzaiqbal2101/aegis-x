# Code signing policy — AEGIS X

Draft prepared 2026-11-04. Not yet pushed to the repository; it takes effect
only once it is committed to `github.com/hamzaiqbal2101/aegis-x`.

## What is signed

- Only official release builds of AEGIS X are signed: the Windows MSI
  (`packaging/windows/aegis-x.msi`) built from a tagged GitHub Release.
- Test, development and self-signed builds are never presented as official
  releases. A self-signed build is trusted only on the machine that created
  it, and is labelled as such.

## How signing works (planned route: SignPath Foundation)

- Signing is done only through an automated build on a GitHub-hosted runner
  (GitHub Actions), never by uploading a private key or by signing a binary
  on a personal machine and distributing it.
- The signing certificate is held by SignPath Foundation, so the Windows
  install dialog will show the publisher as "SignPath Foundation", not
  "Hamza Iqbal". That is the tradeoff of the free route.
- No private key, certificate file, token or secret is ever committed to
  this repository, and no signing credential is shared in chat or email.

## What is signed, and what is not

- Signed: the MSI installer for a tagged release, built from the exact
  commit that the release tag points to.
- Not signed, and never claimed to be signed: individual files, zips,
  dashboard images, or builds from an untagged commit.

## Verification before a release is announced

1. The release tag matches the commit that was built.
2. The MSI's signature verifies (Windows: `Get-AuthenticodeSignature`
   shows a valid, trusted signature, not just a self-signed one).
3. A clean install and uninstall are tested before the release is announced
   as signed.

## If signing is unavailable

- If the free signing route is not approved or is unavailable, releases ship
  unsigned and are labelled unsigned. Windows will show an "Unknown
  publisher" warning in that case; users must not be told to bypass it
  without understanding that warning.
- The fallback own-name option (paid, e.g. Certum Open Source) is a
  separate decision and is not authorised by this document.

## Status

- Public repository: done (github.com/hamzaiqbal2101/aegis-x, pushed
  2026-11-04, commit dd59e7ce).
- This policy document and an MIT LICENSE: drafted, awaiting approval to push.
- GitHub Release, GitHub Actions workflow, account MFA, and the SignPath
  application itself: still to do, and each needs the maintainer's own step.
