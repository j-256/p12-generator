# Repository instructions

## Read first

Read `README.md` and `NOTICE` before changing behavior. This repository's primary product is a static browser application that turns a Salesforce B2C Commerce certificate-authority bundle into a client certificate. The browser-only privacy claim and the inspectable, unminified application source are product contracts, not incidental implementation details.

Keep the README's operator workflow, cryptographic description, privacy claims, and release instructions aligned with the implementation. Preserve the attribution for the node-forge-derived PKCS#12 routine and bundled dependencies in `NOTICE`.

## Privacy and secret handling

- Keep CA private keys, CA passwords, generated private keys, export passwords, and derived PKCS#12 bytes in the browser process. The only intended escape is the user's explicit `.p12` download.
- Do not add a backend, telemetry, analytics, runtime API calls, remote cryptographic assets, or browser persistence for uploaded or derived material. Runtime dependencies must remain local static assets.
- Never log, render, copy, or include secret contents in errors. Progress messages and filenames may be shown, but uploaded key or password contents, generated key material, export passwords, and PKCS#12 bytes must not appear in the page console, developer console, screenshots, fixtures, or commits.
- Revoke download object URLs after use and invalidate the pending download whenever any form field or selected file changes. A certificate generated from stale inputs must not remain downloadable.
- `generate-p12` is a separate local OpenSSL helper that writes secret-bearing files. Do not run it against real CA material for routine verification, print its passwords or keys, or commit any generated `.key`, `.p12`, request, certificate, password, or bundle file.

## Untrusted input and archive handling

- Treat hostnames, uploaded filenames, archive paths, parser errors, and subject fields as untrusted. Render dynamic text with `textContent`, `createTextNode`, or equivalent escaping; do not interpolate it into `innerHTML` or executable markup.
- Keep uploaded files in `Map`-like storage rather than a prototype-backed object. Filenames such as `__proto__` must remain ordinary data.
- Preserve support for a certificate bundle inside an optional containing directory. Flatten archive paths to basenames, ignore directory entries, and reject duplicate basenames or collisions with separately uploaded files rather than choosing or overwriting one silently.
- Select the highest complete numbered CA bundle for generation. A highest partial bundle may guide missing-file feedback, but it must not displace a lower complete bundle.
- Read only the first line of the CA password file while preserving every character on that line, including leading and trailing whitespace.

## Certificate and PKCS#12 contracts

- Reject a CA certificate that lacks certificate-signing authority, a CA private key that does not match the certificate, an invalid or inactive CA validity period, or a requested client-certificate lifetime beyond the CA expiration.
- Keep generation RSA-based and keep signing, PKCS#12 encryption, MAC, KDF, salt, certificate-chain encryption, and local-key-ID choices explicit. Do not weaken or silently downgrade them; unsupported algorithms and malformed iteration or salt options must fail.
- Preserve the PKCS#12 contents and associations: the generated private key, leaf certificate, and CA certificate chain must parse with the export password, and the leaf certificate and private key must share their friendly-name and local-key-ID attributes.
- The `.srl` file remains part of the expected source bundle, but browser generation derives a serial from the current timestamp rather than mutating shared CA state.
- `createPkcs12Asn1` is intentionally adapted from node-forge so the MAC can be selected and the certificate chain can be encrypted. Treat changes to it as cryptographic changes: keep the attribution, compare behavior with the relevant standards and consumers, and add interoperability-focused regression tests.

## Source and generated assets

- Keep `main.js` readable and unminified because users can inspect the code that handles their private material. Do not fold it into the minified dependency bundle.
- `webpack-entry.js` exposes the pinned npm dependencies as browser globals, and `npm run build` regenerates tracked `static/libraries.js`. Edit the entrypoint, dependency declarations, or lockfile rather than the generated bundle, then inspect and commit the resulting bundle diff.
- Preserve the static-only deployment model. The application must work from `index.html`, same-origin local assets, `main.js`, and `static/libraries.js` without a server-side runtime.
- When the visible form changes, rebuild first and use `npm run screenshots` to refresh the documented images. Keep screenshot inputs fabricated and never load certificate material into that workflow.

## Verification and releases

- Use `npm ci` to install the locked dependencies in a fresh checkout or worktree.
- Run `npm test` for repository changes. Add focused tests for certificate validation, archive normalization, password parsing, PKCS#12 structure, stale-download handling, and safe rendering as applicable.
- Run `npm run build` whenever dependencies, `webpack-entry.js`, Webpack configuration, or browser integration changes. Use `npm run release:check` for release-ready verification because it combines tests with the production build.
- Browser checks must use generated or obviously fabricated inputs. Do not upload a real CA bundle merely to validate a code change.
- Use `npm version` only for an explicitly requested release. It requires a clean synchronized `main`, runs the release checks, creates the version commit and tag, and pushes both refs; it is not a harmless version-edit or verification command.
