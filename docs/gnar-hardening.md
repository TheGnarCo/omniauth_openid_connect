# Gnar hardening of this fork

This fork of [omniauth_openid_connect](https://github.com/omniauth/omniauth_openid_connect) is maintained by The Gnar for the CPPD Portal, which signs everyone in through one Commonwealth Entra tenant. The README's "Gnar hardening" section lists each protection and its option name. This file records how the fork is built, what it deliberately leaves to the application, and what to watch when changing it.

## Base and version

- Base: upstream `master` at `4847685`, which is release 0.8.0 plus 12 later commits.
- Version: `0.8.0.gnar.1`. RubyGems treats it as a prerelease, so it sorts below `0.8.0` and does not satisfy `~> 0.8`. That is fine for a `path:` or git source in a Gemfile.
- Ruby: the fork is developed and tested on Ruby 4.0 only, the version the portal uses. The CI workflow runs Ruby 4.0. Upstream tests older Rubies; this fork has not been run on them.

## Decisions built into the fork

- Authorization code flow only. Any `response_type` other than `code` raises `ConfigurationError`. The implicit flow was removed in one commit (`feat: accept only response_type code`), so reverting that commit restores it.
- `response_mode` is unset or `query`. Entra redirects back with `?code=...&state=...` as a GET, so the callback needs no `SameSite=None` cookie and no forgery-check skip. Any other value raises `ConfigurationError`.
- The ID token is required and verified. UserInfo is not called. `uid` is `sub`. The email claim is not mapped into `info`; all claims are in `extra.raw_info`.
- Identity is (`tid`, `oid`) from `extra.raw_info`. Email is never an identity.
- One set of sign-in values (state, nonce, PKCE verifier) is stored per provider in the session. A second sign-in tab on the same provider overwrites the first. OmniAuth 2.3 and later can track several sign-ins at once; the fork does not use that.
- The GET logout route is disabled. The application builds sign-out and can use `logout_redirect_url`.

## Code layout

There is no subclass layer on top of the gem; the fork is the library. Edits to `lib/omniauth/strategies/openid_connect.rb` are kept small. New mechanisms live in their own files so a merge from upstream touches few lines:

- `lib/omniauth/openid_connect/fetch_cache.rb`: process-wide cache for the discovery document and the key set, with timeouts, failure caching, stale serving and a minimum interval between forced key refreshes.
- `lib/omniauth/openid_connect/scoped_session.rb`: per-provider session keys.
- `test/support/fake_entra.rb` and `test/support/browser.rb`: an in-process fake identity provider and a driver for it. The fake is mounted through WebMock, so the suite needs no extra gems and no loopback server, apart from one real-socket test that proves read timeouts reach the HTTP client.

## Left to the application

The callback and failure controllers, session reset on sign-in, account linking, the `tid` check (the application checks that `tid` is the Commonwealth tenant's id), the helper that reads the `email` claim for invitation and CPPD staff matching, sign-out and `sign_out_via`, resetting the inactivity timestamps, log parameter filtering, and `OmniAuth.config.allowed_hosts` or `full_host`.

## Gotchas when changing it

- OmniAuth `test_mode` is global and set to true in `test/test_helper.rb`. The matrix tests switch it off and restore it.
- OmniAuth 2.4.1 turns any exception raised in a phase into `fail!(message)`, which could leak provider text. The strategy rescues errors itself and re-raises `ConfigurationError`.
- `OpenIDConnect.http_config` is global and the first block set wins, so timeouts are set per request instead.
- Bundler 4 cannot resolve this repo because `guard-bundler` requires Bundler below 3. Use Bundler 2.7.2.
- Several upstream tests were changed on purpose because the behavior they check changed (session key names, UserInfo, logout, `response_mode`, `response_type`, `uid`, PKCE, HS256). `CHANGELOG.md` lists the behavior changes. Expect conflicts in `test/lib/omniauth/strategies/openid_connect_test.rb` when merging upstream.

## Not yet verified

None of this has run against a real Entra tenant; the tests use the in-process fake. Still to confirm there: which hosts `jwks_uri` and `end_session_endpoint` are on (the fork refuses anything outside `login.microsoftonline.com` unless `allowed_endpoint_hosts` says otherwise), how the client authenticates at the token endpoint, whether ID tokens carry `azp`, token sizes, clock skew, and the first sign-in of an invited guest.
