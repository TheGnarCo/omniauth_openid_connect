# OmniAuth::OpenIDConnect

Originally was [omniauth-openid-connect](https://github.com/jjbohn/omniauth-openid-connect)

I've forked this repository and launch as separate gem because maintaining of original was dropped.

[![Build Status](https://github.com/omniauth/omniauth_openid_connect/actions/workflows/main.yml/badge.svg)](https://github.com/omniauth/omniauth_openid_connect/actions/workflows/main.yml)
[![Coverage Status](https://coveralls.io/repos/github/omniauth/omniauth_openid_connect/badge.svg)](https://coveralls.io/github/omniauth/omniauth_openid_connect)

## Gnar hardening

This is The Gnar's fork of `omniauth_openid_connect`, version `0.8.0.gnar.N`. It tracks upstream `master` and adds
the protections below to the strategy itself. They are on by default. Where this section and the rest of the README
disagree, this section is right.

| Protection | Option | Default |
|---|---|---|
| PKCE with S256. Any other `code_challenge_method` raises `ConfigurationError`. | `pkce` | `true` |
| Nonce and PKCE verifier come from the session only, never from the callback request. A missing session nonce (with `send_nonce`) or verifier fails the sign-in. | | |
| State is checked first, in constant time, before anything else in the callback. A provider error then fails with its error code only; `error_description` and `error_uri` are never logged or shown. Codes that are not lowercase words become `provider_error`. | | |
| Token endpoint errors fail with the error code only, not the provider's description. | | |
| Session keys for state, nonce, verifier, `omniauth.params` and `omniauth.origin` are per provider (`omniauth.state.<name>`). | | |
| The ID token is required and validated: signature, `iss`, `aud`, `exp`, nonce, plus `nbf` with leeway and `azp` (required with several audiences, must equal the client id when present). Only `RS256` unless configured. | `nbf_leeway`, `client_signing_alg` | `60`, `:RS256` |
| No UserInfo call. Claims come from the verified ID token. `uid` is always `sub`; `info` has no email. All claims are in `extra.raw_info`. | | |
| Metadata from a discovery URL separate from the issuer. The document's issuer must equal `issuer`. `discovery_url` and `issuer` must be https. | `discovery_url`, `issuer` | |
| Authorization, token, key set and end-session endpoints from discovery must be https on an allowed host. | `allowed_endpoint_hosts` | the `discovery_url` host |
| Discovery document and key set cached per process. One fetch at a time per URL; a failed fetch is remembered; an expired value is served while its refresh fails, logged at ERROR, with a shorter cap for keys. A token with an unknown `kid` forces one key set refresh. | `metadata_ttl`, `jwks_ttl`, `stale_ttl`, `jwks_stale_ttl`, `negative_ttl` | `3600`, `900`, `3600`, `300`, `10` seconds |
| Discovery and key set responses: no redirects followed, at most 512 KB, no compression. | | |
| Forced key set refreshes (unknown `kid`) happen at most once per interval per key set, and only for a token whose unverified `iss`, `aud` and `exp` are already right, so a provider that keeps serving tokens with unknown keys cannot cause a fetch per sign-in. | `jwks_min_refresh_interval` | `60` seconds |
| Open and read timeouts on discovery, key set and token requests, set per request (not through the global `OpenIDConnect.http_config`). | `open_timeout`, `read_timeout` | `3`, `5` seconds |
| `redirect_uri` is always the configured value; a `redirect_uri` request parameter is ignored. | `client_options.redirect_uri` | |
| Only the authorization code flow: `response_type` must be unset or `code`; anything else raises `ConfigurationError`. The implicit (`id_token`) flow was removed on purpose. To restore it, revert the commit "feat: accept only response_type code". | `response_type` | `code` |
| `response_mode` must be unset or `query`; anything else raises `ConfigurationError`. | `response_mode` | unset |
| `client_auth_method` must be unset, `:basic` or `:post`; anything else raises `ConfigurationError`. | `client_auth_method` | `:basic` |
| The gem's `GET <request path>/logout` route is removed. The app builds sign-out with `logout_redirect_url`. | | |

Removed options: `uid_field`, `logout_path`.

### Example (single Microsoft Entra tenant)

```ruby
provider :openid_connect, {
  name: :entra,
  issuer: "https://login.microsoftonline.com/#{tenant_id}/v2.0",
  discovery_url: "https://login.microsoftonline.com/#{tenant_id}/v2.0/.well-known/openid-configuration",
  scope: %i[openid profile email],
  post_logout_redirect_uri: "https://app.example.com/users/sign_in",
  client_options: {
    identifier: client_id,
    secret: client_secret,
    redirect_uri: "https://app.example.com/users/auth/entra/callback",
  },
}
```

The identity is the app's decision. For Entra use `tid` and `oid` from `extra.raw_info`; never an email claim.

### Sign-out

```ruby
strategy = OmniAuth::Strategies::OpenIDConnect.new(nil, provider_options)
url = strategy.logout_redirect_url(logout_hint: hint, state: state) # also id_token_hint:
```

Returns the end-session URL with `post_logout_redirect_uri` from configuration, or `nil` if the provider publishes no
end-session endpoint. Raises `OmniAuth::OpenIDConnect::FetchCache::FetchFailed` if the discovery document cannot be
fetched.

### Failure types

`csrf_detected`, the provider's error code (for example `access_denied`, `invalid_grant`, `invalid_client`),
`provider_error`, `missing_nonce`, `missing_code_verifier`, `missing_code`, `missing_id_token`, `invalid_id_token`,
`invalid_jwt_algorithm`, `invalid_response`, `discovery_failed`, `jwks_failed`, `timeout`, `failed_to_connect`.
Configuration problems raise `OmniAuth::OpenIDConnect::ConfigurationError` instead of failing the sign-in.

### Left to the application

Callback controller and failure handler, session reset on sign-in, account linking, the tenant (`tid`) check,
parameter filtering for logs (`code`, `state` and your own parameters), `OmniAuth.config.allowed_hosts` or
`full_host`, and a sign-out route that does not accept GET.

## Installation

Add this line to your application's Gemfile:

    gem 'omniauth_openid_connect'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install omniauth_openid_connect

## Supported Ruby Versions

This fork is tested under Ruby 4.0, the version the portal runs. Upstream tests older Rubies, and this fork has not been run on them.

## Usage

Example configuration

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :openid_connect, {
    name: :my_provider,
    scope: [:openid, :email, :profile, :address],
    response_type: :code,
    client_options: {
      port: 443,
      scheme: "https",
      host: "myprovider.com",
      identifier: ENV["OP_CLIENT_ID"],
      secret: ENV["OP_SECRET_KEY"],
      redirect_uri: "http://myapp.com/users/auth/openid_connect/callback",
    },
  }
end
```

### with Devise
```ruby
Devise.setup do |config|
  config.omniauth :openid_connect, {
    name: :my_provider,
    scope: [:openid, :email, :profile, :address],
    response_type: :code,
    client_options: {
      port: 443,
      scheme: "https",
      host: "myprovider.com",
      identifier: ENV["OP_CLIENT_ID"],
      secret: ENV["OP_SECRET_KEY"],
      redirect_uri: "http://myapp.com/users/auth/openid_connect/callback",
    },
  }
end
```

### Options Overview

| Field                        | Description                                                                                                                                                              | Required | Default                       | Example/Options                                     |
|------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|-------------------------------|-----------------------------------------------------|
| name                         | Arbitrary string to identify connection and identify it from other openid_connect providers                                                                              | no       | String: openid_connect        | :my_idp                                             |
| issuer                       | Root url for the authorization server                                                                                                                                    | yes      |                               | https://myprovider.com                              |
| discovery                    | Should OpenID discovery be used. This is recommended if the IDP provides a discovery endpoint. See client config for how to manually enter discovered values.            | no       | false                         | one of: true, false                                 |
| client_auth_method           | Which authentication method to use to authenticate your app with the authorization server                                                                                | no       | Sym: basic                    | "basic", "jwks"                                     |
| scope                        | Which OpenID scopes to include (:openid is always required)                                                                                                              | no       | Array<sym> [:openid]          | [:openid, :profile, :email]                         |
| response_type                | Which OAuth2 response type to use with the authorization request                                                                                                         | no       | String: code                  | 'code' (anything else is refused)                   |
| state                        | A value to be used for the OAuth2 state parameter on the authorization request. Can be a proc that generates a string.                                                   | no       | Random 16 character string    | Proc.new { SecureRandom.hex(32) }                   |
| require_state                | Should the callback phase require that a state is present. If `send_state` is true, then the callback state must match the authorize state. This is recommended, not required by the OIDC specification. | no       | true                          | false                                               |
| send_state                   | Should the authorize phase send a `state` parameter - this is recommended, not required by the OIDC specification                                                        | no       | true                          | false                                               |
| response_mode                | The response mode per [spec](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)                                                                         | no       | nil                           | :query (anything else is refused)                   |
| display                      | An optional parameter to the authorization request to determine how the authorization and consent page                                                                   | no       | nil                           | one of: :page, :popup, :touch, :wap                 |
| prompt                       | An optional parameter to the authorization request to determine what pages the user will be shown                                                                        | no       | nil                           | one of: :none, :login, :consent, :select_account    |
| send_scope_to_token_endpoint | Should the scope parameter be sent to the authorization token endpoint?                                                                                                  | no       | true                          | one of: true, false                                 |
| post_logout_redirect_uri     | The logout redirect uri to use per the [session management draft](https://openid.net/specs/openid-connect-session-1_0.html)                                              | no       | empty                         | https://myapp.com/logout/callback                   |
| extra_authorize_params       | A hash of extra fixed parameters that will be merged to the authorization request                                                                                        | no       | Hash                          | {"tenant" => "common"}                              |
| allow_authorize_params       | A list of allowed dynamic parameters that will be merged to the authorization request                                                                                    | no       | Array                         | [:screen_name]                                      |
| pkce                         | Enable [PKCE flow](https://oauth.net/2/pkce/)                                                                                                                            | no       | true                          | one of: true, false                                 |
| pkce_verifier                | Specify a custom PKCE verifier code.                                                                                                                                     | no       | A random 128-char string      | Proc.new { SecureRandom.hex(64) }                   |
| pkce_options                 | Specify a custom implementation of the PKCE code challenge/method.                                                                                                       | no       | SHA256(code_challenge) in hex | Proc to customise the code challenge generation     |
| client_options               | A hash of client options detailed in its own section                                                                                                                     | yes      |                               |                                                     |
| jwt_secret_base64            | For HMAC with SHA2 (e.g. HS256) signing algorithms, specify the base64-encoded secret used to sign the JWT token. Defaults to the OAuth2 client secret if not specified. | no       | client_options.secret         | "bXlzZWNyZXQ=\n"                                    |
| acr_values                   | Authentication Class Reference (ACR) values to be passed to the authorize_uri to enforce a specific level, see [RFC9470](https://www.rfc-editor.org/rfc/rfc9470.html)    | no       | nil                           | "c1 c2"                                             |

### Client Config Options

These are the configuration options for the client_options hash of the configuration.

| Field                  | Description                                                     | Default    | Replaced by discovery? |
|------------------------|-----------------------------------------------------------------|------------|------------------------|
| identifier             | The OAuth2 client_id                                            |            |                        |
| secret                 | The OAuth2 client secret                                        |            |                        |
| redirect_uri           | The OAuth2 authorization callback url in your app               |            |                        |
| scheme                 | The http scheme to use                                          | https      |                        |
| host                   | The host of the authorization server                            | nil        |                        |
| port                   | The port for the authorization server                           | 443        |                        |
| audience               | The intended consumer (`aud` field) of the id_token              | nil        |                        |
| authorization_endpoint | The authorize endpoint on the authorization server              | /authorize | yes                    |
| token_endpoint         | The token endpoint on the authorization server                  | /token     | yes                    |
| userinfo_endpoint      | The user info endpoint on the authorization server              | /userinfo  | yes                    |
| jwks_uri               | The jwks_uri on the authorization server                        | /jwk       | yes                    |
| end_session_endpoint   | The url to call to log the user out at the authorization server | nil        | yes                    |

### Additional Configuration Notes
  * `name` is arbitrary, I recommend using the name of your provider. The name
  configuration exists because you could be using multiple OpenID Connect
  providers in a single app.

  **NOTE**: if you use this gem with Devise you should use `:openid_connect` name,
  or Devise would route to 'users/auth/:provider' rather than 'users/auth/openid_connect'

  * `response_type` tells the authorization server which grant type the application wants to use.
  Only `:code` (Authorization Code grant) is accepted in this fork.
  * If you want to pass `state` parameter by yourself. You can set Proc Object.
  e.g. `state: Proc.new { SecureRandom.hex(32) }`
  * `nonce` is optional. If don't want to pass "nonce" parameter to provider, You should specify
  `false` to `send_nonce` option. (default true)
  * Support for other client authentication methods. If don't specified
  `:client_auth_method` option, automatically set `:basic`.
  * Use "OpenID Connect Discovery", You should specify `true` to `discovery` option. (default false)
  * In "OpenID Connect Discovery", generally provider should have Webfinger endpoint.
  If provider does not have Webfinger endpoint, You can specify "Issuer" to option.
  e.g. `issuer: "https://myprovider.com"`
  It means to get configuration from "https://myprovider.com/.well-known/openid-configuration".
  * The uid is always the `sub` claim of the verified ID token.
  * The `issuer` property should exactly match the provider's issuer link.
  * The `response_mode` option is optional and specifies how the result of the authorization request is formatted.
  * Some OpenID Connect providers require the `scope` attribute in requests to the token endpoint, even if
  this is not in the protocol specifications. In those cases, the `send_scope_to_token_endpoint`
  property can be used to add the attribute to the token request. Initial value is `true`, which means that the
  scope attribute is included by default.

## Additional notes
  * `code_verifier` and `nonce` are never read from the callback request, so a callback without the session that
  started the sign-in fails.

For the full low down on OpenID Connect, please check out
[the spec](http://openid.net/specs/openid-connect-core-1_0.html).

## Contributing

1. Fork it ( http://github.com/omniauth/omniauth_openid_connect/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Cover your changes with tests and make sure they're green (`bundle install && bundle exec rake test`)
4. Commit your changes (`git commit -am 'Add some feature'`)
5. Push to the branch (`git push origin my-new-feature`)
6. Create new Pull Request
