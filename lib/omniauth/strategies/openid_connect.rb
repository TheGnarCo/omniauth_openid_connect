# frozen_string_literal: true

require 'base64'
require 'timeout'
require 'net/http'
require 'open-uri'
require 'omniauth'
require 'openid_connect'
require 'forwardable'

module OmniAuth
  module Strategies
    class OpenIDConnect # rubocop:disable Metrics/ClassLength
      include OmniAuth::Strategy
      extend Forwardable

      RESPONSE_TYPE_EXCEPTIONS = {
        'id_token' => { exception_class: OmniAuth::OpenIDConnect::MissingIdTokenError, key: :missing_id_token }.freeze,
        'code' => { exception_class: OmniAuth::OpenIDConnect::MissingCodeError, key: :missing_code }.freeze,
      }.freeze

      # Gnar: the callback is a GET carrying code and state in the query string, so no other response mode.
      RESPONSE_MODES = [nil, 'query'].freeze
      # Gnar: rack-oauth2 puts the client secret in the request body for any method name it does not know.
      CLIENT_AUTH_METHODS = [nil, :basic, :post].freeze
      # Gnar: the most bytes read from a discovery document or a key set.
      MAX_FETCH_BYTES = 512 * 1024
      # Gnar: discovery endpoints the strategy calls or sends the browser to. Each must be https on an allowed host.
      CHECKED_ENDPOINTS = %i[authorization_endpoint token_endpoint jwks_uri end_session_endpoint].freeze
      # Gnar: errors that mean the ID token is malformed, badly signed or fails a claim check.
      INVALID_ID_TOKEN_ERRORS = [
        ::OpenIDConnect::ResponseObject::IdToken::InvalidToken, ::JSON::JWT::Exception, ::AttrRequired::AttrMissing
      ].freeze
      FETCH_CACHE = ::OmniAuth::OpenIDConnect::FetchCache.new

      def self.fetch_cache
        FETCH_CACHE
      end

      def_delegator :request, :params

      option :name, 'openid_connect'
      option(:client_options, identifier: nil,
                              secret: nil,
                              redirect_uri: nil,
                              scheme: 'https',
                              host: nil,
                              port: 443,
                              audience: nil,
                              authorization_endpoint: '/authorize',
                              token_endpoint: '/token',
                              userinfo_endpoint: '/userinfo',
                              jwks_uri: '/jwk',
                              end_session_endpoint: nil)

      option :issuer
      option :discovery, false
      option :client_signing_alg, :RS256
      option :jwt_secret_base64
      option :client_jwk_signing_key
      option :client_x509_signing_key
      option :scope, [:openid]
      option :response_type, 'code' # ['code', 'id_token']
      option :send_state, true
      option :require_state, true
      option :state
      option :response_mode # [:query, :fragment, :form_post, :web_message]
      option :display, nil # [:page, :popup, :touch, :wap]
      option :prompt, nil # [:none, :login, :consent, :select_account]
      option :hd, nil
      option :max_age
      option :ui_locales
      option :id_token_hint
      option :acr_values
      option :send_nonce, true
      option :send_scope_to_token_endpoint, true
      option :client_auth_method
      option :post_logout_redirect_uri
      option :extra_authorize_params, {}
      option :allow_authorize_params, []
      option :pkce, true
      option :pkce_verifier, nil
      option :pkce_options, {
        code_challenge: proc { |verifier|
          Base64.urlsafe_encode64(Digest::SHA2.digest(verifier), padding: false)
        },
        code_challenge_method: 'S256',
      }

      # Gnar hardening options. See README, "Gnar hardening".
      option :discovery_url
      option :allowed_endpoint_hosts
      option :nbf_leeway, 60
      option :open_timeout, 3
      option :read_timeout, 5
      option :metadata_ttl, 3600
      option :jwks_ttl, 900
      option :stale_ttl, 3600
      option :jwks_stale_ttl, 300
      option :negative_ttl, 10
      option :jwks_min_refresh_interval, 60

      # Gnar: always the ID token's sub. Email and other mutable claims are never the uid.
      def uid
        user_info.sub
      end

      # Gnar: no email here. It is in extra.raw_info for the app to use as data, never as an identity.
      info do
        {
          name: user_info.name,
          nickname: user_info.preferred_username,
          first_name: user_info.given_name,
          last_name: user_info.family_name,
          gender: user_info.gender,
          image: user_info.picture,
          phone: user_info.phone_number,
          urls: { website: user_info.website },
        }
      end

      extra do
        { raw_info: user_info.raw_attributes }
      end

      credentials do
        {
          id_token: access_token.id_token,
          token: access_token.access_token,
          refresh_token: access_token.refresh_token,
          expires_in: access_token.expires_in,
          scope: access_token.scope,
        }
      end

      def client
        @client ||= ::OpenIDConnect::Client.new(client_options)
      end

      def config
        return @config ||= discovery_document if options.discovery_url

        @config ||= ::OpenIDConnect::Discovery::Provider::Config.discover!(options.issuer)
      end

      def request_phase
        validate_options!
        options.issuer = issuer if options.issuer.to_s.empty?
        discover!
        redirect authorize_uri
      rescue ::OmniAuth::OpenIDConnect::FetchCache::FetchFailed => e
        fail!(fetch_failure_key(e), e)
      end

      # Gnar: the state is checked first, in constant time, before anything else in the callback is read. A provider
      # error then becomes a failure carrying only its error code; error_description and error_uri are never used.
      def callback_phase
        validate_options!
        raise CallbackError, error: :csrf_detected, reason: "Invalid 'state' parameter" unless valid_state?

        error = params['error'] || params['error_reason']
        raise CallbackError, error: provider_error_code(error) if error

        return unless valid_response_type?

        options.issuer = issuer if options.issuer.nil? || options.issuer.empty?

        verify_id_token!(params['id_token']) if configured_response_type == 'id_token'
        discover!
        client.redirect_uri = redirect_uri

        return id_token_callback_phase if configured_response_type == 'id_token'

        client.authorization_code = authorization_code
        access_token
        super
      rescue CallbackError => e
        fail!(e.error, e)
      rescue ::Rack::OAuth2::Client::Error => e
        # The exception's message is the provider's error_description, so only a checked error code is kept.
        code = provider_error_code(e.response.is_a?(Hash) ? e.response[:error] : nil)
        fail!(code, CallbackError.new(error: code))
      rescue *INVALID_ID_TOKEN_ERRORS => e
        fail!(:invalid_id_token, e)
      rescue ::OmniAuth::OpenIDConnect::FetchCache::FetchFailed => e
        fail!(fetch_failure_key(e), e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT, ::Faraday::TimeoutError => e
        fail!(:timeout, e)
      rescue ::SocketError, ::Faraday::ConnectionFailed => e
        fail!(:failed_to_connect, e)
      rescue ::Faraday::Error => e
        fail!(:failed_to_connect, CallbackError.new(error: :failed_to_connect, reason: e.class.name))
      end

      # Gnar: the gem's GET <request path>/logout route is disabled, because any page could use it to sign a person
      # out. The app builds its own sign-out with #logout_redirect_url.
      def other_phase
        call_app!
      end

      def authorization_code
        params['code']
      end

      def end_session_uri(extra_params = {})
        return unless end_session_endpoint_is_valid?

        end_session_uri = URI(client_options.end_session_endpoint)
        end_session_uri.query = encoded_post_logout_redirect_uri(extra_params)
        end_session_uri.to_s
      end

      # Gnar: the tenant's end_session_endpoint URL for the app's own sign-out, with the configured
      # post_logout_redirect_uri and the given parameters, or nil when the tenant publishes no end_session_endpoint.
      # Works outside a request: OmniAuth::Strategies::OpenIDConnect.new(nil, options).logout_redirect_url(...).
      # Raises FetchCache::FetchFailed when the discovery document cannot be fetched.
      def logout_redirect_url(id_token_hint: nil, logout_hint: nil, state: nil)
        validate_options!
        options.issuer = issuer if options.issuer.to_s.empty?
        discover!
        end_session_uri(id_token_hint: id_token_hint, logout_hint: logout_hint, state: state)
      end

      def authorize_uri # rubocop:disable Metrics/AbcSize
        client.redirect_uri = redirect_uri
        opts = {
          response_type: options.response_type,
          response_mode: options.response_mode,
          scope: options.scope,
          login_hint: params['login_hint'],
          ui_locales: params['ui_locales'],
          claims_locales: params['claims_locales'],
          prompt: options.prompt,
          nonce: (new_nonce if options.send_nonce),
          hd: options.hd,
          acr_values: options.acr_values,
        }

        opts[:state] = new_state if options.send_state
        opts.merge!(options.extra_authorize_params) unless options.extra_authorize_params.empty?

        options.allow_authorize_params.each do |key|
          opts[key] = request.params[key.to_s] unless opts.key?(key)
        end

        if options.pkce
          verifier = options.pkce_verifier ? options.pkce_verifier.call : SecureRandom.hex(64)

          opts.merge!(pkce_authorize_params(verifier))
          session['omniauth.pkce.verifier'] = verifier
        end

        client.authorization_uri(opts.reject { |_k, v| v.nil? })
      end

      def public_key
        @public_key ||= if options.discovery_url
                          cached_jwks
                        elsif options.discovery
                          config.jwks
                        elsif configured_public_key
                          configured_public_key
                        elsif client_options.jwks_uri
                          fetch_key
                        end
      end

      # Some OpenID providers use the OAuth2 client secret as the shared secret, but
      # Keycloak uses a separate key that's stored inside the database.
      def secret
        base64_decoded_jwt_secret || client_options.secret
      end

      def pkce_authorize_params(verifier)
        # NOTE: see https://tools.ietf.org/html/rfc7636#appendix-A
        {
          code_challenge: options.pkce_options[:code_challenge].call(verifier),
          code_challenge_method: options.pkce_options[:code_challenge_method],
        }
      end

      private

      def fetch_key
        @fetch_key ||= parse_jwk_key(::OpenIDConnect.http_client.get(client_options.jwks_uri).body)
      end

      def base64_decoded_jwt_secret
        return unless options.jwt_secret_base64

        Base64.decode64(options.jwt_secret_base64)
      end

      def issuer
        resource = "#{ client_options.scheme }://#{ client_options.host }"
        resource = "#{ resource }:#{ client_options.port }" if client_options.port
        ::OpenIDConnect::Discovery::Provider.discover!(resource).issuer
      end

      def discover!
        return unless options.discovery || options.discovery_url

        client_options.authorization_endpoint = config.authorization_endpoint
        client_options.token_endpoint = config.token_endpoint
        client_options.userinfo_endpoint = config.userinfo_endpoint
        client_options.jwks_uri = config.jwks_uri
        client_options.end_session_endpoint = config.end_session_endpoint if config.respond_to?(:end_session_endpoint)
      end

      # Gnar: claims come from the verified ID token only. The UserInfo endpoint is never called.
      def user_info
        return @user_info if @user_info

        access_token
        claims = @verified_id_token.raw_attributes.to_h.with_indifferent_access
        @user_info = ::OpenIDConnect::ResponseObject::UserInfo.new(claims)
      end

      def access_token
        return @access_token if @access_token

        token_request_params = {
          scope: (options.scope if options.send_scope_to_token_endpoint),
          client_auth_method: options.client_auth_method&.to_sym,
        }

        token_request_params[:code_verifier] = stored_code_verifier if options.pkce

        @access_token = client.access_token!(token_request_params) { |req| apply_http_timeouts(req) }
        verify_id_token!(@access_token.id_token) if configured_response_type == 'code'

        @access_token
      end

      # Unlike ::OpenIDConnect::ResponseObject::IdToken.decode, this
      # method splits the decoding and verification of JWT into two
      # steps. First, we decode the JWT without verifying it to
      # determine the algorithm used to sign. Then, we verify it using
      # the appropriate public key (e.g. if algorithm is RS256) or
      # shared secret (e.g. if algorithm is HS256).  This works around a
      # limitation in the openid_connect gem:
      # https://github.com/nov/openid_connect/issues/61
      def decode_id_token(id_token)
        decoded = JSON::JWT.decode(id_token, :skip_verification)
        algorithm = decoded.algorithm.to_sym

        validate_client_algorithm!(algorithm)

        keyset =
          case algorithm
          when :HS256, :HS384, :HS512
            secret
          else
            public_key
          end

        decoded.verify!(keyset)
        ::OpenIDConnect::ResponseObject::IdToken.new(decoded)
      rescue JSON::JWK::Set::KidNotFound
        # If the JWT has a key ID (kid), then we know that the set of
        # keys supplied doesn't contain the one we want, and we're
        # done. However, if there is no kid, then we try each key
        # individually to see if one works:
        # https://github.com/nov/json-jwt/pull/92#issuecomment-824654949
        raise if decoded&.header&.key?('kid')

        decoded = decode_with_each_key!(id_token, keyset)

        raise unless decoded

        decoded
      end

      # If client_signing_alg is specified, we check that the returned JWT
      # matches the expected algorithm. If not, we reject it.
      def validate_client_algorithm!(algorithm)
        client_signing_alg = options.client_signing_alg&.to_sym

        return unless client_signing_alg
        return if algorithm == client_signing_alg

        reason = "Received JWT is signed with #{algorithm}, but client_singing_alg is configured for #{client_signing_alg}"
        raise CallbackError, error: :invalid_jwt_algorithm, reason: reason, uri: params['error_uri']
      end

      def decode!(id_token, key)
        ::OpenIDConnect::ResponseObject::IdToken.decode(id_token, key)
      end

      def decode_with_each_key!(id_token, keyset)
        return unless keyset.is_a?(JSON::JWK::Set)

        keyset.each do |key|
          begin
            decoded = decode!(id_token, key)
          rescue JSON::JWS::VerificationFailed, JSON::JWS::UnexpectedAlgorithm, JSON::JWK::UnknownAlgorithm
            next
          end

          return decoded if decoded
        end

        nil
      end

      def client_options
        options.client_options
      end

      def new_state
        state = if options.state.respond_to?(:call)
                  if options.state.arity == 1
                    options.state.call(env)
                  else
                    options.state.call
                  end
                end
        session['omniauth.state'] = state || SecureRandom.hex(16)
      end

      def stored_state
        session.delete('omniauth.state')
      end

      def new_nonce
        session['omniauth.nonce'] = SecureRandom.hex(16)
      end

      # Gnar: a missing session nonce fails the sign-in. Otherwise a token without a nonce claim would match (nil == nil).
      def stored_nonce
        nonce = session.delete('omniauth.nonce')
        return nonce unless nonce.to_s.empty? && options.send_nonce

        raise CallbackError, error: :missing_nonce, reason: 'No nonce in the session'
      end

      # Gnar: the PKCE verifier comes from the session only, never from the callback request.
      def stored_code_verifier
        verifier = session.delete('omniauth.pkce.verifier')
        return verifier unless verifier.to_s.empty?

        raise CallbackError, error: :missing_code_verifier, reason: 'No PKCE verifier in the session'
      end

      def script_name
        return '' if @env.nil?

        super
      end

      # Gnar: session keys are scoped per provider (see ScopedSession).
      def session
        return {} if @env.nil?

        ::OmniAuth::OpenIDConnect::ScopedSession.new(super, name)
      end

      def configured_public_key
        @configured_public_key ||= if options.client_jwk_signing_key
                                     parse_jwk_key(options.client_jwk_signing_key)
                                   elsif options.client_x509_signing_key
                                     parse_x509_key(options.client_x509_signing_key)
                                   end
      end

      def parse_x509_key(key)
        OpenSSL::X509::Certificate.new(key).public_key
      end

      def parse_jwk_key(key)
        json = key.is_a?(String) ? JSON.parse(key) : key
        return JSON::JWK::Set.new(json['keys']) if json.key?('keys')

        JSON::JWK.new(json)
      end

      def decode(str)
        UrlSafeBase64.decode64(str).unpack1('B*').to_i(2).to_s
      end

      # Gnar: always the configured value. A redirect_uri request parameter is not appended.
      def redirect_uri
        client_options.redirect_uri
      end

      def encoded_post_logout_redirect_uri(extra_params = {})
        query = { post_logout_redirect_uri: options.post_logout_redirect_uri }.merge(extra_params).compact
        return if query.empty?

        URI.encode_www_form(query)
      end

      def end_session_endpoint_is_valid?
        client_options.end_session_endpoint &&
          client_options.end_session_endpoint =~ URI::DEFAULT_PARSER.make_regexp
      end

      def id_token_callback_phase
        user_data = @verified_id_token.raw_attributes
        env['omniauth.auth'] = AuthHash.new(
          provider: name,
          uid: user_data['sub'],
          info: { name: user_data['name'] },
          extra: { raw_info: user_data }
        )
        call_app!
      end

      def valid_response_type?
        return true if params.key?(configured_response_type)

        error_attrs = RESPONSE_TYPE_EXCEPTIONS[configured_response_type]
        fail!(error_attrs[:key], error_attrs[:exception_class].new(params['error']))

        false
      end

      def configured_response_type
        @configured_response_type ||= options.response_type.to_s
      end

      # Gnar: the ID token is required, its nonce is compared with the session's only, and nbf and azp are checked on
      # top of openid_connect's exp, iss, aud and nonce checks. The verified token is kept for #user_info.
      def verify_id_token!(id_token)
        raise CallbackError, error: :missing_id_token, reason: 'No id_token in the token response' if id_token.to_s.empty?

        verify_kwargs = {
          issuer: options.issuer,
          client_id: client_options.identifier,
          nonce: stored_nonce,
        }
        verify_kwargs.merge!(audience: client_options.audience) if client_options.audience

        decoded = decode_id_token_refreshing_keys(id_token)
        decoded.verify!(**verify_kwargs)
        verify_nbf!(decoded)
        verify_azp!(decoded)
        @verified_id_token = decoded
      end

      # Gnar: a kid that is not in the cached key set forces one refresh of the key set (key rotation).
      def decode_id_token_refreshing_keys(id_token)
        decode_id_token(id_token)
      rescue ::JSON::JWK::Set::KidNotFound
        raise unless options.discovery_url && !@jwks_refreshed

        precheck_unverified_claims!(id_token)
        @jwks_refreshed = true
        @public_key = cached_jwks(replace: @public_key)
        retry
      end

      # Before an unknown kid may force a key set refresh, the claims that need no key must already be right, so a
      # token that would fail anyway costs no fetch. This reads the unverified payload; it is not a validation.
      def precheck_unverified_claims!(id_token)
        claims = JSON::JWT.decode(id_token, :skip_verification)
        audience = client_options.audience || client_options.identifier
        return if claims['iss'] == options.issuer && Array(claims['aud']).include?(audience) && claims['exp'].to_i > Time.now.to_i

        raise ::OpenIDConnect::ResponseObject::IdToken::InvalidToken, 'Invalid ID token: claims fail before key lookup'
      end

      def verify_nbf!(id_token)
        nbf = id_token_claim(id_token, 'nbf')
        return if nbf.nil? || nbf.to_i <= Time.now.to_i + options.nbf_leeway.to_i

        raise ::OpenIDConnect::ResponseObject::IdToken::InvalidToken, 'Invalid ID token: not valid yet (nbf)'
      end

      # OpenID Connect Core 1.0, 3.1.3.7, items 4 and 5: with several audiences azp must be present, and when azp is
      # present it must be this client.
      def verify_azp!(id_token)
        azp = id_token_claim(id_token, 'azp')
        return if azp.nil? && Array(id_token_claim(id_token, 'aud')).size <= 1
        return if azp == client_options.identifier

        raise ::OpenIDConnect::ResponseObject::IdToken::InvalidAudience, 'Invalid ID token: azp does not match the client'
      end

      def id_token_claim(id_token, name)
        claims = id_token.raw_attributes || {}
        claims[name] || claims[name.to_sym]
      end

      # Gnar: the state must be present in the callback and in the session, and equal (constant-time comparison).
      # Read from the session once, which also removes it.
      def valid_state?
        return true unless options.send_state

        given = params['state'].to_s
        stored = stored_state.to_s
        return !options.require_state if given.empty? && stored.empty?

        !given.empty? && !stored.empty? && Rack::Utils.secure_compare(stored, given)
      end

      # OAuth error codes are lowercase words with underscores. Anything else is not echoed.
      def provider_error_code(raw)
        raw.to_s.match?(/\A[a-z][a-z_]{0,63}\z/) ? raw.to_s.to_sym : :provider_error
      end

      def fetch_failure_key(error)
        error.kind == :jwks ? :jwks_failed : :discovery_failed
      end

      def validate_options!
        unless RESPONSE_MODES.include?(options.response_mode&.to_s)
          config_error!("response_mode #{options.response_mode.inspect} is not supported; leave it unset or use 'query'")
        end
        unless CLIENT_AUTH_METHODS.include?(options.client_auth_method&.to_sym)
          config_error!("client_auth_method #{options.client_auth_method.inspect} is not supported; use :basic or :post")
        end
        config_error!('pkce must use S256') if options.pkce && options.pkce_options[:code_challenge_method].to_s != 'S256'
        return unless options.discovery_url

        config_error!('discovery_url must be an https URL') unless https_url?(options.discovery_url)
        config_error!('issuer must be an https URL when discovery_url is set') unless https_url?(options.issuer)
      end

      def config_error!(message)
        raise ::OmniAuth::OpenIDConnect::ConfigurationError, message
      end

      def https_url?(url)
        uri = URI(url.to_s)
        uri.is_a?(URI::HTTPS) && !uri.host.to_s.empty?
      rescue URI::InvalidURIError
        false
      end

      # The key holds every input the document's validation reads: the URL, the expected issuer and the allowed
      # endpoint hosts. Providers that differ in any of them never share a document.
      def discovery_document
        key = [:discovery, options.discovery_url, options.issuer, allowed_endpoint_hosts]
        fetch_cached(key, options.metadata_ttl, options.stale_ttl) { load_discovery_document }
      end

      def cached_jwks(replace: nil)
        uri = config.jwks_uri
        # The key set's check reads only the URI. The URI comes from a document validated under this provider's key.
        key = [:jwks, uri, options.issuer]
        fetch_cached(key, options.jwks_ttl, options.jwks_stale_ttl,
                     replace: replace, min_replace_interval: options.jwks_min_refresh_interval) do
          keys = fetch_json(uri)['keys']
          raise ::OmniAuth::OpenIDConnect::HttpResponseError, 'key set has no keys' unless keys.is_a?(Array) && keys.any?

          JSON::JWK::Set.new(keys)
        end
      end

      def fetch_cached(key, ttl, stale_ttl, replace: nil, min_replace_interval: 0, &block)
        self.class.fetch_cache.fetch(key, ttl: ttl, negative_ttl: options.negative_ttl, stale_ttl: stale_ttl,
                                          replace: replace, min_replace_interval: min_replace_interval, &block)
      end

      # The discovery document's issuer must equal the configured issuer, and every endpoint the strategy uses must be
      # https on an allowed host (by default the discovery URL's host).
      def load_discovery_document
        document = ::OpenIDConnect::Discovery::Provider::Config::Response.new(fetch_json(options.discovery_url).with_indifferent_access)
        document.expected_issuer = options.issuer
        document.validate!
        raise ::OmniAuth::OpenIDConnect::UnsafeMetadataError, 'issuer mismatch' unless document.issuer == options.issuer

        CHECKED_ENDPOINTS.each do |endpoint|
          url = document.respond_to?(endpoint) ? document.public_send(endpoint) : nil
          next if url.nil? && endpoint == :end_session_endpoint
          next if allowed_endpoint?(url)

          raise ::OmniAuth::OpenIDConnect::UnsafeMetadataError, "#{endpoint} is not https on an allowed host"
        end
        document
      end

      def allowed_endpoint?(url)
        https_url?(url) && allowed_endpoint_hosts.include?(URI(url).host.downcase)
      end

      # Downcased and sorted, with the discovery URL's host as the default, so equal lists give equal cache keys.
      def allowed_endpoint_hosts
        Array(options.allowed_endpoint_hosts || URI(options.discovery_url).host).map { |h| h.to_s.downcase }.uniq.sort
      end

      # GETs a JSON document with the configured timeouts, without following redirects, reading at most
      # MAX_FETCH_BYTES and asking for no compression, so a small response cannot expand in memory.
      def fetch_json(url)
        body = +''
        response = ::OpenIDConnect.http_client.get(url) do |req|
          apply_http_timeouts(req)
          req.headers['Accept-Encoding'] = 'identity'
          req.options.on_data = proc do |chunk, _received|
            body << chunk
            raise ::OmniAuth::OpenIDConnect::HttpResponseError, 'response too large' if body.bytesize > MAX_FETCH_BYTES
          end
        end
        raise ::OmniAuth::OpenIDConnect::HttpResponseError, "HTTP #{response.status}" unless response.success?

        JSON.parse(body)
      end

      def apply_http_timeouts(req)
        req.options.open_timeout = options.open_timeout
        req.options.timeout = options.read_timeout
      end

      class CallbackError < StandardError
        attr_accessor :error, :error_reason, :error_uri

        def initialize(data)
          super
          self.error = data[:error]
          self.error_reason = data[:reason]
          self.error_uri = data[:uri]
        end

        def message
          [error, error_reason, error_uri].compact.join(' | ')
        end
      end
    end
  end
end

OmniAuth.config.add_camelization 'openid_connect', 'OpenIDConnect'
