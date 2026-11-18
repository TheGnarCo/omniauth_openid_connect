# frozen_string_literal: true

require 'socket'
require_relative '../../../test_helper'
require_relative '../../../support/oidc_harness'

module OmniAuth
  module Strategies
    # Discovery and key set fetching: cache, stale and negative results, timeouts, https and host checks,
    # and provider text from the token endpoint.
    class OpenIDConnectFetchTest < Minitest::Test # rubocop:disable Metrics/ClassLength
      include OidcHarness

      DESCRIPTION = 'attacker-controlled <b>text</b> 4711'
      STALE = { metadata_ttl: 60, jwks_ttl: 60, stale_ttl: 600, jwks_stale_ttl: 120, negative_ttl: 10 }.freeze

      def teardown
        if OmniAuth::Strategies::OpenIDConnect.respond_to?(:fetch_cache)
          OmniAuth::Strategies::OpenIDConnect.fetch_cache.clock = nil
        end
        super
      end

      def freeze_clock
        @now = 1_000.0
        OmniAuth::Strategies::OpenIDConnect.fetch_cache.clock = -> { @now }
      end

      def counts
        %i[discovery jwks token].to_h { |t| [t, @fake.requests_of(t).size] }
      end

      def test_production_defaults_are_pinned
        defaults = OmniAuth::Strategies::OpenIDConnect.default_options
        expected = {
          open_timeout: 3, read_timeout: 5, metadata_ttl: 3600, jwks_ttl: 900, negative_ttl: 10, stale_ttl: 3600,
          jwks_stale_ttl: 300, nbf_leeway: 60, pkce: true, client_signing_alg: :RS256
        }
        assert_equal(expected, expected.keys.to_h { |k| [k, defaults[k]] })
        assert_equal 'S256', defaults[:pkce_options][:code_challenge_method]
        assert_equal 60, defaults[:jwks_min_refresh_interval]
        assert_equal 512 * 1024, OmniAuth::Strategies::OpenIDConnect::MAX_FETCH_BYTES
      end

      # Records the timeouts on every Faraday request made through the net_http adapter while recording is on.
      module RequestRecorder
        def call(env)
          log = Thread.current[:oidc_faraday_requests]
          log << [env.url.to_s, env.request.open_timeout, env.request.timeout] if log
          super
        end
      end
      Faraday::Adapter::NetHttp.prepend(RequestRecorder)

      def test_default_timeouts_reach_discovery_key_set_and_token_requests
        Thread.current[:oidc_faraday_requests] = []
        assert browser.sign_in('entra').ok?
        seen = Thread.current[:oidc_faraday_requests]
        [@fake.discovery_url, @fake.jwks_url, @fake.token_url].each do |url|
          assert_includes seen, [url, 3, 5], "#{url} in #{seen.inspect}"
        end
      ensure
        Thread.current[:oidc_faraday_requests] = nil
      end

      def test_cold_sign_in_fetches_once_and_warm_sign_in_not_at_all
        b = browser
        assert b.sign_in('entra').ok?
        assert_equal({ discovery: 1, jwks: 1, token: 1 }, counts)
        assert Browser.new(b.app, @fake).sign_in('entra').ok?
        assert_equal({ discovery: 1, jwks: 1, token: 2 }, counts)
      end

      def test_refetches_after_the_ttl
        freeze_clock
        b = browser(metadata_ttl: 60, jwks_ttl: 120)
        assert b.sign_in('entra').ok?
        @now += 61
        assert Browser.new(b.app, @fake).sign_in('entra').ok?
        assert_equal [2, 1], [counts[:discovery], counts[:jwks]]
        @now += 60
        assert Browser.new(b.app, @fake).sign_in('entra').ok?
        assert_equal [3, 2], [counts[:discovery], counts[:jwks]]
      end

      def test_unknown_kid_forces_exactly_one_refresh
        b = browser
        assert b.sign_in('entra').ok?
        @fake.configure(unknown_key: true)
        assert_clean_failure Browser.new(b.app, @fake).sign_in('entra'), :invalid_id_token
        assert_equal 2, counts[:jwks]
      end

      def test_unexpected_token_type_is_a_clean_failure_without_its_text
        @fake.configure(token_overrides: { token_type: 'providertext<b>4711' })
        result = browser.sign_in('entra')
        assert_clean_failure result, :invalid_response
        refute_includes result.failure[:message].to_s + result.log, 'providertext'
      end

      def test_non_json_token_response_is_a_clean_failure
        @fake.configure(token_body: 'providertext not json')
        result = browser.sign_in('entra')
        assert_clean_failure result, :invalid_response
        refute_includes result.failure[:message].to_s + result.log, 'providertext'
      end

      # A malformed ID token served by the token endpoint: header and payload as given, a dummy signature.
      def raw_token(header, payload)
        parts = [header, payload].map { |part| Base64.urlsafe_encode64(JSON.generate(part), padding: false) }
        "#{parts.join('.')}.c2ln"
      end

      def test_id_token_without_alg_or_with_a_non_object_payload_is_a_clean_failure
        @fake.configure(token_overrides: { id_token: raw_token({ typ: 'JWT' }, { iss: @fake.issuer }) })
        assert_clean_failure browser.sign_in('entra'), :invalid_jwt_algorithm
        @fake.configure(token_overrides: { id_token: raw_token({ alg: 'RS256', typ: 'JWT' }, [1, 2]) })
        assert_clean_failure browser.sign_in('entra'), :invalid_response
      end

      def test_error_uri_and_token_alg_header_stay_out_of_failure_and_log
        @fake.configure(token_overrides: { id_token: raw_token({ alg: 'HS256', typ: 'JWT' }, { iss: @fake.issuer }) })
        result = browser.sign_in('entra') { |cb| OidcHarness.with_params(cb, 'error_uri' => 'PROVIDERTEXT<b>4711') }
        assert_clean_failure result, :invalid_jwt_algorithm
        refute_includes result.failure[:message].to_s + result.log, 'PROVIDERTEXT'
        refute_includes result.failure[:message].to_s, 'HS256'
      end

      def test_configuration_error_is_raised_through_the_middleware
        assert_raises(OmniAuth::OpenIDConnect::ConfigurationError) { browser(response_mode: 'form_post').start('entra') }
      end

      def test_missing_session_nonce_fails_before_the_code_is_redeemed
        b = browser
        callback = b.idp(b.start('entra'))
        b.session.delete_if { |k, _| k.include?('nonce') }
        assert_clean_failure b.callback(callback), :missing_nonce
        assert_empty @fake.requests_of(:token)
      end

      # Tokens signed with a key the provider does not publish: forced key set refreshes are rate limited across
      # sign-ins, so a provider that keeps doing this cannot cause a fetch per sign-in.
      def test_unknown_kids_force_at_most_one_refresh_per_interval
        freeze_clock
        @fake.configure(unknown_key: true)
        app = browser.app
        3.times { assert_clean_failure Browser.new(app, @fake).sign_in('entra'), :invalid_id_token }
        assert_equal 2, counts[:jwks], 'one initial fetch and one forced refresh'
        @now += 61
        assert_clean_failure Browser.new(app, @fake).sign_in('entra'), :invalid_id_token
        assert_equal 3, counts[:jwks]
      end

      def test_unknown_kid_with_wrong_issuer_audience_or_expiry_forces_no_refresh
        app = browser.app
        [{ iss: 'https://evil.example.test/v2.0' }, { aud: 'other' }, { exp: Time.now.to_i - 10 }].each do |claims|
          @fake.configure(unknown_key: true, claims: claims)
          assert_clean_failure Browser.new(app, @fake).sign_in('entra'), :invalid_id_token
        end
        assert_equal 1, counts[:jwks]
      end

      def test_failed_discovery_is_remembered_for_negative_ttl
        freeze_clock
        @fake.configure(discovery_status: 500)
        app = browser.app
        2.times { assert_clean_failure Browser.new(app, @fake).start('entra'), :discovery_failed }
        assert_equal 1, counts[:discovery]
        @now += 11
        @fake.configure(discovery_status: nil)
        assert_kind_of String, Browser.new(app, @fake).start('entra')
        assert_equal 2, counts[:discovery]
      end

      def test_expired_document_and_keys_are_served_stale_and_logged_at_error
        freeze_clock
        b = browser(STALE)
        assert b.sign_in('entra').ok?
        @fake.configure(discovery_status: 500, jwks_status: 500)
        @now += 100
        result = Browser.new(b.app, @fake).sign_in('entra')
        assert result.ok?, result.failure.inspect
        assert_match(/ERROR.*serving stale discovery/, result.log)
        assert_match(/ERROR.*serving stale jwks/, result.log)
        refute_match(/eyJ|BEGIN|"kid"/, result.log)
      end

      def test_key_set_past_its_stale_cap_is_not_served
        freeze_clock
        b = browser(STALE)
        assert b.sign_in('entra').ok?
        @fake.configure(discovery_status: 500, jwks_status: 500)
        @now += 200
        result = Browser.new(b.app, @fake).sign_in('entra')
        assert_clean_failure result, :jwks_failed
        assert_match(/serving stale discovery/, result.log)
        refute_match(/serving stale jwks/, result.log)
      end

      def test_document_past_its_stale_window_is_not_served
        freeze_clock
        b = browser(STALE)
        assert b.sign_in('entra').ok?
        @fake.configure(discovery_status: 500)
        @now += 700
        assert_clean_failure Browser.new(b.app, @fake).start('entra'), :discovery_failed
      end

      def test_html_from_the_metadata_url_is_a_clean_failure_without_its_text
        @fake.configure(discovery_body: '<html>attacker-controlled 4711</html>')
        result = browser.start('entra')
        assert_clean_failure result, :discovery_failed
        refute_includes result.failure[:message].to_s + result.log, 'attacker-controlled'
      end

      def test_redirect_from_the_metadata_url_is_not_followed
        @fake.configure(discovery_status: 302)
        assert_clean_failure browser.start('entra'), :discovery_failed
        assert_equal 1, counts[:discovery]
      end

      def test_redirect_with_a_location_is_not_followed
        evil = stub_request(:any, /evil\.example\.test/)
        stub_request(:get, @fake.discovery_url).to_return(status: 302, headers: { 'Location' => 'https://evil.example.test/doc' })
        assert_clean_failure browser.start('entra'), :discovery_failed
        assert_not_requested evil
      end

      def test_error_status_with_a_valid_document_is_refused
        good = Net::HTTP.get_response(URI(@fake.discovery_url)).body
        @fake.reset!.configure(discovery_status: 500, discovery_body: good)
        assert_clean_failure browser.start('entra'), :discovery_failed
      end

      def test_oversized_key_set_is_refused
        stub_request(:get, @fake.jwks_url)
          .to_return(body: JSON.generate(keys: ['x' * (512 * 1024)]), headers: { 'content-type' => 'application/json' })
        assert_clean_failure browser.sign_in('entra'), :jwks_failed
      end

      def test_oversized_metadata_is_refused
        @fake.configure(discovery_overrides: { padding: 'x' * (OmniAuth::Strategies::OpenIDConnect::MAX_FETCH_BYTES + 1) })
        assert_clean_failure browser.start('entra'), :discovery_failed
      end

      def test_http_endpoint_in_the_discovery_document_is_refused
        @fake.configure(discovery_overrides: { token_endpoint: @fake.token_url.sub('https://', 'http://') })
        assert_clean_failure browser.start('entra'), :discovery_failed
      end

      def test_endpoint_on_another_host_is_refused_and_never_called
        evil = stub_request(:any, /evil\.example\.test/)
        @fake.configure(discovery_overrides: { token_endpoint: 'https://evil.example.test/token' })
        assert_clean_failure browser.sign_in('entra'), :discovery_failed
        assert_not_requested evil
      end

      def test_authorization_and_end_session_endpoints_on_another_host_are_refused
        %i[authorization_endpoint end_session_endpoint].each do |endpoint|
          clear_fetch_cache
          @fake.configure(discovery_overrides: { endpoint => 'https://evil.example.test/x' })
          assert_clean_failure browser.start('entra'), :discovery_failed
        end
      end

      def test_document_for_one_issuer_is_not_shared_with_a_provider_expecting_another
        assert browser.sign_in('entra').ok?
        other = browser({ issuer: "https://#{FakeEntra::HOST}/other-tenant/v2.0" }, 'other')
        assert_clean_failure other.start('other'), :discovery_failed
      end

      def test_allowed_endpoint_hosts_admits_a_second_host
        stub_request(:any, %r{\Ahttps://keys\.example\.test/}).to_rack(@fake)
        @fake.configure(discovery_overrides: { jwks_uri: "https://keys.example.test#{URI(@fake.jwks_url).path}" })
        assert_clean_failure browser.start('entra'), :discovery_failed
        clear_fetch_cache
        result = browser(allowed_endpoint_hosts: [FakeEntra::HOST, 'keys.example.test']).sign_in('entra')
        assert result.ok?, result.failure.inspect
      end

      # The cache is process-wide: a document accepted under a looser host list must not be reused by a provider
      # with a stricter one, even with the same discovery URL and issuer.
      def test_document_accepted_under_looser_hosts_is_not_shared_with_stricter_provider
        stub_request(:any, %r{\Ahttps://keys\.example\.test/}).to_rack(@fake)
        @fake.configure(discovery_overrides: { jwks_uri: "https://keys.example.test#{URI(@fake.jwks_url).path}" })
        loose = browser({ allowed_endpoint_hosts: [FakeEntra::HOST, 'keys.example.test'] }, 'loose')
        assert loose.sign_in('loose').ok?

        strict = browser({}, 'strict')
        assert_clean_failure strict.start('strict'), :discovery_failed
        assert_equal 2, counts[:discovery]
      end

      def test_discovery_url_and_issuer_must_be_https
        { discovery_url: 'http://login.example.test/x/.well-known/openid-configuration',
          issuer: 'http://login.example.test/x' }.each do |k, v|
          strategy = OmniAuth::Strategies::OpenIDConnect.new(nil, provider_options('entra', k => v))
          assert_raises(OmniAuth::OpenIDConnect::ConfigurationError, k.to_s) { strategy.request_phase }
        end
      end

      def test_issuer_is_required_with_discovery_url
        strategy = OmniAuth::Strategies::OpenIDConnect.new(nil, provider_options('entra', issuer: nil))
        assert_raises(OmniAuth::OpenIDConnect::ConfigurationError) { strategy.request_phase }
      end

      def test_unknown_client_auth_method_is_refused
        strategy = OmniAuth::Strategies::OpenIDConnect.new(nil,
                                                           provider_options('entra', client_auth_method: 'client_secret_basic'))
        assert_raises(OmniAuth::OpenIDConnect::ConfigurationError) { strategy.request_phase }
      end

      def test_token_endpoint_read_timeout_is_a_clean_failure
        stub_request(:post, @fake.token_url).to_raise(Net::ReadTimeout)
        assert_clean_failure browser.sign_in('entra'), :timeout
      end

      # faraday-net_http reports a connect timeout (Net::OpenTimeout) as Faraday::ConnectionFailed.
      def test_token_endpoint_connect_timeout_is_a_clean_failure
        stub_request(:post, @fake.token_url).to_timeout
        assert_clean_failure browser.sign_in('entra'), :failed_to_connect
      end

      def test_token_endpoint_error_description_stays_out_of_failure_and_log
        @fake.configure(token_error: [400, { error: 'invalid_grant', error_description: DESCRIPTION }])
        result = browser.sign_in('entra')
        assert_clean_failure result, :invalid_grant
        refute_includes result.failure[:message].to_s, DESCRIPTION
        refute_includes result.log, DESCRIPTION
      end

      def test_token_endpoint_error_code_that_is_not_a_plain_word_is_not_echoed
        @fake.configure(token_error: [400, { error: 'x<script>', error_description: DESCRIPTION }])
        result = browser.sign_in('entra')
        assert_clean_failure result, :provider_error
        refute_includes result.failure[:message].to_s + result.log, 'script'
      end

      # A server that accepts the connection and never answers.
      def with_silent_server
        server = TCPServer.new('127.0.0.1', 0)
        thread = Thread.new do
          client = server.accept
          sleep 5
          client.close
        rescue IOError
          nil
        end
        WebMock.disable_net_connect!(allow_localhost: true)
        yield server.addr[1]
      ensure
        WebMock.disable_net_connect!
        thread&.kill
        server&.close
      end

      def test_read_timeout_reaches_the_metadata_fetch
        strategy = OmniAuth::Strategies::OpenIDConnect.new(nil, provider_options('entra', read_timeout: 0.3))
        with_silent_server do |port|
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          assert_raises(Faraday::TimeoutError) { strategy.send(:fetch_json, "http://127.0.0.1:#{port}/meta") }
          assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 2
        end
      end

      def test_read_timeout_reaches_the_token_request
        with_silent_server do |port|
          options = { name: 'entra', read_timeout: 0.3, scope: [:openid],
                      client_options: { identifier: 'id', secret: 's', scheme: 'http', host: '127.0.0.1', port: port,
                                        redirect_uri: "#{PORTAL}/auth/entra/callback" } }
          strategy = OmniAuth::Strategies::OpenIDConnect.new(nil, options)
          session = { 'omniauth.nonce.entra' => 'n', 'omniauth.pkce.verifier.entra' => 'v' }
          strategy.instance_variable_set(:@env,
                                         Rack::MockRequest.env_for('/auth/entra/callback?code=c', 'rack.session' => session))
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          assert_raises(Faraday::TimeoutError) { strategy.send(:access_token) }
          assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 2
        end
      end
    end
  end
end
