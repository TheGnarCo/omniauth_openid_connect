# frozen_string_literal: true

require 'open3'
require_relative '../../../test_helper'
require_relative '../../../support/oidc_harness'

module OmniAuth
  module Strategies
    # The Gnar hardening matrix: each test drives a full sign-in through OmniAuth and FakeEntra and states the
    # behaviour the library must have. Numbering follows the auth library trial (T1-T16, X1-X5).
    class OpenIDConnectMatrixTest < Minitest::Test
      include OidcHarness

      DESCRIPTION = 'attacker-controlled <b>text</b> 4711'

      def test_t01_loads_without_warnings_from_this_gem
        lib = File.expand_path('../../../../lib', __dir__)
        _out, err, status = Open3.capture3(Gem.ruby, '-w', "-I#{lib}", '-e', "require 'omniauth_openid_connect'")
        assert status.success?, err
        assert_empty err.lines.grep(/#{Regexp.escape(lib)}/)
      end

      def test_t02_happy_path_exposes_uid_claims_and_credentials
        result = browser.sign_in('entra')
        assert result.ok?, "#{result.status} #{result.body[0, 200]} #{result.failure.inspect}"
        json = result.json
        assert_equal 'entra', json['provider']
        assert_equal FakeEntra::SUB, json['uid']
        assert_equal FakeEntra::TENANT_ID, json['raw_info']['tid']
        assert_equal FakeEntra::OID, json['raw_info']['oid']
        assert_equal 3600, json['credentials']['expires_in']
        assert_kind_of String, json['credentials']['id_token']
      end

      def test_t03_metadata_comes_from_discovery_url_and_userinfo_is_not_called
        b = Browser.new(build_app([provider_options('entra').tap { |o| o.delete(:discovery) }]), @fake)
        result = b.sign_in('entra')
        assert result.ok?, result.failure.inspect
        assert_equal([URI(@fake.discovery_url).path], @fake.requests_of(:discovery).map { |r| r[:path] })
        assert_empty @fake.requests_of(:not_found)
        assert_not_requested :get, FakeEntra::USERINFO_URL
      end

      def test_t03_discovery_document_with_another_issuer_is_refused
        @fake.configure(discovery_overrides: { issuer: "https://#{FakeEntra::HOST}/other-tenant/v2.0" })
        assert_clean_failure browser.start('entra'), :discovery_failed
      end

      def test_t04_pkce_s256_by_default_and_verifier_matches
        result = browser.sign_in('entra')
        assert result.ok?, result.failure.inspect
        authorize = @fake.requests_of(:authorize).last[:params]
        verifier = @fake.requests_of(:token).last[:params]['code_verifier']
        assert_equal 'S256', authorize['code_challenge_method']
        assert_equal authorize['code_challenge'], Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false)
      end

      def test_t05_verifier_comes_from_the_session_not_the_callback
        result = browser(pkce: true).sign_in('entra') { |cb| OidcHarness.with_params(cb, 'code_verifier' => 'attacker') }
        sent = @fake.requests_of(:token).last[:params]['code_verifier']
        challenge = @fake.requests_of(:authorize).last[:params]['code_challenge']
        refute_equal 'attacker', sent
        assert_equal challenge, Base64.urlsafe_encode64(Digest::SHA256.digest(sent.to_s), padding: false)
        assert result.ok?, result.failure.inspect
      end

      def test_t05_missing_session_verifier_fails_before_the_token_request
        b = browser
        callback = b.idp(b.start('entra'))
        b.session.delete_if { |k, _| k.include?('pkce') }
        assert_clean_failure b.callback(callback), :missing_code_verifier
        assert_empty @fake.requests_of(:token)
      end

      def test_t06a_missing_state_fails
        result = browser.sign_in('entra') { |cb| OidcHarness.with_params(cb, {}, ['state']) }
        assert_clean_failure result, :csrf_detected
        assert_empty @fake.requests_of(:token)
      end

      def test_t06b_wrong_state_fails
        result = browser.sign_in('entra') { |cb| OidcHarness.with_params(cb, 'state' => 'wrong') }
        assert_clean_failure result, :csrf_detected
        assert_empty @fake.requests_of(:token)
      end

      def test_t06b2_state_differing_in_last_character_fails
        result = browser.sign_in('entra') do |cb|
          state = OidcHarness.param(cb, 'state')
          OidcHarness.with_params(cb, 'state' => state[0..-2] + (state[-1] == '0' ? '1' : '0'))
        end
        assert_clean_failure result, :csrf_detected
      end

      def test_t06c_replayed_callback_with_current_session_fails_without_second_token_request
        b = browser
        callback = nil
        assert b.sign_in('entra') { |cb| callback = cb }.ok?
        assert_clean_failure b.callback(callback), :csrf_detected
        assert_equal 1, @fake.requests_of(:token).size
      end

      def test_t07a_provider_error_with_valid_state_keeps_only_the_code
        @fake.configure(authorize_error: { error: 'access_denied', error_description: DESCRIPTION })
        result = browser.sign_in('entra')
        assert_clean_failure result, :access_denied
        refute_includes result.failure[:message].to_s, DESCRIPTION
        refute_includes result.log, DESCRIPTION
      end

      def test_t07b_provider_error_with_missing_or_wrong_state_is_a_state_failure
        %i[missing wrong].each do |mode|
          @fake.configure(authorize_error: { error: 'access_denied', error_description: DESCRIPTION, state: mode })
          result = browser.sign_in('entra')
          assert_clean_failure result, :csrf_detected
          refute_includes result.failure[:message].to_s, DESCRIPTION
          refute_includes result.log, DESCRIPTION
        end
      end

      def test_t07c_provider_error_code_that_is_not_a_plain_word_is_not_echoed
        @fake.configure(authorize_error: { error: 'x<script>', error_description: DESCRIPTION })
        result = browser.sign_in('entra')
        assert_clean_failure result, :provider_error
        refute_includes result.failure[:message].to_s + result.log, 'script'
      end

      def test_t08a_wrong_nonce_is_rejected
        @fake.configure(claims: { nonce: 'wrong' })
        assert_clean_failure browser.sign_in('entra'), :invalid_id_token
      end

      def test_t08b1_token_without_nonce_claim_is_rejected
        @fake.configure(remove_claims: [:nonce])
        assert_clean_failure browser.sign_in('entra'), :invalid_id_token
      end

      def test_t08b2_no_nonce_in_session_and_none_in_token_is_rejected
        @fake.configure(remove_claims: [:nonce])
        b = browser
        callback = b.idp(b.start('entra'))
        b.session.delete_if { |k, _| k.include?('nonce') }
        assert_clean_failure b.callback(callback), :missing_nonce
      end

      def test_t08c_nonce_from_the_callback_is_ignored
        @fake.configure(claims: { nonce: 'attacker-nonce' })
        result = browser.sign_in('entra') { |cb| OidcHarness.with_params(cb, 'nonce' => 'attacker-nonce') }
        assert_clean_failure result, :invalid_id_token
      end

      {
        'wrong iss' => [{ claims: { iss: 'https://evil.example.test/v2.0' } }, :invalid_id_token],
        'wrong aud' => [{ claims: { aud: 'someone-else' } }, :invalid_id_token],
        'expired exp' => [-> { { claims: { exp: Time.now.to_i - 10 } } }, :invalid_id_token],
        'missing exp' => [{ remove_claims: [:exp] }, :invalid_id_token],
        'alg none' => [{ alg: 'none' }, :invalid_jwt_algorithm],
        'alg HS256 empty key' => [{ alg: 'HS256' }, :invalid_jwt_algorithm],
        'alg HS256 public key as secret' => [{ alg: 'HS256_pubkey' }, :invalid_jwt_algorithm],
        'unknown signing key' => [{ unknown_key: true }, :invalid_id_token],
        'nbf beyond the leeway' => [-> { { claims: { nbf: Time.now.to_i + 62 } } }, :invalid_id_token],
        'several audiences without azp' => [{ claims: { aud: [FakeEntra::CLIENT_ID, 'other'] } }, :invalid_id_token],
        'azp naming another client' => [{ claims: { azp: 'other' } }, :invalid_id_token],
      }.each_with_index do |(label, (knobs, type)), i|
        define_method(format('test_t09_%<i>02d_rejects_%<label>s', i: i, label: label.tr(' ', '_'))) do
          @fake.configure(**(knobs.respond_to?(:call) ? knobs.call : knobs))
          assert_clean_failure browser.sign_in('entra'), type
        end
      end

      def test_t09_accepts_several_audiences_with_azp_equal_to_the_client
        @fake.configure(claims: { aud: ['other', FakeEntra::CLIENT_ID], azp: FakeEntra::CLIENT_ID })
        result = browser.sign_in('entra')
        assert result.ok?, result.failure.inspect
      end

      def test_t09_accepts_nbf_at_the_leeway_and_honours_the_option
        @fake.configure(claims: { nbf: Time.now.to_i + 60 })
        result = browser.sign_in('entra')
        assert result.ok?, result.failure.inspect
        @fake.configure(claims: { nbf: Time.now.to_i + 30 })
        assert_clean_failure browser(nbf_leeway: 0).sign_in('entra'), :invalid_id_token
      end

      def test_t04_pkce_method_other_than_s256_is_refused
        options = provider_options('entra', pkce_options: { code_challenge: ->(v) { v }, code_challenge_method: 'plain' })
        strategy = OmniAuth::Strategies::OpenIDConnect.new(nil, options)
        assert_raises(OmniAuth::OpenIDConnect::ConfigurationError) { strategy.request_phase }
      end

      def test_t09_accepts_nbf_inside_the_leeway
        @fake.configure(claims: { nbf: Time.now.to_i + 30 })
        result = browser.sign_in('entra')
        assert result.ok?, result.failure.inspect
      end

      def test_t10_signing_key_rotation_refreshes_the_key_set_once
        b = browser
        assert b.sign_in('entra').ok?
        @fake.rotate_keys!
        second = Browser.new(b.app, @fake).sign_in('entra')
        assert second.ok?, second.failure.inspect
        assert_equal 2, @fake.requests_of(:jwks).size
      end

      def test_t10_rotation_with_the_old_key_dropped
        b = browser
        assert b.sign_in('entra').ok?
        @fake.rotate_keys!(drop_old: true)
        second = Browser.new(b.app, @fake).sign_in('entra')
        assert second.ok?, second.failure.inspect
      end

      def test_t11_client_authentication_methods
        assert browser.sign_in('entra').ok?
        assert_equal :basic, @fake.requests_of(:token).last[:client_auth]

        assert browser(client_auth_method: :post).sign_in('entra').ok?
        assert_equal :post, @fake.requests_of(:token).last[:client_auth]

        @fake.configure(token_auth: :post)
        assert_clean_failure browser.sign_in('entra'), :invalid_client
      end

      def test_t12_login_hint_reaches_the_idp_and_other_params_stay_local
        result = browser.sign_in('entra', 'login_hint' => 'a@b.test', 'invitation' => 'tok')
        assert result.ok?, result.failure.inspect
        authorize = @fake.requests_of(:authorize).last[:params]
        assert_equal 'a@b.test', authorize['login_hint']
        refute_includes authorize.values.join, 'tok'
        assert_equal({ 'login_hint' => 'a@b.test', 'invitation' => 'tok' }, result.json['params'])
      end

      def test_t13_no_prompt_by_default
        browser.sign_in('entra')
        refute @fake.requests_of(:authorize).last[:params].key?('prompt')
      end

      def two_provider_browser
        Browser.new(build_app([provider_options('entra_a'), provider_options('entra_b')]), @fake)
      end

      def test_t14_two_providers_interleaved_in_one_session
        [%i[a b], %i[b a]].each do |order|
          b = two_provider_browser
          callbacks = {
            a: b.idp(b.start('entra_a', 'invitation' => 'tokA')),
            b: b.idp(b.start('entra_b')),
          }
          results = order.to_h { |k| [k, b.callback(callbacks[k])] }
          assert results[:a].ok?, "#{order}: A #{results[:a].failure.inspect}"
          assert results[:b].ok?, "#{order}: B #{results[:b].failure.inspect}"
          assert_equal({ 'invitation' => 'tokA' }, results[:a].json['params'])
          assert_equal({}, results[:b].json['params'])
        end
      end

      def test_t15_get_logout_route_is_passed_to_the_app
        b = browser(post_logout_redirect_uri: "#{PORTAL}/signed_out")
        assert b.sign_in('entra').ok?
        result = b.request('GET', '/auth/entra/logout')
        assert_equal 404, result.status, 'the gem must not redirect to the end_session_endpoint itself'
        assert_empty @fake.requests_of(:logout)
      end

      def test_t15_logout_redirect_url_for_the_app
        options = provider_options('entra', post_logout_redirect_uri: "#{PORTAL}/signed_out")
        strategy = OmniAuth::Strategies::OpenIDConnect.new(nil, options)
        url = strategy.logout_redirect_url(logout_hint: 'hint-1', state: 's-123')
        assert url.start_with?("#{@fake.logout_url}?"), url
        assert_equal "#{PORTAL}/signed_out", OidcHarness.param(url, 'post_logout_redirect_uri')
        assert_equal 'hint-1', OidcHarness.param(url, 'logout_hint')
        assert_equal 's-123', OidcHarness.param(url, 'state')
        assert_nil OidcHarness.param(url, 'id_token_hint')
      end

      def test_t15_no_id_token_is_kept_in_the_session
        b = browser
        assert b.sign_in('entra').ok?
        refute_match(/eyJ[A-Za-z0-9_-]{10,}\./, b.session.to_s)
      end

      def test_t16_response_mode_query_is_allowed
        location = browser(response_mode: 'query').start('entra')
        assert_equal 'query', OidcHarness.param(location, 'response_mode')
        assert_nil OidcHarness.param(browser.start('entra'), 'response_mode')
      end

      def test_t16_response_mode_form_post_is_refused
        strategy = OmniAuth::Strategies::OpenIDConnect.new(nil, provider_options('entra', response_mode: 'form_post'))
        assert_raises(OmniAuth::OpenIDConnect::ConfigurationError) { strategy.request_phase }
      end

      def test_t16_response_type_other_than_code_is_refused
        ['id_token', :id_token, 'code id_token', 'token'].each do |type|
          strategy = OmniAuth::Strategies::OpenIDConnect.new(nil, provider_options('entra', response_type: type))
          error = assert_raises(OmniAuth::OpenIDConnect::ConfigurationError, type.inspect) { strategy.request_phase }
          assert_includes error.message, "'code'"
          assert_raises(OmniAuth::OpenIDConnect::ConfigurationError) { browser(response_type: type).start('entra') }
        end
      end

      def test_t16_unset_response_type_means_code
        %w[code].push(nil, :code).each do |type|
          location = browser(response_type: type).start('entra')
          assert_equal 'code', OidcHarness.param(location, 'response_type'), type.inspect
        end
      end

      def test_x1_token_response_without_id_token_fails
        @fake.configure(no_id_token: true)
        assert_clean_failure browser.sign_in('entra'), :missing_id_token
      end

      def test_x3_hs256_token_signed_with_the_client_secret_is_rejected
        @fake.configure(alg: 'HS256', hmac_secret: FakeEntra::CLIENT_SECRET)
        assert_clean_failure browser.sign_in('entra'), :invalid_jwt_algorithm
      end

      def test_x4a_state_is_stored_per_provider_and_removed_on_first_read
        b = browser
        callback = b.idp(b.start('entra'))
        assert_equal ['omniauth.state.entra'], b.session.keys.grep(/state/)
        assert b.callback(callback).ok?
        assert_empty b.session.keys.grep(/state/)
      end

      def test_x4b_state_is_compared_in_constant_time
        compared = []
        Rack::Utils.stubs(:secure_compare).with { |a, b| compared << [a, b] }.returns(true)
        b = browser
        callback = b.idp(b.start('entra'))
        state = OidcHarness.param(callback, 'state')
        assert b.callback(callback).ok?
        assert_includes compared, [state, state]
      end

      def test_x5_redirect_uri_is_pinned_to_the_configured_value
        location = browser.start('entra', 'redirect_uri' => 'https://evil.example.test/cb')
        assert_equal "#{PORTAL}/auth/entra/callback", OidcHarness.param(location, 'redirect_uri')
      end
    end
  end
end
