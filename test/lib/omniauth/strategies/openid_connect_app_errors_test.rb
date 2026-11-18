# frozen_string_literal: true

require_relative '../../../test_helper'
require_relative '../../../support/oidc_harness'

module OmniAuth
  module Strategies
    # An exception raised by the host application's callback endpoint is the application's own error. It must reach
    # the caller unchanged and must not be turned into a sign-in failure by the strategy's rescues.
    class OpenIDConnectAppErrorsTest < Minitest::Test
      include OidcHarness

      def test_no_method_error_from_the_app_callback_propagates
        seen = nil
        error = assert_raises(NoMethodError) do
          app_browser(->(env) { seen = env['omniauth.auth']; nil.undefined_in_controller }).sign_in('entra')
        end
        assert_match(/undefined_in_controller/, error.message)
        assert_equal FakeEntra::SUB, seen['uid']
        assert_nil Thread.current[:oidc_failure]
      end

      def test_type_error_from_the_app_callback_propagates
        error = assert_raises(TypeError) do
          app_browser(->(_env) { raise TypeError, 'app bug' }).sign_in('entra')
        end
        assert_equal 'app bug', error.message
        assert_nil Thread.current[:oidc_failure]
      end

      private

      def app_browser(endpoint)
        options = provider_options('entra')
        app = Rack::Builder.new do
          use OmniAuth::Builder do
            provider :openid_connect, options
          end
          run endpoint
        end
        Browser.new(app.to_app, @fake)
      end
    end
  end
end
