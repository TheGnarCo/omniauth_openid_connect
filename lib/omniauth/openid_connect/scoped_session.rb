# frozen_string_literal: true

require 'delegate'

module OmniAuth
  module OpenIDConnect
    # Gnar: gives each provider its own session keys for the values a sign-in keeps between the request phase and
    # the callback. Without it, two providers share omniauth.state, .nonce, .pkce.verifier, .params and .origin,
    # and starting a sign-in with one overwrites a sign-in in progress with the other.
    class ScopedSession < SimpleDelegator
      KEYS = %w[omniauth.state omniauth.nonce omniauth.pkce.verifier omniauth.params omniauth.origin].freeze

      def initialize(store, provider)
        super(store)
        @provider = provider.to_s
      end

      def [](key)
        __getobj__[scope(key)]
      end

      def []=(key, value)
        __getobj__[scope(key)] = value
      end

      def delete(key, &block)
        __getobj__.delete(scope(key), &block)
      end

      def key?(key)
        __getobj__.key?(scope(key))
      end
      alias has_key? key?
      alias include? key?

      private

      def scope(key)
        KEYS.include?(key.to_s) ? "#{key}.#{@provider}" : key
      end
    end
  end
end
