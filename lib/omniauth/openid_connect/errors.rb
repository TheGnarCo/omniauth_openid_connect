# frozen_string_literal: true

module OmniAuth
  module OpenIDConnect
    class Error < RuntimeError; end

    class MissingCodeError < Error; end

    # Gnar: the strategy options are unsafe or incomplete. Raised, not turned into a sign-in failure.
    class ConfigurationError < Error; end

    # Gnar: a discovery document names an issuer or an endpoint the configuration does not allow.
    class UnsafeMetadataError < Error; end

    # Gnar: a discovery document or key set response was not a usable 2xx JSON body.
    class HttpResponseError < Error; end
  end
end
