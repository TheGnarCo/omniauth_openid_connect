# frozen_string_literal: true

require 'logger'
require 'stringio'
require_relative 'fake_entra'

# Drives the strategy through a real OmniAuth middleware stack, against FakeEntra, with a Hash as the session
# (a server-side session store). Include it in a Minitest::Test.
module OidcHarness
  PORTAL = 'https://portal.example.test'

  Result = Struct.new(:status, :headers, :body, :failure, :log, keyword_init: true) do
    def ok?
      status == 200
    end

    def failed?
      status == 400 && !failure.nil?
    end

    def json
      JSON.parse(body)
    end

    def location
      headers['location'] || headers['Location']
    end
  end

  # Final app: what a callback controller would see.
  class Terminal
    def call(env)
      auth = env['omniauth.auth']
      return [404, {}, ['not found']] unless auth

      body = {
        provider: auth['provider'], uid: auth['uid'], info: auth['info'].to_h,
        credentials: auth['credentials'].to_h, raw_info: auth['extra']['raw_info'].to_h,
        params: env['omniauth.params'], session_keys: env['rack.session'].keys
      }
      [200, { 'content-type' => 'application/json' }, [JSON.generate(body)]]
    end
  end

  # One browser: a session (as the server keeps it) and the portal app.
  class Browser
    attr_accessor :session
    attr_reader :app, :fake

    def initialize(app, fake)
      @app = app
      @fake = fake
      @session = {}
    end

    def request(method, url, params = {})
      Thread.current[:oidc_failure] = nil
      uri = URI(url)
      path = uri.query ? "#{uri.path}?#{uri.query}" : uri.path
      env = Rack::MockRequest.env_for(path, method: method, params: params)
      env['rack.session'] = @session
      status, headers, body = app.call(env)
      text = +''
      body.each { |part| text << part }
      Result.new(status: status, headers: headers, body: text, failure: Thread.current[:oidc_failure],
                 log: OidcHarness.log.string)
    end

    # POSTs to the request phase. Returns the authorize URL, or the Result when there is no redirect.
    def start(name, query = {})
      qs = query.empty? ? '' : "?#{URI.encode_www_form(query)}"
      result = request('POST', "/auth/#{name}#{qs}")
      result.status == 302 ? result.location : result
    end

    # Visits the authorize URL at the fake IdP and returns the callback URL it redirects to.
    def idp(url)
      _status, headers, = fake.call(Rack::MockRequest.env_for(url))
      headers['location']
    end

    def callback(url)
      request('GET', url)
    end

    def sign_in(name, query = {})
      location = start(name, query)
      return location if location.is_a?(Result)

      cb = idp(location)
      cb = yield(cb) if block_given?
      callback(cb)
    end
  end

  class << self
    attr_accessor :log
  end

  def self.with_params(url, add = {}, remove = [])
    uri = URI(url)
    query = URI.decode_www_form(uri.query.to_s).reject { |k, _| remove.include?(k) || add.key?(k) } + add.to_a
    uri.query = URI.encode_www_form(query)
    uri.to_s
  end

  def self.param(url, key)
    URI.decode_www_form(URI(url).query.to_s).to_h[key]
  end

  def setup
    super
    @fake = FakeEntra.new
    stub_request(:any, %r{\Ahttps://#{Regexp.escape(FakeEntra::HOST)}/}).to_rack(@fake)
    # UserInfo lives on another host, as Entra's does. The strategy must never call it; the stub lets an
    # unhardened strategy get past it so the other checks still say something.
    stub_request(:get, FakeEntra::USERINFO_URL)
      .to_return(body: JSON.generate(sub: FakeEntra::SUB), headers: { 'content-type' => 'application/json' })
    clear_fetch_cache
    @saved_omniauth = %i[test_mode request_validation_phase on_failure logger full_host].to_h { |k| [k, OmniAuth.config.send(k)] }
    OidcHarness.log = StringIO.new
    OmniAuth.config.test_mode = false
    OmniAuth.config.request_validation_phase = nil
    OmniAuth.config.full_host = PORTAL
    OmniAuth.config.logger = Logger.new(OidcHarness.log)
    OmniAuth.config.on_failure = lambda do |env|
      error = env['omniauth.error']
      Thread.current[:oidc_failure] =
        { type: env['omniauth.error.type'], error_class: error&.class&.name, message: error&.message }
      [400, { 'content-type' => 'text/plain' }, ["failure #{env['omniauth.error.type']}"]]
    end
  end

  def teardown
    @saved_omniauth.each { |k, v| OmniAuth.config.send("#{k}=", v) }
    super
  end

  def clear_fetch_cache
    return unless defined?(OmniAuth::OpenIDConnect::FetchCache) && OmniAuth::Strategies::OpenIDConnect.respond_to?(:fetch_cache)

    OmniAuth::Strategies::OpenIDConnect.fetch_cache.clear!
  end

  def provider_options(name = 'entra', extra = {})
    {
      name: name,
      issuer: @fake.issuer,
      discovery: true,
      discovery_url: @fake.discovery_url,
      scope: %i[openid profile],
      client_options: {
        identifier: FakeEntra::CLIENT_ID,
        secret: FakeEntra::CLIENT_SECRET,
        redirect_uri: "#{PORTAL}/auth/#{name}/callback",
      },
    }.merge(extra)
  end

  def build_app(providers)
    Rack::Builder.new do
      use OmniAuth::Builder do
        providers.each { |opts| provider :openid_connect, opts }
      end
      run Terminal.new
    end.to_app
  end

  def browser(extra = {}, name = 'entra')
    Browser.new(build_app([provider_options(name, extra)]), @fake)
  end

  def assert_clean_failure(result, type = nil)
    assert_kind_of Result, result, "expected a failure, got a redirect to #{result}"
    assert result.failed?, "expected a clean failure, got #{result.status}: #{result.body[0, 200]}"
    assert_equal type, result.failure[:type] if type
  end
end
