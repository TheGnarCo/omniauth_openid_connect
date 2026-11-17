# frozen_string_literal: true

require 'json'
require 'rack'

# An in-process identity provider shaped like a single Entra tenant (v2.0 endpoints), served to the strategy
# through WebMock's to_rack. It keeps a log of what it received and has knobs to misbehave.
class FakeEntra
  HOST = 'login.example.test'
  TENANT_ID = '11111111-2222-3333-4444-555555555555'
  CLIENT_ID = 'client-id-0001'
  CLIENT_SECRET = 'client-secret-0001'
  SUB = 'pairwise-sub-0001'
  OID = '99999999-8888-7777-6666-555555555555'
  USERINFO_URL = 'https://graph.example.test/oidc/userinfo'

  KEY_POOL = Array.new(4) { OpenSSL::PKey::RSA.generate(2048) }.freeze

  attr_reader :requests

  def initialize
    reset!
  end

  def reset!
    @requests = []
    @codes = {}
    @key_index = 0
    @published = [signing_key]
    @knobs = {}
    self
  end

  def configure(**knobs)
    @knobs.merge!(knobs)
    self
  end

  def issuer
    "https://#{HOST}/#{TENANT_ID}/v2.0"
  end

  def discovery_url
    "#{issuer}/.well-known/openid-configuration"
  end

  def authorize_url
    "https://#{HOST}/#{TENANT_ID}/oauth2/v2.0/authorize"
  end

  def token_url
    "https://#{HOST}/#{TENANT_ID}/oauth2/v2.0/token"
  end

  def jwks_url
    "https://#{HOST}/#{TENANT_ID}/discovery/v2.0/keys"
  end

  def logout_url
    "https://#{HOST}/#{TENANT_ID}/oauth2/v2.0/logout"
  end

  def requests_of(type)
    requests.select { |r| r[:type] == type }
  end

  # Starts signing with the next key. The old key stays published unless drop_old is set.
  def rotate_keys!(drop_old: false)
    @key_index += 1
    @published = drop_old ? [signing_key] : @published + [signing_key]
  end

  def signing_key
    JSON::JWK.new(KEY_POOL.fetch(@key_index))
  end

  def call(env)
    req = Rack::Request.new(env)
    case req.path
    when URI(discovery_url).path then discovery(req)
    when URI(jwks_url).path then jwks(req)
    when URI(token_url).path then token(req)
    when URI(authorize_url).path then authorize(req)
    when URI(logout_url).path then logout(req)
    else
      log(:not_found, req)
      [404, {}, ['not found']]
    end
  end

  private

  def log(type, req, extra = {})
    @requests << { type: type, params: req.params, path: req.path }.merge(extra)
  end

  def json(status, body)
    [status, { 'content-type' => 'application/json' }, [body.is_a?(String) ? body : JSON.generate(body)]]
  end

  def discovery(req)
    log(:discovery, req)
    if @knobs[:discovery_status]
      return [@knobs[:discovery_status], { 'content-type' => 'text/html' },
              [@knobs[:discovery_body].to_s]]
    end
    return [200, { 'content-type' => 'text/html' }, [@knobs[:discovery_body]]] if @knobs[:discovery_body]

    doc = {
      issuer: issuer,
      authorization_endpoint: authorize_url,
      token_endpoint: token_url,
      jwks_uri: jwks_url,
      end_session_endpoint: logout_url,
      userinfo_endpoint: USERINFO_URL,
      response_types_supported: %w[code id_token],
      subject_types_supported: ['pairwise'],
      id_token_signing_alg_values_supported: ['RS256'],
    }
    json(200, doc.merge(@knobs[:discovery_overrides] || {}))
  end

  def jwks(req)
    log(:jwks, req)
    return json(@knobs[:jwks_status], 'error') if @knobs[:jwks_status]

    keys = @published.map { |k| JSON::JWK.new(k.to_key.public_key) }
    json(200, keys: keys)
  end

  def authorize(req)
    log(:authorize, req)
    p = req.params
    callback = URI(p['redirect_uri'].to_s)
    if (err = @knobs[:authorize_error])
      query = { 'error' => err[:error], 'error_description' => err[:error_description] }
      query['state'] = err[:state] == :wrong ? 'wrong-state' : p['state'] unless err[:state] == :missing
      callback.query = URI.encode_www_form(query)
      return [302, { 'location' => callback.to_s }, []]
    end

    code = SecureRandom.hex(16)
    @codes[code] = { nonce: p['nonce'], challenge: p['code_challenge'], method: p['code_challenge_method'],
                     redirect_uri: p['redirect_uri'], login_hint: p['login_hint'] }
    callback.query = URI.encode_www_form('code' => code, 'state' => p['state'])
    [302, { 'location' => callback.to_s }, []]
  end

  def token(req)
    auth = client_auth(req)
    log(:token, req, client_auth: auth)
    return json(*@knobs[:token_error]) if @knobs[:token_error]

    allowed = @knobs.fetch(:token_auth, :both)
    return json(401, error: 'invalid_client') unless auth && (allowed == :both || allowed == auth)

    grant = @codes.delete(req.params['code'])
    return json(400, error: 'invalid_grant') unless grant
    return json(400, error: 'invalid_grant') unless grant[:redirect_uri] == req.params['redirect_uri']
    return json(400, error: 'invalid_grant') unless pkce_ok?(grant, req.params['code_verifier'])

    body = { access_token: "at-#{SecureRandom.hex(8)}", token_type: 'Bearer', expires_in: 3600, scope: 'openid profile' }
    body[:id_token] = id_token(grant) unless @knobs[:no_id_token]
    json(200, body)
  end

  def logout(req)
    log(:logout, req)
    target = req.params['post_logout_redirect_uri']
    target ? [302, { 'location' => target }, []] : [200, {}, ['signed out']]
  end

  def client_auth(req)
    header = req.get_header('HTTP_AUTHORIZATION').to_s
    if header.start_with?('Basic ')
      id, secret = Base64.decode64(header.sub('Basic ', '')).split(':', 2).map { |v| CGI.unescape(v) }
      return :basic if id == CLIENT_ID && secret == CLIENT_SECRET
    elsif req.params['client_secret']
      return :post if req.params['client_id'] == CLIENT_ID && req.params['client_secret'] == CLIENT_SECRET
    end
    nil
  end

  def pkce_ok?(grant, verifier)
    return true unless grant[:challenge]
    return false if verifier.to_s.empty?

    Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false) == grant[:challenge]
  end

  def id_token(grant)
    now = Time.now.to_i
    claims = { iss: issuer, aud: CLIENT_ID, sub: SUB, tid: TENANT_ID, oid: OID, nonce: grant[:nonce],
               email: grant[:login_hint] || 'user@example.test', name: 'Test User', iat: now, nbf: now, exp: now + 3600 }
    claims.merge!(@knobs[:claims] || {})
    Array(@knobs[:remove_claims]).each { |c| claims.delete(c) }
    sign(JSON::JWT.new(claims))
  end

  def sign(jwt)
    case @knobs[:alg]
    when 'none' then jwt.to_s
    when 'HS256' then jwt.sign(@knobs.fetch(:hmac_secret, ''), :HS256).to_s
    when 'HS256_pubkey' then jwt.sign(signing_key.to_key.public_key.to_pem, :HS256).to_s
    else
      key = @knobs[:unknown_key] ? JSON::JWK.new(KEY_POOL.last) : signing_key
      jwt.sign(key, :RS256).to_s
    end
  end
end
