module Rack
  module OAuth2
    class Server

      # The access grant is a nonce, new grant created each time we need it and
      # good for redeeming one access token.
      class AccessGrant
        include DataMapper::Resource

        class << self
          # Find AccessGrant from authentication code.
          def from_code(code)
            get(code)
          end

          # Create a new access grant.
          def create(identity, client, scope, redirect_uri = nil, expires = nil)
            raise ArgumentError, "Identity must be String or Integer" unless String === identity || Integer === identity
            scope = Utils.normalize_scope(scope) & client.scope # Only allowed scope
            expires_at = Time.now.to_i + (expires || 300)
            fields = { :identity=>identity, :scope=>scope,
                       :client=>client, :redirect_uri=>client.redirect_uri || redirect_uri,
                       :granted_at=>nil, :expires_at => expires,
                       :access_token=>nil, :revoked=>nil }
            c = super(fields)
            c.save
            c
          end
        end

        belongs_to :client
        belongs_to :access_token, :required => false
        property :code,         String, :key => true, :length => 72, :default => proc { Server.secure_random }
        property :identity,     String
        property :redirect_uri, String
        property :scope,        Json
        property :created_at,   DateTime, :default => proc { Time.now }
        property :granted_at,   DateTime
        property :expires_at,   DateTime, :default => proc { Time.now.to_i + 300 }
        property :revoked,      DateTime

        # Authorize access and return new access token.
        #
        # Access grant can only be redeemed once, but client can make multiple
        # requests to obtain it, so we need to make sure only first request is
        # successful in returning access token, futher requests raise
        # InvalidGrantError.
        def authorize!(expires_in = nil)
          raise InvalidGrantError, "You can't use the same access grant twice" if self.access_token || self.revoked
          access_token = AccessToken.get_token_for(identity, client, scope, expires_in)
          self.granted_at = Time.now
          self.access_token = access_token
          self.save
          return access_token
        end

        def revoke!
          self.revoked = Time.now
          self.save
        end
      end

    end
  end
end
