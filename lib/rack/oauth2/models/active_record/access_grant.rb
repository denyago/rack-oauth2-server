module Rack
  module OAuth2
    class Server

      # The access grant is a nonce, new grant created each time we need it and
      # good for redeeming one access token.
      class AccessGrant < ActiveRecord
        class << self
          # Find AccessGrant from authentication code.
          def from_code(code)
            find_by_code code
          end

          # Create a new access grant.
          def create(identity, client, scope, redirect_uri = nil, expires = nil)
            raise ArgumentError, "Identity must be String or Integer" unless String === identity || Integer === identity
            scope = Utils.normalize_scope(scope) & client.scope # Only allowed scope
            expires_at = Time.now.to_i + (expires || 300)
            fields = { :code=>Server.secure_random, :identity=>identity, :scope=>scope,
                       :client=>client, :redirect_uri=>client.redirect_uri || redirect_uri,
                       :expires_at=>expires_at, :granted_at=>nil,
                       :access_token=>nil, :revoked=>nil }

            super fields
          end

          def collection
            all
          end
        end

        # # Authorization code. We are nothing without it.
        # attr_reader :_id
        # alias :code :_id
        # # The identity we authorized access to.
        # attr_reader :identity
        # # Client that was granted this access token.
        # attr_reader :client_id
        # # Redirect URI for this grant.
        # attr_reader :redirect_uri
        # # The scope requested in this grant.
        # attr_reader :scope
        # # Does what it says on the label.
        # attr_reader :created_at
        # # Tells us when (and if) access token was created.
        # attr_accessor :granted_at
        # # Tells us when this grant expires.
        # attr_accessor :expires_at
        # # Access token created from this grant. Set and spent.
        # attr_accessor :access_token
        # # Timestamp if revoked.
        # attr_accessor :revoked

        # Authorize access and return new access token.
        #
        # Access grant can only be redeemed once, but client can make multiple
        # requests to obtain it, so we need to make sure only first request is
        # successful in returning access token, futher requests raise
        # InvalidGrantError.
        def authorize!(expires_in = nil)
          self.class.transaction do
            raise InvalidGrantError, "You can't use the same access grant twice" if self.access_token || self.revoked
            client = Client.find(client_id) or raise InvalidGrantError
            access_token = AccessToken.get_token_for(identity, client, scope, expires_in)
            self.access_token = access_token.token
            self.granted_at = Time.now.to_i

            save!
            access_token
          end
        end

        def revoke!
          update_attributes! revoked: Time.now.to_i
        end

      end

    end
  end
end
