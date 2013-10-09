module Rack
  module OAuth2
    class Server

      # Authorization request. Represents request on behalf of client to access
      # particular scope. Use this to keep state from incoming authorization
      # request to grant/deny redirect.
      class AuthRequest
        include DataMapper::Resource

        class << self
          # Find AuthRequest from identifier.
          def find(request_id)
            get(request_id)
          end

          # Create a new authorization request. This holds state, so in addition
          # to client ID and scope, we need to know the URL to redirect back to
          # and any state value to pass back in that redirect.
          def create(client, scope, redirect_uri, response_type, state)
            scope = Utils.normalize_scope(scope) & client.scope # Only allowed scope
            fields = { :client => client, :scope=>scope,
                       :redirect_uri=>client.redirect_uri || redirect_uri,
                       :response_type=>response_type, :state=>state,
                       :grant_code=>nil, :authorized_at=>nil,
                       :revoked=>nil }
            c = super(fields)
            c.save
            c
          end
        end

        property :id,            Serial
        property :scope,         Json
        property :redirect_uri,  URI
        property :state,         String
        property :created_at,    DateTime, :default => proc { Time.now }
        property :response_type, String
        property :grant_code,    String
        property :authorized_at, DateTime
        property :revoked,       DateTime
        belongs_to :client

        # Grant access to the specified identity.
        def grant!(identity, expires_in = nil)
          raise ArgumentError, "Must supply a identity" unless identity
          return if revoked
          client = Client.find(client_id) or return
          self.authorized_at = Time.now.to_i
          if response_type == "code" # Requested authorization code
            access_grant = AccessGrant.create(identity, client, scope, redirect_uri)
            self.grant_code = access_grant.code
            self.authorized_at = authorized_at
            self.save
          else # Requested access token
            access_token = AccessToken.get_token_for(identity, client, scope, expires_in)
            self.access_token = access_token.token
            self.authorized_at = authorized_at
            self.save
          end
          true
        end

        # Deny access.
        def deny!
          self.authorized_at = Time.now.to_i
          self.save
        end
      end

    end
  end
end
