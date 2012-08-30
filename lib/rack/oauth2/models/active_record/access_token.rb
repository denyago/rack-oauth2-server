module Rack
  module OAuth2
    class Server

      # Access token. This is what clients use to access resources.
      #
      # An access token is a unique code, associated with a client, an identity
      # and scope. It may be revoked, or expire after a certain period.
      class AccessToken < ActiveRecord

        scope :active, lambda { where(revoked: nil) }
        scope :revoked, lambda { where("revoked is not null") }

        validates_uniqueness_of :token

        class << self

          # Find AccessToken from token. Does not return revoked tokens.
          def from_token(token)
            find_by_token token
          end

          # Get an access token (create new one if necessary).
          #
          # You can set optional expiration in seconds. If zero or nil, token
          # never expires.
          def get_token_for(identity, client, scope, expires = nil)
            raise ArgumentError, "Identity must be String or Integer" unless String === identity || Integer === identity
            scope = Utils.normalize_scope(scope) & client.scope # Only allowed scope

            active.where(identity: identity, client_id: client.id, scope: scope.join(",")).where("expires_at is null or expires_at > ?", expires).first ||
                   create_token_for(client, scope, identity, expires)
          end

          # Creates a new AccessToken for the given client and scope.
          def create_token_for(client, scope, identity = nil, expires = nil)
            expires_at = Time.now + expires if expires && expires != 0
            scope = Utils.normalize_scope(scope) & client.scope # Only allowed scope

            attrs = { :token=>Server.secure_random, :scope=>scope,
                      :client_id=>client.id,
                      :expires_at=>expires_at, :revoked=>nil }
            attrs[:identity] = identity if identity

            token = nil

            self.transaction do
              token = create! attrs
              client.increment! :tokens_granted
            end

            token
          end

          # Find all AccessTokens for an identity.
          def from_identity(identity)
            find_by_identity identity
          end

          # Returns all access tokens for a given client, Use limit and offset
          # to return a subset of tokens, sorted by creation date.
          def for_client(client_id, offset = 0, limit = 100)
            if client = Client.find_by_id(client_id)
              client.access_tokens.offset(offset).limit(limit)
            else
              []
            end
          end

          # Returns count of access tokens.
          #
          # @param [Hash] filter Count only a subset of access tokens
          # @option filter [Integer] days Only count that many days (since now)
          # @option filter [Boolean] revoked Only count revoked (true) or non-revoked (false) tokens; count all tokens if nil
          # @option filter [String, ObjectId] client_id Only tokens grant to this client
          def count(filter = {})
            collection = all
            if filter[:days]
              now = Time.now.to_i
              old = now - filter[:days].to_i.days

              collection = collection.where("date between ? and ?", old, now)
            end

            if filter.has_key?(:revoked)
              collection = collection.revoked
            end

            collection = collection.where(client_id: filter[:client_id]) if filter[:client_id]

            collection.count
          end

          def historical(filter = {})
            days = filter[:days] || 60

            collection = where("created_at > ?", Time.now - days.days)
            if filter[:client_id]
              collection = collection.where :client_id => filter[:client_id]
            end
            # FIXME
#            raw = Server::AccessToken.collection.group("function (token) { return { ts: Math.floor(token.created_at / 86400) } }",
#              select, { :granted=>0 }, "function (token, state) { state.granted++ }")
#            raw.sort { |a, b| a["ts"] - b["ts"] }
          end

          def collection
            all
          end
        end

        belongs_to :client

        # # Access token. As unique as they come.
        # attr_reader :_id
        # alias :token :_id
        # # The identity we authorized access to.
        # attr_reader :identity
        # # Client that was granted this access token.
        # attr_reader :client_id
        # # The scope granted to this token.
        # attr_reader :scope
        # # When token was granted.
        # attr_reader :created_at
        # # When token expires for good.
        # attr_reader :expires_at
        # # Timestamp if revoked.
        # attr_accessor :revoked
        # # Timestamp of last access using this token, rounded up to hour.
        # attr_accessor :last_access
        # # Timestamp of previous access using this token, rounded up to hour.
        # attr_accessor :prev_access

        # Updates the last access timestamp.
        def access!
          today = Time.now
          if last_access.nil? || last_access < today
            update_attribute :last_access, today
          end
        end

        # Revokes this access token.
        def revoke!
          self.class.transaction do
            update_attribute :revoked, Time.now
            client.increment! :tokens_revoked
          end
        end

        def scope= scope
          self[:scope] = scope.try :join, ","
        end

        def scope
          self[:scope].split(",")
        end

      end

    end
  end
end
