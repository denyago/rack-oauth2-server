module Rack
  module OAuth2
    class Server

      class Client
        include DataMapper::Resource

        property :id,             String,   :key => true, :length => 72, :default => proc { Server.secure_random }
        property :secret,         String,   :required => false, :length => 72, :default => proc { Server.secure_random }
        property :display_name,   String
        property :link,           URI
        property :image_url,      URI
        property :redirect_uri,   String
        property :scope,          Json
        property :notes,          Text
        property :created_at,     DateTime, :default => proc { Time.now }
        property :revoked,        DateTime
        property :tokens_granted, Integer,  :default => 0
        property :tokens_revoked, Integer,  :default => 0
        has n, :auth_requests

        class << self
          def find(id)
            get(id)
          end

          def create(args)
            args[:id] ||= Server.secure_random
            args[:secret] ||= Server.secure_random
            args[:scope] = Server::Utils.normalize_scope(args[:scope])
            args[:revoked] = nil
            c = super(args)
            c.save
            c
          end

          def lookup(field)
            c = find(field) || first(:display_name => field) | first(:link => field)
            Server.new_instance(self, c.attributes)
          end

          def all
            super(:order => :display_name).map do |c|
              Server.new_instance self, c.attributes
            end
          end

          def delete(id)
            find(id).destroy
            AuthRequest.all(:client_id => id).destroy
            AccessGrant.all(:client_id => id).destroy
            AccessToken.all(:client_id => id).destroy
          end
        end

        def revoke!
          self.revoked = Time.now
          AuthRequest.all(:client_id => id).update(:revoked => revoked)
          AccessGrant.all(:client_id => id).update(:revoked => revoked)
          AccessToken.all(:client_id => id).update(:revoked => revoked)
        end

        def update(args)
          args[:scope] = Server::Utils.normalize_scope(args[:scope])
          args[:revoked] = nil
          super(args)
          self.class.find(id)
        end
      end

    end
  end
end
