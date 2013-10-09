module Rack
  module OAuth2
    class Server
      # A third party that issues assertions
      # http://tools.ietf.org/html/draft-ietf-oauth-assertions-01#section-5.1
      class Issuer
        include DataMapper::Resource

        class << self

          # returns the Issuer object for the given identifier
          def from_identifier(identifier)
            Server.new_instance self, collection.find_one({:_id=>identifier})
          end

          # Create a new Issuer.
          def create(args)
            fields = {}
            [:hmac_secret, :public_key, :notes].each do |key|
              fields[key] = args[key] if args.has_key?(key)
            end
            fields[:created_at] = Time.now.to_i
            fields[:updated_at] = Time.now.to_i
            fields[:_id] = args[:identifier]
            c = super(fields)
            c.save
            c
          end
        end

        property :identifier,  Text, :key => true
        property :hmac_secret, Text
        property :public_key,  Text
        property :notes,       Text

        def update(args)
          fields = [:hmac_secret, :public_key, :notes].inject({}) {|h,k| v = args[k]; h[k] = v if v; h}
          self.class.collection.update({:_id => identifier }, {:$set => fields})
          self.class.from_identifier(identifier)
        end
      end
    end
  end
end
