module Rack
  module OAuth2
    class Server

      class Client < ActiveRecord

        # Returns all the clients in the database, sorted alphabetically.
#        default_scope order(:display_name)

        validates_uniqueness_of :client_id

        class << self

          # Create a new client. Client provides the following properties:
          # # :display_name -- Name to show (e.g. UberClient)
          # # :link -- Link to client Web site (e.g. http://uberclient.dot)
          # # :image_url -- URL of image to show alongside display name
          # # :redirect_uri -- Registered redirect URI.
          # # :scope -- List of names the client is allowed to request.
          # # :notes -- Free form text.
          #
          # This method does not validate any of these fields, in fact, you're
          # not required to set them, use them, or use them as suggested. Using
          # them as suggested would result in better user experience.  Don't ask
          # how we learned that.
          def create(args)
            redirect_uri = Server::Utils.parse_redirect_uri(args[:redirect_uri]).to_s if args[:redirect_uri]
            scope = Server::Utils.normalize_scope(args[:scope])
            fields =  { :display_name=>args[:display_name], :link=>args[:link],
                        :image_url=>args[:image_url], :redirect_uri=>redirect_uri,
                        :notes=>args[:notes].to_s, :scope=>scope,
                        :revoked=>nil }

            fields[:secret] = Server.secure_random
            fields[:client_id] = Server.secure_random 4

            create! fields
          end

          # Lookup client by ID, display name or URL.
          def lookup(field)
            find_by_id(field) || find_by_display_name(field) || find_by_link(field)
          end

          # Deletes client with given identifier (also, all related records).
          def delete(client_id)
            find_by_id(client_id).try(:destroy)
          end

          def collection
            all
          end
        end

        has_many :auth_requests, :dependent => :destroy
        has_many :access_grants, :dependent => :destroy
        has_many :access_tokens, :dependent => :destroy

        # Client identifier.
        # attr_reader :_id
        # alias :id :_id
        # # Client secret: random, long, and hexy.
        # attr_reader :secret
        # # User see this.
        # attr_reader :display_name
        # # Link to client's Web site.
        # attr_reader :link
        # # Preferred image URL for this icon.
        # attr_reader :image_url
        # # Redirect URL. Supplied by the client if they want to restrict redirect
        # # URLs (better security).
        # attr_reader :redirect_uri
        # # List of scope the client is allowed to request.
        # attr_reader :scope
        # # Free form fields for internal use.
        # attr_reader :notes
        # # Does what it says on the label.
        # attr_reader :created_at
        # # Timestamp if revoked.
        # attr_accessor :revoked
        # # Counts how many access tokens were granted.
        # attr_reader :tokens_granted
        # # Counts how many access tokens were revoked.
        # attr_reader :tokens_revoked

        # Revoke all authorization requests, access grants and access tokens for
        # this client. Ward off the evil.
        def revoke!
          self.class.transaction do
            attribs = { revoked: Time.now }
            update_attributes! attribs

            revoke_l = lambda { |o| o.update_attributes attribs }

            auth_requests.each &revoke_l
            access_grants.each(&:revoke!)
            access_tokens.each &revoke_l
          end
        end

        # def update(args)
        #   fields = [:display_name, :link, :image_url, :notes].inject({}) { |h,k| v = args[k]; h[k] = v if v; h }
        #   fields[:redirect_uri] = Server::Utils.parse_redirect_uri(args[:redirect_uri]).to_s if args[:redirect_uri]
        #   fields[:scope] = Server::Utils.normalize_scope(args[:scope])

        #   update_attributes! fields
        # end

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
