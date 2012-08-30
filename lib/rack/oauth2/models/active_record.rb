module Rack
  module OAuth2
    class Server

      class ActiveRecord < ::ActiveRecord::Base
        TABLE_PREFIX = "oauth2_provider_"

        def self.table_name
          TABLE_PREFIX + name.split("::").last.underscore
        end
      end

      class << self
        # Create new instance of the klass and populate its attributes.
        def new_instance(klass, fields)
          instance = klass.new fields
        end
      end
      class CreateRackOauth2ServerSchema < ::ActiveRecord::Migration
        def change

          create_table "#{ActiveRecord::TABLE_PREFIX}client" do |t|
            # Client identifier.
            t.string :client_id
            # Client secret: random, long, and hexy.
            t.string :secret
            # User see this.
            t.string :display_name
            # Link to client's Web site.
            t.string :link
            # Preferred image URL for this icon.
            t.string :image_url
            # Redirect URL. Supplied by the client if they want to restrict redirect URLs (better security).
            t.string :redirect_uri
            # List of scope the client is allowed to request.
            t.string :scope
            # Free form fields for internal use.
            t.string :notes
            # Timestamp if revoked.
            t.datetime :revoked
            # Counts how many access tokens were granted.
            t.integer :tokens_granted
            # Counts how many access tokens were revoked.
            t. integer :tokens_revoked

            t.timestamps
          end
          change_table "#{ActiveRecord::TABLE_PREFIX}client" do |t|
            t.index :client_id
            t.index [:client_id, :secret]
          end
        end
      end
    end
  end
end


require "rack/oauth2/models/active_record/client"
require "rack/oauth2/models/active_record/auth_request"
require "rack/oauth2/models/active_record/access_grant"
require "rack/oauth2/models/active_record/access_token"
require "rack/oauth2/models/active_record/issuer"
