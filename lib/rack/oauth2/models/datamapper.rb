require 'data_mapper'

module Rack
  module OAuth2
    class Server

      class << self
        # Create new instance of the klass and populate its attributes.
        def new_instance(klass, fields)
          instance = klass.new fields
        end
      end

    end
  end
end

require "rack/oauth2/models/datamapper/client"
require "rack/oauth2/models/datamapper/auth_request"
require "rack/oauth2/models/datamapper/access_grant"
require "rack/oauth2/models/datamapper/access_token"
require "rack/oauth2/models/datamapper/issuer"
