require "openssl"
require "rack/oauth2/server/errors"
require "rack/oauth2/server/utils"

module Rack
  module OAuth2
    class Server

      class << self
        # Create new instance of the klass and populate its attributes.
        def new_instance(klass, fields)
          raise "No database Configured. You must configure it."
        end

        # Long, random and hexy.
        def secure_random bytes = 32
          OpenSSL::Random.random_bytes(bytes).unpack("H*")[0]
        end
 
        # A ::DB object.
        def database
          raise "No database Configured. You must configure it."
        end
      end
 
    end
  end
end
