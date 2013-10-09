require "mongo"

module Rack
  module OAuth2
    class Server

      class << self
        # Create new instance of the klass and populate its attributes.
        def new_instance(klass, fields)
          return unless fields
          instance = klass.new
          fields.each do |name, value|
            instance.instance_variable_set :"@#{name}", value
          end
          instance
        end
        
        # @private
        def create_indexes(&block)
          if block
            @create_indexes ||= []
            @create_indexes << block
          elsif @create_indexes
            @create_indexes.each do |block|
              block.call
            end
            @create_indexes = nil
          end
        end
 
        # A Mongo::DB object.
        def database
          @database ||= Server.options.database
          raise "No database Configured. You must configure it using Server.options.database = Mongo::Connection.new()[db_name]" unless @database
          raise "You set Server.database to #{Server.database.class}, should be a Mongo::DB object" unless Mongo::DB === @database
          @database
        end
      end
 
    end
  end
end


require "rack/oauth2/models/mongodb/client"
require "rack/oauth2/models/mongodb/auth_request"
require "rack/oauth2/models/mongodb/access_grant"
require "rack/oauth2/models/mongodb/access_token"
require "rack/oauth2/models/mongodb/issuer"
