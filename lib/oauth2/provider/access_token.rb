module OAuth2
  class Provider
    
    class AccessToken
      attr_reader :authorization,
                  :error, :error_description
      
      def initialize(resource_owner = nil, scopes = [], access_token = nil, error = nil)
        @resource_owner = resource_owner
        @scopes         = scopes
        @access_token   = access_token
        @error          = error && INVALID_REQUEST
        
        authorize!(access_token, error)
        validate!
      end
      
      def client
        valid? ? @authorization.client : nil
      end
      
      def owner
        valid? ? @authorization.owner : nil
      end
      
      def response_body
        return nil if @authorization and valid?
        JSON.unparse(
          ERROR             => @error,
          ERROR_DESCRIPTION => @error_description)
      end
      
      def response_headers
        return {} if valid?
        error_message =  "OAuth realm='#{ Provider.realm }'"
        error_message << ", error='#{ @error }'" unless @error == ''
        {'WWW-Authenticate' => error_message}
      end
      
      def response_status
        case @error
          when INVALID_REQUEST, INVALID_TOKEN, EXPIRED_TOKEN then 401
          when INSUFFICIENT_SCOPE                            then 403
          when ''                                            then 401
                                                             else 200
        end
      end
      
      def valid?
        @error.nil?
      end
      
    private
      
      def authorize!(access_token, error)
        return unless @authorization = Model.find_access_token(access_token)
        @authorization.update_attribute(:access_token, nil) if error
      end
      
      def validate!
        unless @access_token and @authorization
          @error = INVALID_TOKEN
          @error_description = 'Invalid access token'
          return
        end
        
        if @authorization.expired?
          @error = EXPIRED_TOKEN
          @error_description = 'Expired access token'
        end
        
        if !@authorization.in_scope?(@scopes) or
           (@resource_owner and @authorization.owner != @resource_owner)
          @error = INSUFFICIENT_SCOPE
          @error_description = 'Insufficient scope for resource'
        end
      end
    end
    
  end
end

