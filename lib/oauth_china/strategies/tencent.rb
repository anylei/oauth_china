module OauthChina
  class Tencent < OauthChina::OAuth
    attr_accessor :code, :expires_at, :uid
    alias :oauth_consumer_key :key
    alias :openid :uid

    class MissingArgumentError < ::StandardError; end
    def initialize(*args)
      self.consumer_options = {
        :site               => 'https://graph.qq.com/oauth2.0/',
        :access_token_path  => '/oauth2.0/token',
        :authorize_path     => '/oauth2.0/authorize'
      }

      # super(*args)
      if args[0]
        self.code = args[0]
      else
      end
    end

    def name
      :tencent
    end

    def authorized?
      #TODO
      ! self.access_token.nil?
    end

    def authorize(options = {})
      return unless self.code
      self.access_token ||= consumer.auth_code.get_token self.code, :redirect_uri => self.callback, :parse => :query
    end

    def authorize_url
      @authorize_url ||= consumer.auth_code.authorize_url(:redirect_uri => self.callback)
    end

    def request_hash
      {
        'access_token' =>  self.access_token.token.to_s,
        'oauth_consumer_key' => self.oauth_consumer_key,
        'openid' => self.openid,
        'format' => 'json'
      }
    end

    def get url, params={}
      params = params.merge request_hash
      response = self.access_token.get(url, :params => params)
      response.body =~ /(\{.*\})/
      JSON.parse $1 || response.body
    end

    def post url, params={}
      params = request_hash.merge params
      req_data = ''
      params.each do |k, v|
        req_data += "#{k}=#{v}&"
      end
      req_data = URI.escape req_data[0..-2]

      response = self.access_token.post(url, :body => req_data)
      response.body =~ /(\{.*\})/
      JSON.parse $1 || response.body
    end

    def get_uid
      @uid ||= get("https://graph.qq.com/oauth2.0/me?access_token=#{self.access_token.token.to_s}")['openid']
    end

    def consumer
      @consumer ||= OAuth2::Client.new(key, 
                                       secret,
                                       :site => consumer_options[:site], 
                                       :authorize_url => consumer_options[:authorize_path],
                                       :token_url => consumer_options[:access_token_path])
    end

    def get_user_info user_url, openid
      self.get(user_url,{:openid => uid})
    end

    def add_status params={}
      unless params[:title] && params[:url] && params[:site] && params[:fromurl]
        raise MissingArgumentError, "title, url, site, fromurl should not be null"
      end
      self.post('https://graph.qq.com/share/add_share', params.stringify_keys)
    end

    def self.load data
      client =  self.new
      oauth_token = OAuth2::AccessToken.new client.consumer, data[:access_token], {'expires_at'=> data[:expires_at]}
      client.access_token = oauth_token
      client.uid = data[:openid]
      client
    end

    def dump
      {
        :access_token => access_token.nil? ? nil : access_token.token,
        :expires_at => access_token.nil? ? nil : access_token.expires_at,
      }
    end
  end
end
