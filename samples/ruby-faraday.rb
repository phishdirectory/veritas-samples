# frozen_string_literal: true

require 'faraday'
require 'json'
require 'base64'
require 'openssl'
require 'digest'

# VeritasClient - Ruby client for the Veritas auth API using Faraday
class VeritasClient
  attr_reader :api_url, :api_key, :hash_key

  # Initialize the client with your API credentials
  # @param api_url [String] Base URL for the Veritas API
  # @param api_key [String] Your service API key
  # @param hash_key [String] Your service hash key for encrypting data
  def initialize(api_url, api_key, hash_key)
    @api_url = api_url.chomp('/')
    @api_key = api_key
    @hash_key = hash_key
    
    puts "Initializing VeritasClient with API URL: #{@api_url}"
    puts "Note: For production usage, contact a core team member for API credentials."
  end

  # Authenticate a user with email and password
  # @param email [String] User's email
  # @param password [String] User's password
  # @return [Hash] Response with authentication result
  def authenticate(email, password)
    credentials = { email: email, password: password }
    hashed_data = hash_data(credentials)

    response = post('/auth/authenticate', { credentials: hashed_data })
    
    if response['authenticated']
      puts "User authenticated successfully! User ID: #{response['pd_id']}"
    else
      puts "Authentication failed"
    end

    response
  end

  # Get user information by PD_ID
  # @param pd_id [String] User's PD_ID
  # @return [Hash] User information
  def get_user(pd_id)
    get("/users/#{pd_id}")
  end

  # Get user information by email
  # @param email [String] User's email
  # @return [Hash] User information
  def get_user_by_email(email)
    get("/users/by_email?email=#{URI.encode_www_form_component(email)}")
  end

  # Create a new user
  # @param user_data [Hash] User data including first_name, last_name, email, password, password_confirmation
  # @return [Hash] New user information
  def create_user(user_data)
    hashed_data = hash_data(user_data)
    post('/users', { hashed_data: hashed_data })
  end

  private

  # Create a Faraday connection with the base URL and default headers
  # @return [Faraday::Connection] Configured Faraday connection
  def connection
    Faraday.new(url: "#{@api_url}/api/v1") do |faraday|
      faraday.headers['X-Api-Key'] = @api_key
      faraday.headers['Content-Type'] = 'application/json'
      faraday.adapter Faraday.default_adapter
      faraday.ssl.verify = true if @api_url.start_with?('https')
    end
  end

  # Make a GET request to the API
  # @param path [String] API endpoint path
  # @return [Hash] Response data
  def get(path)
    response = connection.get(path)
    parse_response(response)
  end

  # Make a POST request to the API
  # @param path [String] API endpoint path
  # @param data [Hash] Request data
  # @return [Hash] Response data
  def post(path, data)
    response = connection.post(path) do |req|
      req.body = data.to_json
    end
    parse_response(response)
  end

  # Parse the API response
  # @param response [Faraday::Response] The response from the API
  # @return [Hash] Parsed response data
  def parse_response(response)
    return JSON.parse(response.body) if response.success?
    
    # Handle error responses
    begin
      JSON.parse(response.body)
    rescue JSON::ParserError
      { 'error' => "Request failed with status #{response.status}: #{response.body}" }
    end
  end

  # Hash data using the service's hash_key
  # @param data [Hash] Data to encrypt
  # @return [String] Base64 encoded encrypted data
  def hash_data(data)
    # Convert data to JSON string
    json_data = data.to_json

    # Use OpenSSL to encrypt the data with the hash_key
    cipher = OpenSSL::Cipher.new('aes-256-cbc')
    cipher.encrypt

    # Create key and iv from the hash_key
    key = Digest::SHA256.digest(@hash_key)[0...32]
    iv = @hash_key[0...16].ljust(16, '0')

    cipher.key = key
    cipher.iv = iv

    # Encrypt the data
    encrypted = cipher.update(json_data) + cipher.final

    # Encode to base64
    Base64.strict_encode64(encrypted)
  end
end

# Example usage
if __FILE__ == $PROGRAM_NAME
  # Development URL (change to production URL in production environment)
  # Development: http://localhost:3000/api/v1/
  # Production: https://veritas.phish.directory/api/v1/
  # Note: Contact a core team member if you need production keys for authenticating with Veritas
  API_URL = ENV['RAILS_ENV'] == 'production' ? 'https://veritas.phish.directory' : 'http://localhost:3000'
  API_KEY = 'your_api_key_here' # Obtain from core team member for production
  HASH_KEY = 'your_hash_key_here' # Obtain from core team member for production

  client = VeritasClient.new(API_URL, API_KEY, HASH_KEY)

  # Authenticate a user
  # result = client.authenticate('user@example.com', 'password123')
  # puts result

  # Get user by PD_ID
  # user = client.get_user('PDU1A2B3C4')
  # puts user

  # Get user by email
  # user = client.get_user_by_email('user@example.com')
  # puts user

  # Create a new user
  # new_user = client.create_user({
  #   first_name: 'John',
  #   last_name: 'Doe',
  #   email: 'john.doe@example.com',
  #   password: 'SecureP@ssw0rd',
  #   password_confirmation: 'SecureP@ssw0rd'
  # })
  # puts new_user
end
