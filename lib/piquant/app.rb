module Piquant
  # sinatra app
  class App < Sinatra::Base
    # secret for cipher
    SECRET = ENV.fetch('PIQUANT_SECRET')

    # sqlite database
    DB = Sequel.sqlite(ENV.fetch('PIQUANT_DATABASE'))

    # create users table
    DB.create_table? :users do
      String :id, primary_key: true

      String :name
      String :password

      String :token
    end

    # create bookmarks table
    DB.create_table? :bookmarks do
      String :id, primary_key: true
      String :user

      String :url
      String :title
    end

    # create tags table
    DB.create_table? :tags do
      String :tag
      String :user
      String :bookmark
    end

    # set content type
    set :default_content_type, :json

    # cross origin resource sharing
    before do
      headers['Access-Control-Allow-Origin']  = '*'
      headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
    end

    # options for all routes
    options '*' do
      response.headers['Allow'] = 'HEAD, GET, POST, PUT, PATCH, DELETE, OPTIONS'
      response.headers['Access-Control-Allow-Headers'] =
        'X-Requested-With, X-HTTP-Method-Override, Content-Type, Cache-Control, Accept, Authorization'
    end

    # encrypt string
    def encrypt(string)
      # create cipher
      cipher = OpenSSL::Cipher.new('aes-128-ecb')

      cipher.encrypt
      cipher.key = SECRET

      # update cipher and convert to hex
      encrypted = cipher.update(string) + cipher.final
      encrypted.unpack1('H*')
    end

    helpers do
      # halt with message
      def message_halt(message, code = 400)
        halt code, { message: }.to_json
      end

      # authorize user
      def authorize_user
        message_halt 'token not present', 401 \
          unless request.env['HTTP_AUTHORIZATION']

        # slice header
        token = request.env['HTTP_AUTHORIZATION']
        token.slice!('Bearer ')

        # get user
        user_id =
          DB[:users]
          .select(:id)
          .where(token:)
          .first

        message_halt 'token is invalid', 401 unless user_id
        user_id[:id]
      end
    end

    # not found page
    not_found do
      message_halt 'route cannot be found', 404
    end

    # get token for user
    post '/auth/:username' do |username|
      data = JSON.parse(request.body.read)
      message_halt 'password is invalid' unless data['password'].is_a?(String)

      # get user
      user =
        DB[:users]
        .select(:password, :token)
        .where(name: username).first

      message_halt 'password is incorrect' if encrypt(data['password']) != user[:password]

      # return token
      { token: user[:token] }.to_json
    end

    # generate new token for user
    put '/token' do
      user_id    = authorize_user
      user_token = SecureRandom.hex

      # insert user
      DB[:users]
        .where(id: user_id)
        .update(token: user_token)

      { token: user_token }.to_json
    end

    # create new user
    post '/user/:username' do |username|
      user = JSON.parse(request.body.read)
      user_token = SecureRandom.hex

      message_halt 'user with given username exists' unless DB[:users].where(name: user['name']).empty?
      message_halt 'password is invalid' unless user['password'].is_a?(String)

      # insert user
      DB[:users].insert(
        SecureRandom.hex,
        username,
        encrypt(user['password']),
        user_token
      )

      { token: user_token }.to_json
    end

    # get all bookmarks
    get '/bookmarks' do
      user_id = authorize_user

      # get bookmarks
      bookmarks =
        DB[:bookmarks]
        .select(:id, :url, :title)
        .where(user: user_id)
        .all

      # get bookmark tags
      bookmarks.map! do |bookmark|
        bookmark[:tags] =
          DB[:tags]
          .select(:tag)
          .where(user: user_id, bookmark: bookmark[:id])
          .all
          .map { |t| t[:tag] }

        bookmark
      end

      { bookmarks: }.to_json
    end

    # get bookmarks with tag
    get '/bookmarks/tag/:tag' do |tag|
      user_id = authorize_user

      bookmark_ids =
        DB[:tags]
        .select(:bookmark)
        .where(tag:)
        .all
        .map { |t| t[:bookmark] }

      # get bookmarks
      bookmarks = bookmark_ids.map do |bookmark_id|
        DB[:bookmarks]
          .select(:id, :url, :title)
          .where(id: bookmark_id, user: user_id)
          .first
      end

      # get bookmark tags
      bookmarks.map! do |bookmark|
        bookmark[:tags] =
          DB[:tags]
          .select(:tag)
          .where(user: user_id, bookmark: bookmark[:id])
          .all
          .map { |t| t[:tag] }

        bookmark
      end

      { bookmarks: }.to_json
    end

    # create new bookmark
    post '/bookmark' do
      user_id = authorize_user

      bookmark    = JSON.parse(request.body.read)
      bookmark_id = SecureRandom.hex

      message_halt 'bookmark details are invalid' unless \
        bookmark['url'].is_a?(String) &&
        bookmark['title'].is_a?(String) &&
        bookmark['tags'].is_a?(Array)

      # insert bookmark
      DB[:bookmarks].insert(
        bookmark_id,
        user_id,
        bookmark['url'],
        bookmark['title']
      )

      # insert bookmark tags
      bookmark['tags']&.each do |tag|
        DB[:tags].insert(
          tag,
          user_id,
          bookmark_id
        )
      end

      { id: bookmark_id }.to_json
    end

    # update bookmark
    patch '/bookmark/:bookmark_id' do |bookmark_id|
      user_id  = authorize_user
      bookmark = JSON.parse(request.body.read)

      message_halt 'bookmark details are invalid' unless \
        bookmark['url'].is_a?(String) &&
        bookmark['title'].is_a?(String)

      # update bookmark
      DB[:bookmarks]
        .where(id: bookmark_id, user: user_id)
        .update(url: bookmark['url'], title: bookmark['title'])

      if bookmark['tags'].is_a?(Array)
        # delete old bookmark tags
        DB[:tags]
          .where(user: user_id, bookmark: bookmark_id)
          .delete

        # insert new bookmark tags
        bookmark['tags']&.each do |tag|
          DB[:tags].insert(
            tag,
            user_id,
            bookmark_id
          )
        end
      end

      { id: bookmark_id }.to_json
    end

    # delete bookmark
    delete '/bookmark/:bookmark_id' do |bookmark_id|
      user_id = authorize_user

      # remove bookmark
      DB[:bookmarks]
        .where(id: bookmark_id, user: user_id)
        .delete

      # remove bookmark tags
      DB[:tags]
        .where(user: user_id, bookmark: bookmark_id)
        .delete

      { id: bookmark_id }.to_json
    end
  end
end
