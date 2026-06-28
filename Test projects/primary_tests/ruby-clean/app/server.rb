#!/usr/bin/env ruby
# frozen_string_literal: true

require 'webrick'
require 'json'
require 'sqlite3'

db = SQLite3::Database.new(ENV['DB_PATH'] || 'ghazaldb.db')

def get_user(db, params)
  id = params['id']
  stmt = db.prepare("SELECT * FROM users WHERE id = ?")
  stmt.bind_params(id)
  result = stmt.execute
  result.first
end

server = WEBrick::HTTPServer.new(Port: 8080)

server.mount_proc '/api/user' do |req, res|
  res['Content-Type'] = 'application/json'
  res.body = get_user(db, req.query).to_json
end

trap('INT') { server.shutdown }
server.start
