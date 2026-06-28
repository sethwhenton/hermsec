#!/usr/bin/env ruby
# frozen_string_literal: true

require 'webrick'
require 'json'
require 'sqlite3'
require 'yaml'

# VULN 1: Hardcoded database credentials (CWE-798)
DB_CONFIG = {
  host: 'localhost',
  username: 'admin',
  password: 'ghazal_ruby_db_pass!@#',
  database: 'ghazaldb'
}.freeze

# VULN 2: Hardcoded API key (CWE-798)
API_KEY = 'ghazal-ruby-api-key-rk-1234567890abcdef'

db = SQLite3::Database.new('ghazaldb.db')

# VULN 3: SQL Injection via string interpolation (CWE-89)
def get_user(db, params)
  id = params['id']
  result = db.execute("SELECT * FROM users WHERE id = '#{id}'")
  result.first
end

# VULN 4: SQL Injection via concatenation (CWE-89)
def search_users(db, params)
  name = params['name']
  result = db.execute("SELECT * FROM users WHERE name LIKE '%" + name + "%'")
  result
end

# VULN 5: Command Injection via backticks (CWE-78)
def ping_host(params)
  host = params['host']
  output = `ping -c 4 #{host}`
  output
end

# VULN 6: Command Injection via system (CWE-78)
def run_command(params)
  cmd = params['command']
  system(cmd)
end

# VULN 7: Command Injection via exec (CWE-78)
def exec_command(params)
  cmd = params['cmd']
  output = []
  exec(cmd) { |line| output << line }
  output.join
end

# VULN 8: Path Traversal (CWE-22)
def read_file(params)
  filename = params['name']
  filepath = "data/#{filename}"
  File.read(filepath)
rescue Errno::ENOENT
  'File not found'
end

# VULN 9: Path Traversal via require (CWE-22)
def load_module(params)
  module_name = params['module']
  require "modules/#{module_name}"
end

# VULN 10: XSS via string interpolation (CWE-79)
def search_page(params)
  query = params['q']
  "<html><body><h1>Search: #{query}</h1></body></html>"
end

# VULN 11: Unsafe YAML deserialization (CWE-502)
def load_yaml(params)
  data = params['data']
  YAML.load(data)
end

# VULN 12: Information exposure (CWE-209)
def handle_error
  begin
    raise 'Something went wrong'
  rescue => e
    "Error: #{e.message}\n#{e.backtrace.join("\n")}"
  end
end

server = WEBrick::HTTPServer.new(Port: 8080)

server.mount_proc '/api/user' do |req, res|
  res['Content-Type'] = 'application/json'
  res.body = get_user(db, req.query).to_json
end

server.mount_proc '/api/search' do |req, res|
  res['Content-Type'] = 'application/json'
  res.body = search_users(db, req.query).to_json
end

server.mount_proc '/api/ping' do |req, res|
  res.body = ping_host(req.query)
end

server.mount_proc '/api/run' do |req, res|
  run_command(req.query)
  res.body = 'Command executed'
end

server.mount_proc '/api/exec' do |req, res|
  res.body = exec_command(req.query)
end

server.mount_proc '/api/file' do |req, res|
  res.body = read_file(req.query)
end

server.mount_proc '/api/module' do |req, res|
  load_module(req.query)
  res.body = 'Module loaded'
end

server.mount_proc '/api/search-page' do |req, res|
  res['Content-Type'] = 'text/html'
  res.body = search_page(req.query)
end

server.mount_proc '/api/yaml' do |req, res|
  res['Content-Type'] = 'application/json'
  res.body = load_yaml(req.query).to_json
end

server.mount_proc '/api/error' do |req, res|
  res.body = handle_error
end

trap('INT') { server.shutdown }
server.start
