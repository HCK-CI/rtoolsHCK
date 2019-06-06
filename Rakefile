# frozen_string_literal: true

require './lib/version'
require 'bundler/gem_tasks'

require 'rdoc/task'
Rake::RDocTask.new do |rdoc|
  rdoc.rdoc_dir = 'rdoc'
  rdoc.title = 'rtoolsHCK RToolsHCK::VERSION'
  rdoc.rdoc_files.include('README.md')
  rdoc.rdoc_files.include('lib/rtoolsHCK.rb')
end

require 'rubocop/rake_task'
RuboCop::RakeTask.new
