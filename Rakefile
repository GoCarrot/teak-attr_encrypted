require "bundler/gem_tasks"
require "rspec/core/rake_task"

begin
  require 'teak/dev/tasks'
  Teak::Dev::Tasks.install(service: 'teak-attr_encrypted')
rescue LoadError
end

RSpec::Core::RakeTask.new(:spec)

task :default => :spec
