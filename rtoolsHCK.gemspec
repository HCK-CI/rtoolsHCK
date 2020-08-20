# frozen_string_literal: true

require './lib/version'

Gem::Specification.new do |s|
  s.name             = 'rtoolsHCK'
  s.version          = RToolsHCK::VERSION
  s.license          = 'BSD'
  s.required_ruby_version = '>= 2.4.0'

  s.summary          = 'HCK/HLK remote management.'
  s.description      = 'rtoolsHCK: a tool-kit to manage the HCK setup remotely.'

  s.authors          = ['Bishara AbuHatoum', 'Lior Haim', 'Yan Vugenfirer']
  s.email            = 'yvugenfi@redhat.com'
  s.homepage         = 'https://github.com/HCK-CI/rtoolsHCK'

  all_files          = `git ls-files -z`.split("\x0")
  s.files            = all_files.grep(/^(lib)/)
  s.require_paths    = ['lib']

  s.extra_rdoc_files = %w[README.md LICENSE]

  s.add_runtime_dependency('bundler',    '~> 1.16')
  s.add_runtime_dependency('rdoc',       '~> 4.1')
  s.add_runtime_dependency('rubocop',    '~> 0.57')
  s.add_runtime_dependency('winrm',      '~> 2.2')
  s.add_runtime_dependency('winrm-fs',   '~> 1.1')
end
