require_relative 'lib/teak/attr_encrypted/version'

Gem::Specification.new do |spec|
  spec.name          = "teak-attr_encrypted"
  spec.version       = Teak::AttrEncrypted::VERSION
  spec.authors       = ["Alex Scarborough"]
  spec.email         = ["alex@teak.io"]

  spec.summary       = %q{Encrypts attributes on models using a key encryption key and envelopes.}
  spec.homepage      = "https://github.com/GoCarrot/teak-attr_encrypted"
  spec.required_ruby_version = Gem::Requirement.new(">= 2.5.0")

  spec.license = "Apache-2.0"

  spec.metadata["rubygems_mfa_required"] = "true"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "https://github.com/GoCarrot/teak-attr_encrypted/blob/main/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "msgpack", "~> 1.7"
end
