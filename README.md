# Teak::AttrEncrypted

teak-attr_encrypted provides a DSL to transparently encrypt and decrypt attributes on any class, with the primary usecase intended to be with ORM models.

Quickstart:

```ruby
require 'openssl'
require 'teak/attr_encrypted/kek_provider/aes'
# NOTE: The AES provider is only intended for dev and local use. Its security for
# production usage has not been considered or evaluated.
# TODO: Use the same master key on every run ;)
master_key = OpenSSL::Cipher.new('aes-256-gcm').encrypt.random_key
Teak::AttrEncrypted.default_kek_provider = Teak::AttrEncrypted::KEKProvider::AES.new(master_key)

class MyEncryptedClass
    include Teak::AttrEncrypted

    attr_encrypted :sooper_secret

private

    # By default attr_encrypted will read and write ciphertext from
    # "#{attribute_name}_enc". This can be customized with the
    # `ciphertext_attr_name:` keyword argument
    attr_accessor :sooper_secret_enc
end

instance = MyEncryptedClass.new
# Sets instance.sooper_secret_enc to a ciphertext blob
instance.sooper_secret = 'keep it safe'
# Decrypts sooper_secret_enc to its original value
puts instance.sooper_secret
```

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'teak-attr_encrypted'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install teak-attr_encrypted

## Usage

In production the `Teak::AttrEncrypted.default_kek_provider` should be set to an instance of `Teak::AttrEncrypted::KEKProvider::AwsKMS`. The AwsKMS provider will use the given [AWS KMS](https://aws.amazon.com/kms/) key to generate and decrypt data keys for locally applied envelope encryption.

It's highly recommended that you provide a `context:` parameter when using `attr_encrypted`. This may be a symbol, which will attempt to invoke the named method on the object, a proc, which will be evaluated in the context of the object, or another value which will be used as is. The context parameter will be used as [additional authenticated data](https://docs.aws.amazon.com/crypto/latest/userguide/cryptography-concepts.html#term-aad) and must match on both encryption (write) and decryption (read) operations.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/GoCarrot/teak-attr_encrypted.
