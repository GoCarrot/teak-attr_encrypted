# frozen_string_literal: true

require 'teak/attr_encrypted/kek_provider/base'

require 'openssl'
require 'msgpack'

module Teak
  module AttrEncrypted
    module KEKProvider
      # Provides a random key encrypted with a given aes-256-gcm key
      # NOTE: This uses a random iv and is only considered secure for
      # 2**32 invocations of request_data_key.
      class AES < Base
        Decrypted = Struct.new(:plaintext)
        KeyInfo = Struct.new(:plaintext, :ciphertext_blob)

        CIPHER = 'aes-256-gcm'

        def initialize(key)
          super(OpenSSL::Digest::SHA256.hexdigest(key))
          @key = key
        end

        def request_data_key(encryption_context)
          data_key = OpenSSL::Cipher.new(CIPHER).encrypt.random_key
          cipher = OpenSSL::Cipher.new(CIPHER).encrypt
          cipher.key = @key
          iv = cipher.random_iv
          cipher.auth_data =
            if encryption_context
              MessagePack.pack(encryption_context)
            else
              ''
            end
          ciphertext = cipher.update(data_key) + cipher.final
          ciphertext_blob = MessagePack.pack({'iv' => iv, 'tag' => cipher.auth_tag, 'key' => ciphertext})

          KeyInfo.new(data_key, ciphertext_blob)
        end

        def decrypt_data_key(ciphertext_blob, encryption_context)
          data = MessagePack.unpack(ciphertext_blob)
          cipher = OpenSSL::Cipher.new(CIPHER).decrypt
          cipher.key = @key
          cipher.iv = data['iv']
          cipher.auth_tag = data['tag']
          cipher.auth_data =
            if encryption_context
              MessagePack.pack(encryption_context)
            else
              ''
            end

          data_key = cipher.update(data['key']) + cipher.final
          Decrypted.new(data_key)
        end
      end
    end
  end
end
