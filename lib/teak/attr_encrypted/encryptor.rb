# frozen_string_literal: true

require 'openssl'
require 'msgpack'
require 'base64'

module Teak
  module AttrEncrypted
    class Encryptor
      KEY_SPEC = 'AES_256'
      CIPHER = 'aes-256-gcm'

      def initialize(kek_provider)
        @kek_provider = kek_provider
      end

      def encrypt(plaintext, encryption_context)
        key_info = @kek_provider.request_data_key(encryption_context)

        cipher = OpenSSL::Cipher.new(CIPHER).encrypt
        cipher.key = key_info.plaintext
        iv = cipher.random_iv
        cipher.auth_data = ''

        encrypted = cipher.update(plaintext) + cipher.final
        Base64.strict_encode64(
          MessagePack.pack({iv: iv, tag: cipher.auth_tag, key: key_info.ciphertext_blob, packet: encrypted})
        )
      end

      def decrypt(envelope, encryption_context)
        structure = MessagePack.unpack(Base64.strict_decode64(envelope))
        key_info = @kek_provider.decrypt_data_key(structure['key'], encryption_context)

        cipher = OpenSSL::Cipher.new(CIPHER).decrypt
        cipher.key = key_info.plaintext
        cipher.iv = structure['iv']
        cipher.auth_tag = structure['tag']
        cipher.auth_data = ''

        cipher.update(structure['packet']) + cipher.final
      end
    end
  end
end
