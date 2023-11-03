# frozen_string_literal: true

require 'openssl'
require 'msgpack'
require 'base64'

module Teak
  module AttrEncrypted
    class Encryptor
      KEY_SPEC = 'AES_256'
      CIPHER = 'aes-256-gcm'

      CURRENT_VERSION = '1'

      IV = 'v'
      TAG = 't'
      KEY = 'k'
      PACKET = 'p'
      KEK_ID = 'i'

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
        "#{CURRENT_VERSION}#{Base64.strict_encode64(
          MessagePack.pack({
            IV => iv,
            TAG => cipher.auth_tag,
            KEY => key_info.ciphertext_blob,
            PACKET => encrypted
          })
        )}"
      end

      def decrypt(envelope, encryption_context)
        version = envelope[0]
        case version
        when '1'
          structure = MessagePack.unpack(Base64.strict_decode64(envelope[1..-1]))
          key_info = @kek_provider.decrypt_data_key(structure[KEY], encryption_context)

          cipher = OpenSSL::Cipher.new(CIPHER).decrypt
          cipher.key = key_info.plaintext
          cipher.iv = structure[IV]
          cipher.auth_tag = structure[TAG]
          cipher.auth_data = ''

          cipher.update(structure[PACKET]) + cipher.final
        else
          raise Teak::AttrEncrypted::Error.new("Unrecognized envelope version #{version}")
        end
      end
    end
  end
end
