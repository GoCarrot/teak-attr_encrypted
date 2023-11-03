# frozen_string_literal: true

require 'teak/attr_encrypted/encryptor'
require 'teak/attr_encrypted/kek_provider/aes'
require 'securerandom'

RSpec.describe Teak::AttrEncrypted::Encryptor do
  let(:kek_provider) { Teak::AttrEncrypted::KEKProvider::AES.new(OpenSSL::Cipher.new('aes-256-gcm').encrypt.random_key) }
  let(:encryption_context) { nil }
  let(:plaintext) { SecureRandom.hex }
  subject(:encryptor) { described_class.new(kek_provider) }

  shared_examples_for 'basic functioning' do
    it 'round trips' do
      ciphertext_blob = encryptor.encrypt(plaintext, encryption_context)
      recovered = encryptor.decrypt(ciphertext_blob, encryption_context)
      expect(recovered).to eq plaintext
    end

    it 'prefixes the envelope with the current version' do
      ciphertext_blob = encryptor.encrypt(plaintext, encryption_context)
      expect(ciphertext_blob[0]).to eq described_class::CURRENT_VERSION
    end

    it 'raises if the envelope version is unrecognized' do
      ciphertext_blob = +encryptor.encrypt(plaintext, encryption_context)
      ciphertext_blob[0] = ciphertext_blob[0].succ
      expect { encryptor.decrypt(ciphertext_blob, encryption_context) }.to raise_error(Teak::AttrEncrypted::Error)
    end
  end

  context 'with no encryption_context' do
    include_examples 'basic functioning'
  end

  context 'with an encryption_context' do
    let(:encryption_context) { { foo: 'bar', baz: 'boo' } }

    include_examples 'basic functioning'
  end
end
