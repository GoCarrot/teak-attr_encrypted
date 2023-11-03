# frozen_string_literal: true

require 'teak/attr_encrypted/kek_provider/aes'

RSpec.describe Teak::AttrEncrypted::KEKProvider::AES do
  let(:key) { OpenSSL::Cipher.new('aes-256-gcm').encrypt.random_key }
  let(:encryption_context) { nil }
  subject(:kek_provider) { described_class.new(key) }

  it 'sets the same kek id for the same key' do
    alt_provider = described_class.new(key)
    expect(kek_provider.id).to eq alt_provider.id
  end

  it 'sets different kek ids for different keys' do
    alt_provider = described_class.new(OpenSSL::Cipher.new('aes-256-gcm').encrypt.random_key)
    expect(kek_provider.id).not_to eq alt_provider.id
  end

  shared_examples_for 'basic functioning' do
    it 'returns a structure with plaintext and ciphertext_blob attributes' do
      expect(kek_provider.request_data_key(encryption_context)).to have_attributes(
        plaintext: anything,
        ciphertext_blob: anything
      )
    end

    it 'round trips' do
      key_info = kek_provider.request_data_key(encryption_context)
      decrypted_info = kek_provider.decrypt_data_key(key_info.ciphertext_blob, encryption_context)
      expect(key_info.plaintext).to eq decrypted_info.plaintext
    end
  end

  context 'with no encryption_context' do
    include_examples 'basic functioning'
  end

  context 'with an encryption_context' do
    let(:encryption_context) { { foo: 'bar', baz: 'boo' } }

    include_examples 'basic functioning'
  end

  context 'with a mismatched encryption_context' do
    it 'raises an error' do
      key_info = kek_provider.request_data_key(encryption_context)
      expect do
        kek_provider.decrypt_data_key(key_info.ciphertext_blob, { something: 'different' })
      end.to raise_error(OpenSSL::Cipher::CipherError)
    end
  end

  context 'with a munged ciphertext_blob' do
    it 'raises an error' do
      key_info = kek_provider.request_data_key(encryption_context)
      expect do
        kek_provider.decrypt_data_key(key_info.ciphertext_blob.succ, encryption_context)
      end.to raise_error(OpenSSL::Cipher::CipherError)
    end
  end
end
