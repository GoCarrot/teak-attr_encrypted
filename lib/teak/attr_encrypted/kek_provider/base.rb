# frozen_string_literal: true

module Teak
  module AttrEncrypted
    module KEKProvider
      class Base
        attr_reader :id

        def initialize(id)
          @id = id
        end
      end
    end
  end
end
