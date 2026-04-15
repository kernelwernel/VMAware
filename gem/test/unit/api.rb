require 'minitest/autorun'
require 'vmaware-rb'

module VMAware
  class ApiTest < Minitest::Test

    def test_has_vm_class
      assert defined?(VMAware)
      assert defined?(VMAware::VM)
    end

    def test_responds_to_check
      assert_respond_to VMAware::VM, :vm?
    end

    def test_responds_to_confidence
      assert_respond_to VMAware::VM, :confidence
    end
  end
end
