require 'minitest/autorun'
require 'vmaware-rb'

raise "vmaware-rb gem failed to load VMAware module" unless defined?(VMAware)
raise "vmaware-rb gem failed to load VMAware::VM class" unless defined?(VMAware::VM)

class ApiTest < Minitest::Test

  def test_responds_to_check
    assert_respond_to VMAware::VM, :vm?
  end

  def test_responds_to_confidence
    assert_respond_to VMAware::VM, :confidence
  end

  def test_vm_check_returns_boolean
    result = VMAware::VM.vm?
    assert_includes [true, false], result, "vm? must return true or false, got #{result.inspect}"
  end

  def test_confidence_returns_integer_in_range
    result = VMAware::VM.confidence
    assert_kind_of Integer, result, "confidence must return an Integer, got #{result.class}"
    assert_operator result, :>=, 0, "confidence must be >= 0"
    assert_operator result, :<=, 100, "confidence must be <= 100"
  end

end
