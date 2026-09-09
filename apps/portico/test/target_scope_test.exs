defmodule Portico.TargetScopeTest do
  use ExUnit.Case, async: true

  alias Core.Scope.Error
  alias Portico.Scope.Allowlist
  alias Portico.Target

  describe "target parsing" do
    test "normalizes IPv4, IPv6, CIDRs, and hostnames" do
      assert %Target{kind: :ip, value: "192.0.2.1", bits: 32} = Target.parse!("192.0.2.1")
      assert %Target{kind: :ip, value: "2001:db8::1", bits: 128} = Target.parse!("2001:0db8::1")
      assert %Target{kind: :cidr, prefix: 24} = Target.parse!("192.0.2.0/24")

      assert %Target{kind: :hostname, value: "scanner.example"} =
               Target.parse!("Scanner.Example.")
    end

    test "rejects malformed targets" do
      assert {:error, :invalid_prefix} = Target.parse("192.0.2.1/33")
      assert {:error, :invalid_hostname} = Target.parse("not a target!")
    end
  end

  describe "Core scope authorization" do
    test "allows contained hosts and subnets but rejects broader or unrelated targets" do
      policy = Allowlist.new!(["10.0.0.0/8", "2001:db8::/32"])

      assert Core.Scope.authorized?(Target.parse!("10.2.3.4"), policy)
      assert Core.Scope.authorized?(Target.parse!("10.2.0.0/16"), policy)
      assert Core.Scope.authorized?(Target.parse!("2001:db8:2::/48"), policy)
      refute Core.Scope.authorized?(Target.parse!("11.0.0.1"), policy)
      refute Core.Scope.authorized?(Target.parse!("10.0.0.0/7"), policy)

      assert_raise Error, fn ->
        Core.Scope.ensure_authorized!(Target.parse!("11.0.0.1"), policy)
      end
    end

    test "requires explicit hostname authorization" do
      assert {:error, {:hostname_requires_explicit_option, "example.com"}} =
               Allowlist.new(["example.com"])

      policy = Allowlist.new!([], hostnames: ["example.com"])
      assert Core.Scope.authorized?(Target.parse!("example.com"), policy)
    end
  end
end
