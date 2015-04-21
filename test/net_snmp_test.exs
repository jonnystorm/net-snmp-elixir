# Copyright © 2015 Jonathan Storm <the.jonathan.storm@gmail.com>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING.WTFPL file for more details.

defmodule NetSNMPTest do
  use ExUnit.Case, async: true

  test "agent returns correct Agent" do
    assert NetSNMP.agent("192.0.2.1", :udp, 161)
      == %NetSNMP.Agent{host: "192.0.2.1", ip_proto: :udp, port: 161}
  end
  test "agent fails for invalid protocol" do
    assert_raise FunctionClauseError, fn ->
      NetSNMP.agent("192.0.2.1", :blarg, 161)
    end
  end

  test "credential returns correct keyword list for SNMPv2c" do
    assert NetSNMP.credential(:v2c, "ancommunity") ==
      [version: "2c", community: "ancommunity"]
  end
  test "credential returns correct keyword list for SNMPv3, noAuthNoPriv" do
    assert NetSNMP.credential(:v3, :no_auth_no_priv, "anname") ==
      [version: "3", sec_level: "noAuthNoPriv", sec_name: "anname"]
  end
  test "credential returns correct keyword list for SNMPv3, authNoPriv" do
    assert NetSNMP.credential(:v3, :auth_no_priv, "anname", :md5, "anpass") ==
      [
        version: "3",
        sec_level: "authNoPriv",
        sec_name: "anname",
        auth_proto: "md5",
        auth_pass: "anpass"
      ]
  end
  test "credential returns correct keyword list for SNMPv3, authPriv" do
    assert NetSNMP.credential(:v3, :auth_priv, "anname", :sha, "anpass", :des, "anpass2") ==
      [
        version: "3",
        sec_level: "authPriv",
        sec_name: "anname",
        auth_proto: "sha",
        auth_pass: "anpass",
        priv_proto: "des",
        priv_pass: "anpass2"
      ]
  end
  test "credential fails for invalid security level" do
    assert_raise FunctionClauseError, fn ->
      NetSNMP.credential(:v3, :blarg, "anname", :sha, "anpass", :des, "anpass2")
    end
  end
  test "credential fails for invalid authentication protocol" do
    assert_raise FunctionClauseError, fn ->
      NetSNMP.credential(:v3, :auth_priv, "anname", :blarg, "anpass", :des, "anpass2")
    end
  end
  test "credential fails for invalid privacy protocol" do
    assert_raise FunctionClauseError, fn ->
      NetSNMP.credential(:v3, :auth_priv, "anname", :sha, "anpass", :blarg, "anpass2")
    end
  end

  test "credential_to_snmpcmd_args returns correct string" do
    test_creds = [
      version: "3",
      sec_level: "authPriv",
      sec_name: "anname",
      auth_proto: "sha",
      auth_pass: "anpass",
      priv_proto: "aes",
      priv_pass: "anpass2"
    ]

    assert NetSNMP.credential_to_snmpcmd_args(test_creds) ==
      "-v3 -lauthPriv -u anname -a sha -A anpass -x aes -X anpass2"
  end

  test "to_string returns correct string for Agent" do
    assert to_string(NetSNMP.agent("192.0.2.1", :udp, 161))
      == "udp:192.0.2.1:161"
  end
end
