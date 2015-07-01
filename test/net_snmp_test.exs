# Copyright © 2015 Jonathan Storm <the.jonathan.storm@gmail.com>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING.WTFPL file for more details.

defmodule NetSNMPTest do
  use Amrita.Sweet

  fact "agent returns correct Agent" do
    agent = %NetSNMP.Agent{host: "192.0.2.1", ip_proto: :udp, port: 161}

    NetSNMP.agent("192.0.2.1", :udp, 161) |> agent
  end
  fact "agent fails for invalid protocol" do
    fn -> NetSNMP.agent("192.0.2.1", :blarg, 161) end
    |> raises FunctionClauseError
  end

  fact "credential returns correct keyword list for SNMPv2c" do
    NetSNMP.credential(:v2c, "ancommunity")
    |> [version: "2c", community: "ancommunity"]
  end
  fact "credential returns correct keyword list for SNMPv3, noAuthNoPriv" do
    NetSNMP.credential(:v3, :no_auth_no_priv, "anname")
    |> [version: "3", sec_level: "noAuthNoPriv", sec_name: "anname"]
  end
  fact "credential returns correct keyword list for SNMPv3, authNoPriv" do
    NetSNMP.credential(:v3, :auth_no_priv, "anname", :md5, "anpass")
    |> [
         version: "3",
         sec_level: "authNoPriv",
         sec_name: "anname",
         auth_proto: "md5",
         auth_pass: "anpass"
       ]
  end
  fact "credential returns correct keyword list for SNMPv3, authPriv" do
    NetSNMP.credential(:v3, :auth_priv, "anname", :sha, "anpass", :des, "anpass2")
    |> [
         version: "3",
         sec_level: "authPriv",
         sec_name: "anname",
         auth_proto: "sha",
         auth_pass: "anpass",
         priv_proto: "des",
         priv_pass: "anpass2"
       ]
  end

  fact "credential fails for invalid security level" do
    fn ->
      NetSNMP.credential(:v3, :blarg, "anname", :sha, "anpass", :des, "anpass2")
    end |> raises FunctionClauseError
  end

  fact "credential fails for invalid authentication protocol" do
    fn ->
      NetSNMP.credential(:v3, :auth_priv, "anname", :blarg, "anpass", :des, "anpass2")
    end |> raises FunctionClauseError
  end

  fact "credential fails for invalid privacy protocol" do
    fn ->
      NetSNMP.credential(:v3, :auth_priv, "anname", :sha, "anpass", :blarg, "anpass2")
    end |> raises FunctionClauseError
  end

  fact "credential_to_snmpcmd_args returns correct string" do
    test_creds = [
      version: "3",
      sec_level: "authPriv",
      sec_name: "anname",
      auth_proto: "sha",
      auth_pass: "anpass",
      priv_proto: "aes",
      priv_pass: "anpass2"
    ]

    NetSNMP.credential_to_snmpcmd_args(test_creds)
    |> "-v3 -lauthPriv -u anname -a sha -A anpass -x aes -X anpass2"
  end

  fact "to_string returns correct string for Agent" do
    to_string(NetSNMP.agent("192.0.2.1", :udp, 161)) |> "udp:192.0.2.1:161"
  end

  fact "parses snmptable output" do
    output = "SNMP table: IP-FORWARD-MIB::ipCidrRouteTable

Dest       Mask            Tos NextHop    IfIndex Type Proto Age  Info                    NextHopAS Metric1 Metric2 Metric3 Metric4 Metric5 Status 
1.1.1.1    255.255.255.255 0   0.0.0.0    6       3    2     3804 SNMPv2-SMI::zeroDotZero 0         0       -1      -1      -1      -1      1      
2.2.2.2    255.255.255.255 0   172.31.0.3 1       4    13    0    SNMPv2-SMI::zeroDotZero 0         2       -1      -1      -1      -1      1      
"

    NetSNMP.parse_snmp_table_output(output)
    |> [
      %{
        dest: "1.1.1.1",
        mask: "255.255.255.255",
        tos: "0",
        nexthop: "0.0.0.0",
        ifindex: "6",
        type: "3",
        proto: "2",
        age: "3804",
        info: "SNMPv2-SMI::zeroDotZero",
        nexthopas: "0",
        metric1: "0",
        metric2: "-1",
        metric3: "-1",
        metric4: "-1",
        metric5: "-1",
        status: "1"
      },
      %{
        dest: "2.2.2.2",
        mask: "255.255.255.255",
        tos: "0",
        nexthop: "172.31.0.3",
        ifindex: "1",
        type: "4",
        proto: "13",
        age: "0",
        info: "SNMPv2-SMI::zeroDotZero",
        nexthopas: "0",
        metric1: "2", metric2: "-1", metric3: "-1",
        metric4: "-1",
        metric5: "-1",
        status: "1"
      }
    ]
  end
end
