# Copyright © 2015 Jonathan Storm <the.jonathan.storm@gmail.com>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING.WTFPL file for more details.

defmodule NetSNMPTest do
  use ExUnit.Case, async: true

  doctest NetSNMP

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

  test "parses snmpget/walk output" do
    output = "
.1.3.6.1.2.1.1.1.0 = STRING: Cisco IOS Software, 3700 Software (C3725-ADVENTERPRISEK9-M), Version 12.4(25d), RELEASE SOFTWARE (fc1)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2010 by Cisco Systems, Inc.
Compiled Wed 18-Aug-10 07:55 by prod_rel_team
.1.3.6.1.2.1.1.6.0 = STRING: 
.1.3.6.1.2.1.1.7.0 = INTEGER: 78
.1.3.6.1.2.1.1.8.0 = 0"

    assert NetSNMP.Parse.parse_snmp_output(output) ==
      [ {:ok, %SNMPMIB.Object{oid: [1, 3, 6, 1, 2, 1, 1, 1, 0], type: 4, value: "Cisco IOS Software, 3700 Software (C3725-ADVENTERPRISEK9-M), Version 12.4(25d), RELEASE SOFTWARE (fc1)\nTechnical Support: http://www.cisco.com/techsupport\nCopyright (c) 1986-2010 by Cisco Systems, Inc.\nCompiled Wed 18-Aug-10 07:55 by prod_rel_team"}},
        {:ok, %SNMPMIB.Object{oid: [1, 3, 6, 1, 2, 1, 1, 6, 0], type: 4, value: ""}},
        {:ok, %SNMPMIB.Object{oid: [1, 3, 6, 1, 2, 1, 1, 7, 0], type: 2, value: 78}},
        {:ok, %SNMPMIB.Object{oid: [1, 3, 6, 1, 2, 1, 1, 8, 0], type: 2, value: "0"}}
      ]
  end

  test "parses snmptable output" do
    output = "SNMP table: IP-FORWARD-MIB::ipCidrRouteTable

Dest||Mask||Tos||NextHop||IfIndex||Type||Proto||Age||Info||NextHopAS||Metric1||Metric2||Metric3||Metric4||Metric5||Status
1.1.1.1||255.255.255.255||0||0.0.0.0||6||3||2||3804||SNMPv2-SMI::zeroDotZero||0||0||-1||-1||-1||-1||1
2.2.2.2||255.255.255.255||0||172.31.0.3||1||4||13||0||SNMPv2-SMI::zeroDotZero||0||2||-1||-1||-1||-1||1
"

    assert NetSNMP.Parse.parse_snmp_table_output(output) ==
      [%{dest: "1.1.1.1",
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
       %{dest: "2.2.2.2",
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
