# Copyright © 2015 Jonathan Storm <the.jonathan.storm@gmail.com>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING.WTFPL file for more details.

defmodule NetSNMP.ParseTest do
  use ExUnit.Case

  test "Removes all MIB parse errors from output" do
    output =
      """
      MIB search path: /home/jesolutions/.snmp/mibs:/usr/share/snmp/mibs:/usr/share/snmp/mibs/iana:/usr/share/snmp/mibs/ietf:/usr/share/mibs/site:/usr/share/snmp/mibs:/usr/share/mibs/iana:/usr/share/mibs/ietf:/usr/share/mibs/netsnmp
      Cannot find module (SNMPv2-SMI): At line 34 in /usr/share/snmp/mibs/UCD-SNMP-MIB.txt
      Cannot find module (SNMPv2-TC): At line 37 in /usr/share/snmp/mibs/UCD-SNMP-MIB.txt
      Did not find 'enterprises' in module #-1 (/usr/share/snmp/mibs/UCD-SNMP-MIB.txt)
      Did not find 'DisplayString' in module #-1 (/usr/share/snmp/mibs/UCD-SNMP-MIB.txt)
      Did not find 'TruthValue' in module #-1 (/usr/share/snmp/mibs/UCD-SNMP-MIB.txt)
      Unlinked OID in UCD-SNMP-MIB: ucdavis ::= { enterprises 2021 }
      Undefined identifier: enterprises near line 39 of /usr/share/snmp/mibs/UCD-SNMP-MIB.txt
      Did not find 'ucdavis' in module UCD-SNMP-MIB (/usr/share/snmp/mibs/UCD-SNMP-MIB-OLD.txt)
      Did not find 'DisplayString' in module #-1 (/usr/share/snmp/mibs/UCD-SNMP-MIB-OLD.txt)
      Unlinked OID in UCD-SNMP-MIB-OLD: loadaves ::= { ucdavis 7 }
      Undefined identifier: ucdavis near line 528 of /usr/share/snmp/mibs/UCD-SNMP-MIB-OLD.txt
      Unlinked OID in UCD-SNMP-MIB-OLD: disk ::= { ucdavis 6 }
      Undefined identifier: ucdavis near line 417 of /usr/share/snmp/mibs/UCD-SNMP-MIB-OLD.txt
      Unlinked OID in UCD-SNMP-MIB-OLD: extensible ::= { ucdavis 3 }
      Undefined identifier: ucdavis near line 146 of /usr/share/snmp/mibs/UCD-SNMP-MIB-OLD.txt
      Unlinked OID in UCD-SNMP-MIB-OLD: processes ::= { ucdavis 1 }
      Undefined identifier: ucdavis near line 67 of /usr/share/snmp/mibs/UCD-SNMP-MIB-OLD.txt
      Cannot find module (SNMPv2-TC): At line 15 in /usr/share/snmp/mibs/UCD-DISKIO-MIB.txt
      Did not find 'DisplayString' in module #-1 (/usr/share/snmp/mibs/UCD-DISKIO-MIB.txt)
      Did not find 'ucdExperimental' in module UCD-SNMP-MIB (/usr/share/snmp/mibs/UCD-DISKIO-MIB.txt)
      Unlinked OID in UCD-DISKIO-MIB: ucdDiskIOMIB ::= { ucdExperimental 15 }
      Undefined identifier: ucdExperimental near line 19 of /usr/share/snmp/mibs/UCD-DISKIO-MIB.txt
      Cannot find module (SNMPv2-SMI): At line 8 in /usr/share/snmp/mibs/NET-SNMP-MIB.txt
      Did not find 'enterprises' in module #-1 (/usr/share/snmp/mibs/NET-SNMP-MIB.txt)
      Unlinked OID in NET-SNMP-MIB: netSnmp ::= { enterprises 8072 }
      Undefined identifier: enterprises near line 10 of /usr/share/snmp/mibs/NET-SNMP-MIB.txt
      Cannot find module (SNMPv2-TC): At line 13 in /usr/share/snmp/mibs/NET-SNMP-PERIODIC-NOTIFY-MIB.txt
      Did not find 'netSnmpModuleIDs' in module NET-SNMP-MIB (/usr/share/snmp/mibs/NET-SNMP-PERIODIC-NOTIFY-MIB.txt)
      Did not find 'netSnmpObjects' in module NET-SNMP-MIB (/usr/share/snmp/mibs/NET-SNMP-PERIODIC-NOTIFY-MIB.txt)
      Did not find 'netSnmpNotifications' in module NET-SNMP-MIB (/usr/share/snmp/mibs/NET-SNMP-PERIODIC-NOTIFY-MIB.txt)
      Did not find 'DisplayString' in module #-1 (/usr/share/snmp/mibs/NET-SNMP-PERIODIC-NOTIFY-MIB.txt)
      Unlinked OID in NET-SNMP-PERIODIC-NOTIFY-MIB: netSnmpPeriodicNotifyMib ::= { netSnmpModuleIDs 5 }
      Undefined identifier: netSnmpModuleIDs near line 16 of /usr/share/snmp/mibs/NET-SNMP-PERIODIC-NOTIFY-MIB.txt
      Cannot find module (SNMP-FRAMEWORK-MIB): At line 9 in /usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt
      Cannot find module (SNMPv2-TC): At line 21 in /usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt
      Did not find 'SnmpAdminString' in module #-1 (/usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt)
      Did not find 'netSnmpObjects' in module NET-SNMP-MIB (/usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt)
      Did not find 'netSnmpModuleIDs' in module NET-SNMP-MIB (/usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt)
      Did not find 'netSnmpNotifications' in module NET-SNMP-MIB (/usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt)
      Did not find 'netSnmpGroups' in module NET-SNMP-MIB (/usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt)
      Did not find 'DisplayString' in module #-1 (/usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt)
      Did not find 'RowStatus' in module #-1 (/usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt)
      Did not find 'TruthValue' in module #-1 (/usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt)
      Unlinked OID in NET-SNMP-AGENT-MIB: nsAgentNotifyGroup ::= { netSnmpGroups 9 }
      Undefined identifier: netSnmpGroups near line 545 of /usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt
      Unlinked OID in NET-SNMP-AGENT-MIB: nsTransactionGroup ::= { netSnmpGroups 8 }
      Undefined identifier: netSnmpGroups near line 536 of /usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt
      Unlinked OID in NET-SNMP-AGENT-MIB: nsConfigGroups ::= { netSnmpGroups 7 }
      Undefined identifier: netSnmpGroups near line 515 of /usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt
      Unlinked OID in NET-SNMP-AGENT-MIB: nsCacheGroup ::= { netSnmpGroups 4 }
      Undefined identifier: netSnmpGroups near line 505 of /usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt
      Unlinked OID in NET-SNMP-AGENT-MIB: nsModuleGroup ::= { netSnmpGroups 2 }
      Undefined identifier: netSnmpGroups near line 495 of /usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt
      Unlinked OID in NET-SNMP-AGENT-MIB: netSnmpAgentMIB ::= { netSnmpModuleIDs 2 }
      Undefined identifier: netSnmpModuleIDs near line 24 of /usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt
      Unlinked OID in NET-SNMP-AGENT-MIB: nsTransactions ::= { netSnmpObjects 8 }
      Undefined identifier: netSnmpObjects near line 55 of /usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt
      Unlinked OID in NET-SNMP-AGENT-MIB: nsConfiguration ::= { netSnmpObjects 7 }
      Undefined identifier: netSnmpObjects near line 54 of /usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt
      Unlinked OID in NET-SNMP-AGENT-MIB: nsErrorHistory ::= { netSnmpObjects 6 }
      Undefined identifier: netSnmpObjects near line 53 of /usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt
      Unlinked OID in NET-SNMP-AGENT-MIB: nsCache ::= { netSnmpObjects 5 }
      Undefined identifier: netSnmpObjects near line 52 of /usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt
      Unlinked OID in NET-SNMP-AGENT-MIB: nsDLMod ::= { netSnmpObjects 4 }
      Undefined identifier: netSnmpObjects near line 51 of /usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt
      Unlinked OID in NET-SNMP-AGENT-MIB: nsExtensions ::= { netSnmpObjects 3 }
      Undefined identifier: netSnmpObjects near line 50 of /usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt
      Unlinked OID in NET-SNMP-AGENT-MIB: nsMibRegistry ::= { netSnmpObjects 2 }
      Undefined identifier: netSnmpObjects near line 49 of /usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt
      Unlinked OID in NET-SNMP-AGENT-MIB: nsVersion ::= { netSnmpObjects 1 }
      Undefined identifier: netSnmpObjects near line 48 of /usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt
      Unlinked OID in NET-SNMP-AGENT-MIB: nsNotifyRestart ::= { netSnmpNotifications 3 }
      Undefined identifier: netSnmpNotifications near line 482 of /usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt
      Unlinked OID in NET-SNMP-AGENT-MIB: nsNotifyShutdown ::= { netSnmpNotifications 2 }
      Undefined identifier: netSnmpNotifications near line 476 of /usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt
      Unlinked OID in NET-SNMP-AGENT-MIB: nsNotifyStart ::= { netSnmpNotifications 1 }
      Undefined identifier: netSnmpNotifications near line 470 of /usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt
      Did not find 'nsExtensions' in module NET-SNMP-AGENT-MIB (/usr/share/snmp/mibs/NET-SNMP-EXTEND-MIB.txt)
      Did not find 'DisplayString' in module #-1 (/usr/share/snmp/mibs/NET-SNMP-EXTEND-MIB.txt)
      Did not find 'RowStatus' in module #-1 (/usr/share/snmp/mibs/NET-SNMP-EXTEND-MIB.txt)
      Did not find 'StorageType' in module #-1 (/usr/share/snmp/mibs/NET-SNMP-EXTEND-MIB.txt)
      Unlinked OID in NET-SNMP-EXTEND-MIB: nsExtendGroups ::= { nsExtensions 3 }
      Undefined identifier: nsExtensions near line 39 of /usr/share/snmp/mibs/NET-SNMP-EXTEND-MIB.txt
      Unlinked OID in NET-SNMP-EXTEND-MIB: nsExtendObjects ::= { nsExtensions 2 }
      Undefined identifier: nsExtensions near line 38 of /usr/share/snmp/mibs/NET-SNMP-EXTEND-MIB.txt
      Unlinked OID in NET-SNMP-EXTEND-MIB: netSnmpExtendMIB ::= { nsExtensions 1 }
      Undefined identifier: nsExtensions near line 19 of /usr/share/snmp/mibs/NET-SNMP-EXTEND-MIB.txt
      Cannot find module (SNMP-FRAMEWORK-MIB): At line 10 in /usr/share/snmp/mibs/NET-SNMP-PASS-MIB.txt
      Cannot find module (SNMP-FRAMEWORK-MIB): At line 10 in /usr/share/snmp/mibs/NET-SNMP-EXAMPLES-MIB.txt
      Bad operator (INTEGER): At line 73 in /usr/share/mibs/ietf/SNMPv2-PDU
      Unlinked OID in IPATM-IPMC-MIB: marsMIB ::= { mib-2 57 }
      Undefined identifier: mib-2 near line 18 of /usr/share/mibs/ietf/IPATM-IPMC-MIB
      Expected "::=" (RFC5644): At line 493 in /usr/share/mibs/iana/IANA-IPPM-METRICS-REGISTRY-MIB
      Expected "{" (EOF): At line 651 in /usr/share/mibs/iana/IANA-IPPM-METRICS-REGISTRY-MIB
      Bad object identifier: At line 651 in /usr/share/mibs/iana/IANA-IPPM-METRICS-REGISTRY-MIB
      Bad parse of OBJECT-IDENTITY: At line 651 in /usr/share/mibs/iana/IANA-IPPM-METRICS-REGISTRY-MIB
      """ |> String.split("\n")
          |> Enum.filter(& &1 != "")

    result =
      output
      |> NetSNMP.Parse.remove_mib_parse_errors
      |> Enum.into([])

    assert result == []
  end

  test """
  Does not erroneously identify an SNMP error as a MIB
  parse error
  """
  do
    output = ["snmptable: Unknown user name"]

    result =
      output
      |> NetSNMP.Parse.remove_mib_parse_errors
      |> Enum.into([])

    assert result == output
  end
end
