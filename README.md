net-snmp-elixir
=======
[![Build Status](https://travis-ci.org/jonnystorm/net-snmp-elixir.svg?branch=master)](https://travis-ci.org/jonnystorm/net-snmp-elixir)

A thin layer of Elixir poured atop net-snmp utilities. To be used with [snmp-mib-elixir](https://github.com/jonnystorm/snmp-mib-elixir).

### To use:

```
iex> sysname_object = ".1.3.6.1.2.1.1.5" |> SNMPMIB.object(:string, "")
%SNMPMIB.Object{oid: [1, 3, 6, 1, 2, 1, 1, 5], type: 4, value: ""}

iex> credential = NetSNMP.credential(:v2c, "public")
[version: "2c", community: "public"]

iex> agent = NetSNMP.agent("192.0.2.2")
%NetSNMP.Agent{host: "192.0.2.2", ip_proto: :udp, port: 161}

iex> sysname_object |> SNMPMIB.index(0) |> NetSNMP.get(agent, credential)
[ok: %SNMPMIB.Object{oid: [1, 3, 6, 1, 2, 1, 1, 5, 0], type: 4, value: "R1"}]

iex> ip_net_to_media_table_object = "1.3.6.1.2.1.4.22" |> SNMPMIB.object(:any, nil)
[ok: %SNMPMIB.Object{oid: [1, 3, 6, 1, 2, 1, 4, 22], type: 0, value: nil}]

iex> ip_net_to_media_table_object |> NetSNMP.walk(agent, credential)
[ok: %SNMPMIB.Object{oid: [1, 3, 6, 1, 2, 1, 4, 22, 1, 1, 2, 192, 0, 2, 1],
  type: 2, value: 2},
 ok: %SNMPMIB.Object{oid: [1, 3, 6, 1, 2, 1, 4, 22, 1, 1, 2, 192, 0, 2, 2],
  type: 2, value: 2},
 ok: %SNMPMIB.Object{oid: [1, 3, 6, 1, 2, 1, 4, 22, 1, 2, 2, 192, 0, 2, 1],
  type: 4, value: "66:fb:30:37:c3:81"},
 ok: %SNMPMIB.Object{oid: [1, 3, 6, 1, 2, 1, 4, 22, 1, 2, 2, 192, 0, 2, 2],
  type: 4, value: "c2:1:39:f3:0:0"},
 ok: %SNMPMIB.Object{oid: [1, 3, 6, 1, 2, 1, 4, 22, 1, 3, 2, 192, 0, 2, 1],
  type: 4, value: "192.0.2.1"},
 ok: %SNMPMIB.Object{oid: [1, 3, 6, 1, 2, 1, 4, 22, 1, 3, 2, 192, 0, 2, 2],
  type: 4, value: "192.0.2.2"},
 ok: %SNMPMIB.Object{oid: [1, 3, 6, 1, 2, 1, 4, 22, 1, 4, 2, 192, 0, 2, 1],
  type: 2, value: 3},
 ok: %SNMPMIB.Object{oid: [1, 3, 6, 1, 2, 1, 4, 22, 1, 4, 2, 192, 0, 2, 2],
  type: 2, value: 4}]
```

For now, this assumes you (1) have net-snmp utilities installed and (2) snmpget, snmpset, etc. are in your path.

