net-snmp-elixir
=======
[![Build Status](https://travis-ci.org/jonnystorm/net-snmp-elixir.svg?branch=master)](https://travis-ci.org/jonnystorm/net-snmp-elixir)

A thin layer of Elixir poured atop snmpget/snmpset. To be used with [snmp-mib-elixir](https://github.com/jonnystorm/snmp-mib-elixir).

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
```

For now, this assumes you (1) have net-snmp utilities installed and (2) snmpget/set/walk is in your path.

