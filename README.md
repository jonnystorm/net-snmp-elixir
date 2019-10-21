net-snmp-elixir
=======
[![Build Status](https://gitlab.com/jonnystorm/snmp-elixir/badges/master/pipeline.svg)](https://gitlab.com/jonnystorm/snmp-elixir/commits/master)

A thin layer of Elixir poured atop net-snmp utilities.
To be used with [snmp-mib-elixir](https://gitlab.com/jonnystorm/snmp-mib-elixir).

If you're able, please consider contributing to
[snmp-elixir](https://gitlab.com/jonnystorm/snmp-elixir); OTP, as is,
should provide 90% of what `net-snmp-elixir` does.

See the [API documentation](https://jonnystorm.github.io/net-snmp-elixir).

## Two APIs

A new request API is now provided by the `NetSNMP2` module.
The original API (`NetSNMP`) remains untouched.

### To use the new API:

```elixir
iex> credential = NetSNMP2.credential :v2, "public"
%{version: "2", community: "public"}

iex> uri = URI.parse "snmp://192.0.2.2"
%URI{authority: "192.0.2.2", fragment: nil, host: "192.0.2.2", path: nil,
 port: nil, query: nil, scheme: "snmp", userinfo: nil}

# GET
iex> %{uri: uri, credential: credential}
iex> |> Map.put(:varbinds, [%{oid: "1.3.6.1.2.1.1.5.0"}])
iex> |> NetSNMP2.request
[ok: %{oid: [1, 3, 6, 1, 2, 1, 1, 5, 0], type: :string, value: "R1"}]

# SET
iex> %{uri: uri, credential: credential}
iex> |> Map.put(:varbinds, [%{oid: "1.3.6.1.2.1.1.5.0", value: "Router1"}])
iex> |> NetSNMP2.request
[ok: %{oid: [1, 3, 6, 1, 2, 1, 1, 5, 0], type: :string, value: "Router1"}]

# Table
iex> %{uri: uri, credential: credential}
iex> |> Map.put(:varbinds, [%{oid: [1,3,6,1,2,1,4,24,4], type: :table}])
iex> |> NetSNMP2.request
[%{age: "313", dest: "192.0.2.2", ifindex: "2", info: "SNMPv2-SMI::zeroDotZero",
   mask: "255.255.255.254", metric1: "0", metric2: "-1", metric3: "-1",
   metric4: "-1", metric5: "-1", nexthop: "0.0.0.0", nexthopas: "0", proto: "2",
   status: "1", tos: "0", type: "3"},
 %{age: "2", dest: "192.0.2.33", ifindex: "6", info: "SNMPv2-SMI::zeroDotZero",
   mask: "255.255.255.255", metric1: "0", metric2: "-1", metric3: "-1",
   metric4: "-1", metric5: "-1", nexthop: "0.0.0.0", nexthopas: "0", proto: "2",
   status: "1", tos: "0", type: "3"}]
```

### To use the original API:

```elixir
iex> credential = NetSNMP.credential :v2c, "public"
[version: "2c", community: "public"]

iex> agent = URI.parse "snmp://192.0.2.2"
%URI{authority: "192.0.2.2", fragment: nil, host: "192.0.2.2", path: nil,
 port: nil, query: nil, scheme: "snmp", userinfo: nil}

iex> sysname_object = SNMPMIB.object ".1.3.6.1.2.1.1.5", :string, ""
%SNMPMIB.Object{oid: [1, 3, 6, 1, 2, 1, 1, 5], type: 4, value: ""}

iex> sysname_object |> SNMPMIB.index(0) |> NetSNMP.get(agent, credential)
[ok: %SNMPMIB.Object{oid: [1, 3, 6, 1, 2, 1, 1, 5, 0], type: 4, value: "R1"}]


iex> ip_net_to_media_table_object = SNMPMIB.object "1.3.6.1.2.1.4.22", :any, nil
[ok: %SNMPMIB.Object{oid: [1, 3, 6, 1, 2, 1, 4, 22], type: 0, value: nil}]

iex> NetSNMP.walk ip_net_to_media_table_object, agent, credential
[ok: %SNMPMIB.Object{oid: [1,3,6,1,2,1,4,22,1,1,2,192,0,2,1], type: 2, value: 2},
 ok: %SNMPMIB.Object{oid: [1,3,6,1,2,1,4,22,1,1,2,192,0,2,2], type: 2, value: 2},
 ok: %SNMPMIB.Object{oid: [1,3,6,1,2,1,4,22,1,2,2,192,0,2,1], type: 4, value: "66:fb:30:37:c3:81"},
 ok: %SNMPMIB.Object{oid: [1,3,6,1,2,1,4,22,1,2,2,192,0,2,2], type: 4, value: "c2:1:39:f3:0:0"},
 ok: %SNMPMIB.Object{oid: [1,3,6,1,2,1,4,22,1,3,2,192,0,2,1], type: 4, value: "192.0.2.1"},
 ok: %SNMPMIB.Object{oid: [1,3,6,1,2,1,4,22,1,3,2,192,0,2,2], type: 4, value: "192.0.2.2"},
 ok: %SNMPMIB.Object{oid: [1,3,6,1,2,1,4,22,1,4,2,192,0,2,1], type: 2, value: 3},
 ok: %SNMPMIB.Object{oid: [1,3,6,1,2,1,4,22,1,4,2,192,0,2,2], type: 2, value: 4}]


iex> ip_cidr_route_table_object = SNMPMIB.object "1.3.6.1.2.1.4.24.4", :any, nil
%SNMPMIB.Object{oid: [1, 3, 6, 1, 2, 1, 4, 24, 4], type: 0, value: nil}

iex> NetSNMP.table ip_cidr_route_table_object, agent, credential
[%{age: "313", dest: "192.0.2.2", ifindex: "2", info: "SNMPv2-SMI::zeroDotZero",
   mask: "255.255.255.254", metric1: "0", metric2: "-1", metric3: "-1",
   metric4: "-1", metric5: "-1", nexthop: "0.0.0.0", nexthopas: "0", proto: "2",
   status: "1", tos: "0", type: "3"},
 %{age: "2", dest: "192.0.2.33", ifindex: "6", info: "SNMPv2-SMI::zeroDotZero",
   mask: "255.255.255.255", metric1: "0", metric2: "-1", metric3: "-1",
   metric4: "-1", metric5: "-1", nexthop: "0.0.0.0", nexthopas: "0", proto: "2",
   status: "1", tos: "0", type: "3"}]
```

For now, this assumes you (1) have net-snmp utilities installed and (2) `snmpget`, `snmpset`, etc. are in your `$PATH`.

