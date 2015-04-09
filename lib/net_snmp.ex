# Copyright © 2015 Jonathan Storm <the.jonathan.storm@gmail.com>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING.WTFPL file for more details.

defmodule NetSNMP do
  @type asn1_tag :: 0 | 1..6 | 9..10
  @type asn1_type :: :any|:boolean|:integer|:bit_string|:octet_string|:string|:null|:object_identifier|:real|:enumerated
  @type ip_protocol :: :udp | :tcp
  @type port_number :: 0..65535

  defmodule Agent do
    defstruct host: nil, ip_proto: nil, port: nil

    @type t :: %Agent{
      host: String.t,
      ip_proto: NetSNMP.ip_protocol,
      port: NetSNMP.port_number
    }

    def host(agent) do
      agent.host
    end

    def ip_protocol(agent) do
      agent.ip_proto
    end

    def port(agent) do
      agent.port
    end
  end

  defmodule Object do
    defstruct oid: nil, type: nil, value: nil

    @type t :: %Object{
      oid: [non_neg_integer],
      type: NetSNMP.asn1_tag,
      value: String.t | number
    }
    
    def oid(object) do
      object.oid
    end

    def oid(object, new_value) when is_list(new_value) do
      %Object{object|oid: new_value}
    end

    def type(object) do
      object.type
    end

    def type(object, new_type) when is_atom(new_type) do
      %Object{object|type: new_type}
    end
    
    def value(object) do
      object.value
    end

    def value(object, new_value)
        when is_number(new_value) or is_binary(new_value) do
      %Object{object|value: new_value}
    end
  end
  
  def list_oid_to_string(list_oid) do
    list_oid |> Enum.join(".")
  end

  def string_oid_to_list(string_oid) do
    string_oid
      |> String.strip(?.)
      |> :binary.split(".", [:global])
      |> Enum.map(&(String.to_integer &1))
  end

  def asn1_tag_to_type_char(type) do
    %{
      0 => "=",
      1 => "i",
      2 => "i",
      3 => "s",
      4 => "s",
      5 => "=",
      6 => "o",
      9 => "d",
      10 => "i"
    } |> Map.fetch!(type)
  end

  def type_to_asn1_tag(type) do
    %{
      any: 0,
      boolean: 1,
      integer: 2,
      bit_string: 3,
      octet_string: 4, string: 4,
      null: 5,
      object_identifier: 6, oid: 6,
      real: 9,
      enumerated: 10
    } |> Map.fetch!(type)
  end

  @spec agent(String.t, ip_protocol, port_number) :: Agent.t
  def agent(host, ip_protocol, port)
      when ip_protocol in [:tcp, :udp] and port in 0..65535 do
    %Agent{host: host, ip_proto: ip_protocol, port: port}
  end
  @spec agent(String.t) :: Agent.t
  def agent(host) do
    %Agent{host: host, ip_proto: :udp, port: 161}
  end

  @spec object(String.t, asn1_type, String.t | number) :: Object.t
  def object(oid, type, value) do
    %Object{
      oid: string_oid_to_list(oid),
      type: type_to_asn1_tag(type),
      value: value
    }
  end

  @spec index(Object.t, pos_integer) :: Object.t
  def index(object, index) when is_integer(index) do
    indexed_oid = Object.oid(object) ++ [index]

    Object.oid(object, indexed_oid)
  end

  @spec credential(:v2c, String.t) :: Keyword.t
  def credential(:v2c, community) do
    [
      version: "2c",
      community: community
    ]
  end
  @spec credential(:v3, :no_auth_no_priv, String.t) :: Keyword.t
  def credential(:v3, :no_auth_no_priv, sec_name) do
    [
      version: "3",
      sec_level: "noAuthNoPriv",
      sec_name: sec_name
    ]
  end
  @spec credential(:v3, :auth_no_priv, String.t, :md5 | :sha, String.t) :: Keyword.t
  def credential(:v3, :auth_no_priv, sec_name, auth_proto, auth_pass)
      when auth_proto in [:md5, :sha] do
    [
      version: "3",
      sec_level: "authNoPriv",
      sec_name: sec_name,
      auth_proto: to_string(auth_proto),
      auth_pass: auth_pass
    ]
  end
  @spec credential(:v3, :auth_priv, String.t, :md5 | :sha, String.t, :des | :aes, String.t) :: Keyword.t
  def credential(:v3, :auth_priv, sec_name, auth_proto, auth_pass, priv_proto, priv_pass)
      when auth_proto in [:md5, :sha] and priv_proto in [:des, :aes] do
    [
      version: "3",
      sec_level: "authPriv",
      sec_name: sec_name,
      auth_proto: to_string(auth_proto),
      auth_pass: auth_pass,
      priv_proto: to_string(priv_proto),
      priv_pass: priv_pass
    ]
  end

  defp _credential_to_snmpcmd_args([], acc) do
    Enum.join(acc, " ")
  end
  defp _credential_to_snmpcmd_args([{:version, version}|tail], acc) do
    _credential_to_snmpcmd_args(tail, ["-v#{version}"|acc])
  end
  defp _credential_to_snmpcmd_args([{:community, community}|tail], acc) do
    _credential_to_snmpcmd_args(tail, acc ++ ["-c #{community}"])
  end
  defp _credential_to_snmpcmd_args([{:sec_level, sec_level}|tail], acc) do
    _credential_to_snmpcmd_args(tail, acc ++ ["-l#{sec_level}"])
  end
  defp _credential_to_snmpcmd_args([{:sec_name, sec_name}|tail], acc) do
    _credential_to_snmpcmd_args(tail, acc ++ ["-u #{sec_name}"])
  end
  defp _credential_to_snmpcmd_args([{:auth_proto, auth_proto}|tail], acc) do
    _credential_to_snmpcmd_args(tail, acc ++ ["-a #{auth_proto}"])
  end
  defp _credential_to_snmpcmd_args([{:auth_pass, auth_pass}|tail], acc) do
    _credential_to_snmpcmd_args(tail, acc ++ ["-A #{auth_pass}"])
  end
  defp _credential_to_snmpcmd_args([{:priv_proto, priv_proto}|tail], acc) do
    _credential_to_snmpcmd_args(tail, acc ++ ["-x #{priv_proto}"])
  end
  defp _credential_to_snmpcmd_args([{:priv_pass, priv_pass}|tail], acc) do
    _credential_to_snmpcmd_args(tail, acc ++ ["-X #{priv_pass}"])
  end
  def credential_to_snmpcmd_args(credential) do
    _credential_to_snmpcmd_args(credential, [])
  end

  defp output_type_string_to_type(type_string) do
    type_string
      |> String.rstrip(?:)
      |> String.downcase
      |> String.to_atom
  end

  defp output_error_message_to_cause(error_message) do
    error_message
      |> String.lstrip(?=)
      |> String.strip
  end

  defp parse_snmp_output_line(line) do
    try do
      [oid, _, type_string, value] = String.split(line)
      type = output_type_string_to_type(type_string)

      {:ok, object(oid, type, value)}
    rescue
      _e in MatchError ->
        [_|error_words] = String.split(line)
        cause = error_words |> Enum.join(" ") |> output_error_message_to_cause

        {:error, cause}
    end
  end

  defp parse_snmp_output(output) do
    output
      |> String.strip
      |> String.split("\n")
      |> Enum.map(&(parse_snmp_output_line &1))
  end

  defp gen_snmpcmd(:get, snmp_objects, agent, credential)
      when is_list(snmp_objects) do
    [
      "snmpget -On",
      credential_to_snmpcmd_args(credential),
      to_string(agent) |
        (for o <- snmp_objects, do: Object.oid(o) |> list_oid_to_string)
    ] |> Enum.join(" ")
  end
  defp gen_snmpcmd(:set, snmp_objects, agent, credential)
      when is_list(snmp_objects) do
    [
      "snmpset -On",
      credential_to_snmpcmd_args(credential),
      to_string(agent) | (for o <- snmp_objects, do: to_string o)
    ] |> Enum.join(" ")
  end

  defp shell_cmd(command) do
    command
      |> :binary.bin_to_list
      |> :os.cmd
      |> :binary.list_to_bin
  end

  def get(snmp_objects, agent, credential) when is_list(snmp_objects) do
    gen_snmpcmd(:get, snmp_objects, agent, credential)
      |> shell_cmd
      |> parse_snmp_output
  end
  def get(snmp_object, agent, credential) do
    get([snmp_object], agent, credential)
  end

  def set(snmp_objects, agent, credential) when is_list(snmp_objects) do
    gen_snmpcmd(:set, snmp_objects, agent, credential)
      |> shell_cmd
      |> parse_snmp_output
  end
  def set(snmp_object, agent, credential) do
    set([snmp_object], agent, credential)
  end
end

defimpl String.Chars, for: NetSNMP.Agent do
  import Kernel, except: [to_string: 1]

  def to_string(agent) do
    transport_spec = agent
      |> NetSNMP.Agent.ip_protocol
      |> Kernel.to_string
    transport_addr = NetSNMP.Agent.host(agent)
    transport_port = agent
      |> NetSNMP.Agent.port
      |> Kernel.to_string

    [transport_spec, transport_addr, transport_port] |> Enum.join(":")
  end
end

defimpl String.Chars, for: NetSNMP.Object do
  import Kernel, except: [to_string: 1]

  def to_string(object) do
    [
      object |> NetSNMP.Object.oid |> NetSNMP.list_oid_to_string,
      object |> NetSNMP.Object.type |> NetSNMP.asn1_tag_to_type_char,
      object |> NetSNMP.Object.value
    ] |> Enum.join " "
  end
end
