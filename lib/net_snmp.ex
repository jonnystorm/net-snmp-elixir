# Copyright © 2015 Jonathan Storm <the.jonathan.storm@gmail.com>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING.WTFPL file for more details.

defmodule NetSNMP do
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
  
  @spec agent(String.t, ip_protocol, port_number) :: Agent.t
  def agent(host, ip_protocol, port)
      when ip_protocol in [:tcp, :udp] and port in 0..65535 do
    %Agent{host: host, ip_proto: ip_protocol, port: port}
  end
  @spec agent(String.t) :: Agent.t
  def agent(host) do
    %Agent{host: host, ip_proto: :udp, port: 161}
  end

  @spec credential(:v1, String.t) :: Keyword.t
  def credential(:v1, community) do
    [
      version: "1",
      community: community
    ]
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

      {:ok, SNMPMIB.object(oid, type, value)}
    rescue
      _ ->
        [_|error_words] = String.split(line)
        cause = error_words |> Enum.join(" ") |> output_error_message_to_cause

        {:error, cause}
    end
  end

  defp parse_snmp_output(output) do
    output
    |> String.strip
    |> String.split("\n")
    |> Enum.map(&parse_snmp_output_line(&1))
  end

  defp columns_and_values_to_data_model(columns, values) do
    for pair <- Enum.zip(columns, values), into: %{}, do: pair
  end
  def parse_snmp_table_output(output) do
    [headers | rows] = output
    |> String.strip
    |> String.split("\n")
    |> Enum.drop(1)
    |> Enum.filter(fn "" -> false; _ -> true end)

    columns = headers
    |> String.split("||")
    |> Enum.map(fn header ->
      header |> String.downcase |> String.to_atom
    end)

    rows
    |> Stream.map(fn row -> String.split(row, "||") end)
    |> Enum.map(fn values ->
      columns_and_values_to_data_model(columns, values)
    end)
  end

  defp objects_to_oids(snmp_objects) do
    snmp_objects
    |> Enum.map(fn object ->
      SNMPMIB.Object.oid(object) |> SNMPMIB.list_oid_to_string
    end)
  end

  defp gen_snmpcmd(:get, snmp_objects, agent, credential)
      when is_list(snmp_objects) do
    [
      "snmpget -Le -mALL -One",
      credential_to_snmpcmd_args(credential),
      to_string(agent) | objects_to_oids(snmp_objects)
    ] |> Enum.join(" ")
  end
  defp gen_snmpcmd(:set, snmp_objects, agent, credential)
      when is_list(snmp_objects) do
    [
      "snmpset -Le -mALL -One",
      credential_to_snmpcmd_args(credential),
      to_string(agent) | (for o <- snmp_objects, do: to_string o)
    ] |> Enum.join(" ")
  end
  defp gen_snmpcmd(:table, snmp_object, agent, credential) do
    [
      "snmptable -Le -mALL -Clbf '||' -Oe",
      credential_to_snmpcmd_args(credential),
      to_string(agent) | objects_to_oids([snmp_object])
    ] |> Enum.join(" ")
  end
  defp gen_snmpcmd(:walk, snmp_object, agent, credential) do
    [
      "snmpwalk -Le -mALL -One",
      credential_to_snmpcmd_args(credential),
      to_string(agent) | objects_to_oids([snmp_object])
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

  def table(snmp_objects, agent, credential) when is_list(snmp_objects) do
    snmp_objects
    |> Enum.map(fn object -> table(object, agent, credential) end)
    |> List.flatten
  end
  def table(snmp_object, agent, credential) do
    gen_snmpcmd(:table, snmp_object, agent, credential)
    |> shell_cmd
    |> parse_snmp_table_output
  end

  def walk(snmp_objects, agent, credential) when is_list(snmp_objects) do
    snmp_objects
    |> Enum.map(fn object -> walk(object, agent, credential) end)
    |> List.flatten
  end
  def walk(snmp_object, agent, credential) do
    gen_snmpcmd(:walk, snmp_object, agent, credential)
    |> shell_cmd
    |> parse_snmp_output
  end
end

defimpl String.Chars, for: NetSNMP.Agent do
  import Kernel, except: [to_string: 1]

  def to_string(agent) do
    transport_spec = agent |> NetSNMP.Agent.ip_protocol |> Kernel.to_string
    transport_addr = NetSNMP.Agent.host(agent)
    transport_port = agent |> NetSNMP.Agent.port |> Kernel.to_string

    [transport_spec, transport_addr, transport_port] |> Enum.join(":")
  end
end

