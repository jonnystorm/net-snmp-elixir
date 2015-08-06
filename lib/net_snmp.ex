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

  defp get_snmpcmd_error(message) do
    %{
      "Generic error"                                                                                 => :snmperr_generr,
      "Invalid local port"                                                                            => :snmperr_bad_locport,
      "Unknown host"                                                                                  => :snmperr_bad_address,
      "Unknown session"                                                                               => :snmperr_bad_session,
      "Too long"                                                                                      => :snmperr_too_long,
      "No socket"                                                                                     => :snmperr_no_socket,
      "Cannot send V2 PDU on V1 session"                                                              => :snmperr_v2_in_v1,
      "Cannot send V1 PDU on V2 session"                                                              => :snmperr_v1_in_v2,
      "Bad value for non-repeaters"                                                                   => :snmperr_bad_repeaters,
      "Bad value for max-repetitions"                                                                 => :snmperr_bad_repetitions,
      "Error building ASN.1 representation"                                                           => :snmperr_bad_asn1_build,
      "Failure in sendto"                                                                             => :snmperr_bad_sendto,
      "Bad parse of ASN.1 type"                                                                       => :snmperr_bad_parse,
      "Bad version specified"                                                                         => :snmperr_bad_version,
      "Bad source party specified"                                                                    => :snmperr_bad_src_party,
      "Bad destination party specified"                                                               => :snmperr_bad_dst_party,
      "Bad context specified"                                                                         => :snmperr_bad_context,
      "Bad community specified"                                                                       => :snmperr_bad_community,
      "Cannot send noAuth/Priv"                                                                       => :snmperr_noauth_despriv,
      "Bad ACL definition"                                                                            => :snmperr_bad_acl,
      "Bad Party definition"                                                                          => :snmperr_bad_party,
      "Session abort failure"                                                                         => :snmperr_abort,
      "Unknown PDU type"                                                                              => :snmperr_unknown_pdu,
      "Timeout"                                                                                       => :snmperr_timeout,
      "Failure in recvfrom"                                                                           => :snmperr_bad_recvfrom,
      "Unable to determine contextEngineID"                                                           => :snmperr_bad_eng_id,
      "No securityName specified"                                                                     => :snmperr_bad_sec_name,
      "Unable to determine securityLevel"                                                             => :snmperr_bad_sec_level,
      "ASN.1 parse error in message"                                                                  => :snmperr_asn_parse_err,
      "Unknown security model in message"                                                             => :snmperr_unknown_sec_model,
      "Invalid message (e.g. msgFlags)"                                                               => :snmperr_invalid_msg,
      "Unknown engine ID"                                                                             => :snmperr_unknown_eng_id,
      "Unknown user name"                                                                             => :snmperr_unknown_user_name,
      "Unsupported security level"                                                                    => :snmperr_unsupported_sec_level,
      "Authentication failure (incorrect password, community or key)"                                 => :snmperr_authentication_failure,
      "Not in time window"                                                                            => :snmperr_not_in_time_window,
      "Decryption error"                                                                              => :snmperr_decryption_err,
      "SCAPI general failure"                                                                         => :snmperr_sc_general_failure,
      "SCAPI sub-system not configured"                                                               => :snmperr_sc_not_configured,
      "Key tools not available"                                                                       => :snmperr_kt_not_available,
      "Unknown Report message"                                                                        => :snmperr_unknown_report,
      "USM generic error"                                                                             => :snmperr_usm_genericerror,
      "USM unknown security name (no such user exists)"                                               => :snmperr_usm_unknownsecurityname,
      "USM unsupported security level (this user has not been configured for that level of security)" => :snmperr_usm_unsupportedsecuritylevel,
      "USM encryption error"                                                                          => :snmperr_usm_encryptionerror,
      "USM authentication failure (incorrect password or key)"                                        => :snmperr_usm_authenticationfailure,
      "USM parse error"                                                                               => :snmperr_usm_parseerror,
      "USM unknown engineID"                                                                          => :snmperr_usm_unknownengineid,
      "USM not in time window"                                                                        => :snmperr_usm_notintimewindow,
      "USM decryption error"                                                                          => :snmperr_usm_decryptionerror,
      "MIB not initialized"                                                                           => :snmperr_nomib,
      "Value out of range"                                                                            => :snmperr_range,
      "Sub-id out of range"                                                                           => :snmperr_max_subid,
      "Bad sub-id in object identifier"                                                               => :snmperr_bad_subid,
      "Object identifier too long"                                                                    => :snmperr_long_oid,
      "Bad value name"                                                                                => :snmperr_bad_name,
      "Bad value notation"                                                                            => :snmperr_value,
      "Unknown Object Identifier"                                                                     => :snmperr_unknown_objid,
      "No PDU in snmp_send"                                                                           => :snmperr_null_pdu,
      "Missing variables in PDU"                                                                      => :snmperr_no_vars,
      "Bad variable type"                                                                             => :snmperr_var_type,
      "Out of memory (malloc failure)"                                                                => :snmperr_malloc,
      "Kerberos related error"                                                                        => :snmperr_krb5,
      "Protocol error"                                                                                => :snmperr_protocol,
      "OID not increasing"                                                                            => :snmperr_oid_nonincreasing,
      "Context probe"                                                                                 => :snmperr_just_a_context_probe,
      "Configuration data found but the transport can't be configured"                                => :snmperr_transport_no_config,
      "Transport configuration failed"                                                                => :snmperr_transport_config_error
    }[message]
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
        cause = error_words
        |> Enum.join(" ")
        |> output_error_message_to_cause
        |> get_snmpcmd_error

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
