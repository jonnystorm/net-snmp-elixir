# Copyright © 2015 Jonathan Storm <the.jonathan.storm@gmail.com>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING.WTFPL file for more details.

defmodule NetSNMP do
  require Logger

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
  @spec credential(:v3, :auth_no_priv, String.t, :md5|:sha, String.t) :: Keyword.t
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
  @spec credential(:v3, :auth_priv, String.t, :md5|:sha, String.t, :des|:aes, String.t) :: Keyword.t
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
    Enum.join acc, " "
  end
  defp _credential_to_snmpcmd_args([{:version, version}|tail], acc) do
    _credential_to_snmpcmd_args tail, ["-v#{version}"|acc]
  end
  defp _credential_to_snmpcmd_args([{:community, community}|tail], acc) do
    _credential_to_snmpcmd_args tail, acc ++ ["-c '#{community}'"]
  end
  defp _credential_to_snmpcmd_args([{:sec_level, sec_level}|tail], acc) do
    _credential_to_snmpcmd_args tail, acc ++ ["-l#{sec_level}"]
  end
  defp _credential_to_snmpcmd_args([{:sec_name, sec_name}|tail], acc) do
    _credential_to_snmpcmd_args tail, acc ++ ["-u '#{sec_name}'"]
  end
  defp _credential_to_snmpcmd_args([{:auth_proto, auth_proto}|tail], acc) do
    _credential_to_snmpcmd_args tail, acc ++ ["-a #{auth_proto}"]
  end
  defp _credential_to_snmpcmd_args([{:auth_pass, auth_pass}|tail], acc) do
    _credential_to_snmpcmd_args tail, acc ++ ["-A '#{auth_pass}'"]
  end
  defp _credential_to_snmpcmd_args([{:priv_proto, priv_proto}|tail], acc) do
    _credential_to_snmpcmd_args tail, acc ++ ["-x #{priv_proto}"]
  end
  defp _credential_to_snmpcmd_args([{:priv_pass, priv_pass}|tail], acc) do
    _credential_to_snmpcmd_args tail, acc ++ ["-X '#{priv_pass}'"]
  end
  def credential_to_snmpcmd_args(credential) do
    _credential_to_snmpcmd_args credential, []
  end

  defp output_type_string_to_type(type_string) do
    type_string
    |> String.rstrip(?:)
    |> String.downcase
    |> String.to_atom
  end

  defp get_snmpcmd_error(message) do
    %{
      "(noError) No Error"                                                                           => :snmp_err_noerror,
      "(tooBig) Response message would have been too large."                                         => :snmp_err_toobig,
      "(noSuchName) There is no such variable name in this MIB."                                     => :snmp_err_nosuchname,
      "(badValue) The value given has the wrong type or length."                                     => :snmp_err_badvalue,
      "(readOnly) The two parties used do not have access to use the specified SNMP PDU."            => :snmp_err_readonly,
      "(genError) A general failure occured"                                                         => :snmp_err_generr,
      "noAccess"                                                                                     => :snmp_err_noaccess,
      "wrongType (The set datatype does not match the data type the agent expects)"                  => :snmp_err_wrongtype,
      "wrongLength (The set value has an illegal length from what the agent expects)"                => :snmp_err_wronglength,
      "wrongEncoding"                                                                                => :snmp_err_wrongencoding,
      "wrongValue (The set value is illegal or unsupported in some way)"                             => :snmp_err_wrongvalue,
      "noCreation (That table does not support row creation or that object can not ever be created)" => :snmp_err_nocreation,
      "inconsistentValue (The set value is illegal or unsupported in some way)"                      => :snmp_err_inconsistentvalue,
      "resourceUnavailable (This is likely a out-of-memory failure within the agent)"                => :snmp_err_resourceunavailable,
      "commitFailed"                                                                                 => :snmp_err_commitfailed,
      "undoFailed"                                                                                   => :snmp_err_undofailed,
      "authorizationError (access denied to that object)"                                            => :snmp_err_authorizationerror,
      "notWritable (That object does not support modification)"                                      => :snmp_err_notwritable,
      "inconsistentName (That object can not currently be created)"                                  => :snmp_err_inconsistentname
    }[message]
  end

  defp parse_snmp_error(error_line) do
    case String.split(error_line) do
      ["Timeout:"|_] ->
        {:error, :timeout}

      ["Reason:"|reason_words] ->
        cause = reason_words
        |> Enum.join(" ")
        |> get_snmpcmd_error

        {:error, cause}

      [_, "=", "No", "Such", "Object"|_] ->
        {:error, :snmp_nosuchobject}

      [_, "=", "No", "Such", "Instance"|_] ->
        {:error, :snmp_nosuchinstance}

      [_, "=", "No", "more", "variables"|_] ->
        {:error, :snmp_endofmibview}

      _ ->
        nil
    end
  end

  defp parse_snmp_output_line(line) do
    try do
      [oid, _, type_string, value] = String.split(line)

      type = output_type_string_to_type(type_string)

      {:ok, SNMPMIB.object(oid, type, value)}
    rescue
      _ ->
        parse_snmp_error line
    end
  end

  defp parse_snmp_output(output) do
    Logger.debug "Output is '#{inspect output}'"

    output
    |> String.strip
    |> String.split("\n")
    |> Enum.reduce([], fn(line, acc) ->
      if result = parse_snmp_output_line(line) do
        acc ++ [result]
      else
        acc
      end
    end)
  end

  defp columns_and_values_to_data_model(columns, values) do
    for pair <- Enum.zip(columns, values), into: %{}, do: pair
  end

  defp parse_column_headers(headers) do
    headers
    |> String.split("||")
    |> Enum.map(fn header ->
      header
      |> String.downcase
      |> String.to_atom
    end)
  end

  def parse_snmp_table_output(output) do
    try do
      [headers | rows] = output
      |> String.strip
      |> String.split("\n")
      |> Enum.drop(1)
      |> Enum.filter(fn "" -> false; _ -> true end)

      rows
      |> Stream.map(fn row -> String.split(row, "||") end)
      |> Enum.map(fn values ->
        headers
        |> parse_column_headers
        |> columns_and_values_to_data_model(values)
      end)
    rescue
      _ ->
        parse_snmp_error(output)
    end
  end

  defp objects_to_oids(snmp_objects) do
    Enum.map(snmp_objects, fn object ->
      object
      |> SNMPMIB.Object.oid
      |> SNMPMIB.list_oid_to_string
    end)
  end

  defp gen_snmpcmd(:get, snmp_objects, pathname, credential)
      when is_list(snmp_objects) do
    [
      "snmpget -Le -mALL -One",
      credential_to_snmpcmd_args(credential),
      to_string(pathname) | objects_to_oids(snmp_objects)
    ]
    |> Enum.join(" ")
  end
  defp gen_snmpcmd(:set, snmp_objects, pathname, credential)
      when is_list(snmp_objects) do
    [
      "snmpset -Le -mALL -One",
      credential_to_snmpcmd_args(credential),
      to_string(pathname) | (for o <- snmp_objects, do: to_string o)
    ]
    |> Enum.join(" ")
  end
  defp gen_snmpcmd(:table, snmp_object, pathname, credential) do
    [
      "snmptable -Le -mALL -Clbf '||' -Oe",
      credential_to_snmpcmd_args(credential),
      to_string(pathname) | objects_to_oids([snmp_object])
    ]
    |> Enum.join(" ")
  end
  defp gen_snmpcmd(:walk, snmp_object, pathname, credential) do
    [
      "snmpwalk -Le -mALL -One",
      credential_to_snmpcmd_args(credential),
      to_string(pathname) | objects_to_oids([snmp_object])
    ]
    |> Enum.join(" ")
  end

  defp shell_cmd(command) do
    command
    |> :binary.bin_to_list
    |> :os.cmd
    |> :binary.list_to_bin
  end

  def get(snmp_objects, pathname, credential) when is_list(snmp_objects) do
    gen_snmpcmd(:get, snmp_objects, pathname, credential)
    |> shell_cmd
    |> parse_snmp_output
  end
  def get(snmp_object, pathname, credential) do
    get [snmp_object], pathname, credential
  end

  def set(snmp_objects, pathname, credential) when is_list(snmp_objects) do
    gen_snmpcmd(:set, snmp_objects, pathname, credential)
    |> shell_cmd
    |> parse_snmp_output
  end
  def set(snmp_object, pathname, credential) do
    set [snmp_object], pathname, credential
  end

  def table(snmp_objects, pathname, credential) when is_list(snmp_objects) do
    snmp_objects
    |> Enum.map(fn object -> table(object, pathname, credential) end)
    |> List.flatten
  end
  def table(snmp_object, pathname, credential) do
    gen_snmpcmd(:table, snmp_object, pathname, credential)
    |> shell_cmd
    |> parse_snmp_table_output
  end

  def walk(snmp_objects, pathname, credential) when is_list(snmp_objects) do
    snmp_objects
    |> Enum.map(fn object -> walk(object, pathname, credential) end)
    |> List.flatten
  end
  def walk(snmp_object, pathname, credential) do
    gen_snmpcmd(:walk, snmp_object, pathname, credential)
    |> shell_cmd
    |> parse_snmp_output
  end
end

defimpl String.Chars, for: Pathname do
  import Kernel, except: [to_string: 1]

  def to_string(pathname) do
    transport_spec = pathname
    |> Pathname.protocol
    |> Kernel.to_string

    transport_addr = Pathname.address(pathname)

    transport_port = Pathname.protocol_params(pathname)[:port]
    |> Kernel.to_string

    [transport_spec, transport_addr, transport_port]
    |> Enum.join(":")
    |> String.strip(?:)
  end
end
