# Copyright © 2015 Jonathan Storm <the.jonathan.storm@gmail.com>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING.WTFPL file for more details.

defmodule NetSNMP do
  @moduledoc """
  A Net-SNMP library supporting SNMPv1/2c/3.
  """

  alias NetSNMP.Parse

  @doc """
  Returns a keyword list containing the given SNMPv1/2c/3
  credentials.

  ## Examples

      iex> NetSNMP.credential [:v1, "public"]
      [version: "1", community: "public"]

      iex> NetSNMP.credential [:v2c, "public"]
      [version: "2c", community: "public"]

      iex> NetSNMP.credential [:v3, :no_auth_no_priv, "user"]
      [version: "3", sec_level: "noAuthNoPriv", sec_name: "user"]

      iex> NetSNMP.credential [:v3, :auth_no_priv, "user", :sha, "authpass"]
      [ version: "3",
        sec_level: "authNoPriv",
        sec_name: "user",
        auth_proto: "sha", auth_pass: "authpass"
      ]

      iex> NetSNMP.credential [:v3, :auth_priv, "user", :sha, "authpass", :aes, "privpass"]
      [ version: "3",
        sec_level: "authPriv",
        sec_name: "user",
        auth_proto: "sha", auth_pass: "authpass",
        priv_proto: "aes", priv_pass: "privpass"
      ]
  """
  @spec credential(list)
    :: Keyword.t
  def credential(args) do
    case args do
      [:v1, _] ->
        apply(&credential/2, args)

      [:v2c, _] ->
        apply(&credential/2, args)

      [:v3, :no_auth_no_priv, _] ->
        apply(&credential/3, args)

      [:v3, :auth_no_priv, _, _, _] ->
        apply(&credential/5, args)

      [:v3, :auth_priv, _, _, _, _, _] ->
        apply(&credential/7, args)
    end
  end

  @doc """
  Returns a keyword list containing the given SNMPv1/2c
  community.

  ## Examples

      iex> NetSNMP.credential :v1, "public"
      [version: "1", community: "public"]

      iex> NetSNMP.credential :v2c, "public"
      [version: "2c", community: "public"]
  """
  @spec credential(:v1|:v2c, String.t)
    :: Keyword.t
  def credential(version, community)

  def credential(:v1, community) do
    [ version: "1",
      community: community,
    ]
  end

  def credential(:v2c, community) do
    [ version: "2c",
      community: community,
    ]
  end

  @doc """
  Returns a keyword list containing the given SNMPv3
  noAuthNoPriv credentials.

  ## Examples

      iex> NetSNMP.credential :v3, :no_auth_no_priv, "user"
      [version: "3", sec_level: "noAuthNoPriv", sec_name: "user"]
  """
  @spec credential(:v3, :no_auth_no_priv, String.t)
    :: Keyword.t
  def credential(version, sec_level, sec_name)

  def credential(:v3, :no_auth_no_priv, sec_name) do
    [ version: "3",
      sec_level: "noAuthNoPriv",
      sec_name: sec_name,
    ]
  end

  @doc """
  Returns a keyword list containing the given SNMPv3
  authNoPriv credentials.

  ## Examples

      iex> NetSNMP.credential :v3, :auth_no_priv, "user", :sha, "authpass"
      [ version: "3",
        sec_level: "authNoPriv",
        sec_name: "user",
        auth_proto: "sha", auth_pass: "authpass"
      ]
  """
  @spec credential(
    :v3,
    :auth_no_priv,
    String.t,
    :md5|:sha,
    String.t
  ) :: Keyword.t

  def credential(
    version,
    sec_level,
    sec_name,
    auth_proto,
    auth_pass
  )

  def credential(
      :v3,
      :auth_no_priv,
      sec_name,
      auth_proto,
      auth_pass
  ) when auth_proto in [:md5, :sha]
  do
    [ version: "3",
      sec_level: "authNoPriv",
      sec_name: sec_name,
      auth_proto: to_string(auth_proto),
      auth_pass: auth_pass,
    ]
  end

  @doc """
  Returns a keyword list containing the given SNMPv3
  authPriv credentials.

  ## Examples

      iex> NetSNMP.credential :v3, :auth_priv, "user", :sha, "authpass", :aes, "privpass"
      [ version: "3",
        sec_level: "authPriv",
        sec_name: "user",
        auth_proto: "sha", auth_pass: "authpass",
        priv_proto: "aes", priv_pass: "privpass"
      ]
  """
  @spec credential(
    :v3,
    :auth_priv,
    String.t,
    :md5|:sha,
    String.t,
    :des|:aes,
    String.t
  ) :: Keyword.t

  def credential(
    version,
    sec_level,
    sec_name,
    auth_proto,
    auth_pass,
    priv_proto,
    priv_pass
  )

  def credential(
      :v3,
      :auth_priv,
      sec_name,
      auth_proto,
      auth_pass,
      priv_proto,
      priv_pass
  ) when auth_proto in [:md5, :sha]
     and priv_proto in [:des, :aes]
  do
    [ version: "3",
      sec_level: "authPriv",
      sec_name: sec_name,
      auth_proto: to_string(auth_proto),
      auth_pass: auth_pass,
      priv_proto: to_string(priv_proto),
      priv_pass: priv_pass,
    ]
  end

  defp _credential_to_args([], acc),
    do: acc |> Enum.reverse |> Enum.join(" ")

  defp _credential_to_args([{:version, v}|tail], acc),
    do: _credential_to_args(tail, ["-v #{v}"] ++ acc)

  defp _credential_to_args([head|tail], acc) do
    arg =
      case head do
        {:community,  v} -> "-c '#{v}'"
        {:sec_level,  v} -> "-l #{v}"
        {:sec_name,   v} -> "-u '#{v}'"
        {:auth_proto, v} -> "-a #{v}"
        {:auth_pass,  v} -> "-A '#{v}'"
        {:priv_proto, v} -> "-x #{v}"
        {:priv_pass,  v} -> "-X '#{v}'"
      end

    _credential_to_args(tail, [arg|acc])
  end

  defp credential_to_args(credential),
    do: _credential_to_args(credential, [])

  defp uri_to_agent_string(uri),
    do: "udp:#{uri.host}:#{uri.port || 161}"

  defp objects_to_oids(objects) do
    Enum.map objects, fn object ->
      object
      |> SNMPMIB.Object.oid
      |> SNMPMIB.list_oid_to_string
    end
  end

  defp get_field_delimiter,
    do: Application.get_env(:net_snmp_ex, :field_delimiter)

  defp get_max_repetitions,
    do: Application.get_env(:net_snmp_ex, :max_repetitions)

  defp gen_snmpcmd(:get, objects, uri, credential, context)
  do
    [ "snmpget -Le -mALL -OUnet -n '#{context}'",
      credential_to_args(credential),
      uri_to_agent_string(uri)
    | objects_to_oids(objects)
    ] |> Enum.join(" ")
  end

  defp gen_snmpcmd(:set, objects, uri, credential, context)
  do
    [ "snmpset -Le -mALL -OUnet -n '#{context}'",
      credential_to_args(credential),
      uri_to_agent_string(uri)
    | Enum.map(objects, &to_string/1)
    ] |> Enum.join(" ")
  end

  defp gen_snmpcmd(:walk, object, uri,  credential, context)
  do
    [ "snmpwalk -Le -mALL -OUnet -n '#{context}'",
      credential_to_args(credential),
      uri_to_agent_string(uri)
    | objects_to_oids([object])
    ] |> Enum.join(" ")
  end

  defp gen_snmpcmd(:table, object, uri, credential, context)
  do
    max_reps = get_max_repetitions()
    delim = get_field_delimiter()

    [ "snmptable -Le -mALL -Cr #{max_reps}",
      "-Clibf '#{delim}' -OXUet -n '#{context}'",
      credential_to_args(credential),
      uri_to_agent_string(uri)
    | objects_to_oids([object])
    ] |> Enum.join(" ")
  end

  defp shell_cmd(command) do
    command
    |> :binary.bin_to_list
    |> :os.cmd
    |> :binary.list_to_bin
  end

  defp do_snmpcmd(
      command,
      objects,
      uri,
      credential,
      context
  ) when command in [:get, :set, :walk]
  do
    command
    |> gen_snmpcmd(objects, uri, credential, context)
    |> shell_cmd
    |> Parse.parse_snmp_output
  end

  # TODO: When URI.parse receives a bare IP, it puts this in
  #   :path rather than :host. Since we rely on :host, we
  #   shouldn't accept a %{host: nil}. Since the API is
  #   showing cracks (SNMPMIB), queue this up for later.

  @doc """
  Send SNMPGET request to `uri` for given objects and
  credentials.
  """
  def get(object, uri, credential, context \\ "")

  def get(objects, uri, credential, context)
      when is_list(objects),
  do: do_snmpcmd(:get, objects, uri, credential, context)

  def get(object, uri, credential, context),
    do: get([object], uri, credential, context)

  @doc """
  Send SNMPSET request to `uri` for given objects and
  credentials.
  """
  def set(object, uri, credential, context \\ "")

  def set(objects, uri, credential, context)
      when is_list(objects),
  do: do_snmpcmd(:set, objects, uri, credential, context)

  def set(object, uri, credential, context),
    do: set([object], uri, credential, context)

  @doc """
  Perform SNMP table operations against `uri` for given
  objects and credentials.
  """
  def table(object, uri, credential, context \\ "")

  def table(objects, uri, credential, context)
      when is_list objects
  do
    objects
    |> Enum.map(&table(&1, uri, credential, context))
    |> List.flatten
  end

  def table(object, uri, credential, context) do
    :table
    |> gen_snmpcmd(object, uri, credential, context)
    |> shell_cmd
    |> Parse.parse_snmp_table_output
  end

  @doc """
  Send SNMPGETNEXT requests to `uri`, starting at given
  objects, with given credentials.
  """
  def walk(object, uri, credential, context \\ "")

  def walk(objects, uri, credential, context)
      when is_list objects
  do
    objects
    |> Enum.map(&walk(&1, uri, credential, context))
    |> List.flatten
  end

  def walk(object, uri, credential, context),
    do: do_snmpcmd(:walk, object, uri, credential, context)
end

