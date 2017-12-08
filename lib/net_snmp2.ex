# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

defmodule NetSNMP2 do
  @moduledoc """
  A Net-SNMP library supporting SNMPv1/2/3.
  """

  alias NetSNMP2.Parse

  @doc """
  Returns a keyword list containing the given SNMPv1/2/3
  credentials.

  ## Examples

      iex> NetSNMP2.credential [:v1, "public"]
      %{version: "1", community: "public"}

      iex> NetSNMP2.credential [:v2, "public"]
      %{version: "2", community: "public"}

      iex> NetSNMP2.credential [:v3, :no_auth_no_priv, "user"]
      %{version: "3",
        sec_level: "noAuthNoPriv",
        sec_name: "user"
      }

      iex> NetSNMP2.credential [:v3, :auth_no_priv, "user", :sha, "authpass"]
      %{version: "3",
        sec_level: "authNoPriv",
        sec_name: "user",
        auth_proto: "sha", auth_pass: "authpass"
      }

      iex> NetSNMP2.credential [:v3, :auth_priv, "user", :sha, "authpass", :aes, "privpass"]
      %{version: "3",
        sec_level: "authPriv",
        sec_name: "user",
        auth_proto: "sha", auth_pass: "authpass",
        priv_proto: "aes", priv_pass: "privpass"
      }
  """
  def credential(args) do
    case args do
      [:v1, _] ->
        apply(&credential/2, args)

      [:v2, _] ->
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
  Returns a keyword list containing the given SNMPv1/2
  community.

  ## Examples

      iex> NetSNMP2.credential :v1, "public"
      %{version: "1", community: "public"}

      iex> NetSNMP2.credential :v2, "public"
      %{version: "2", community: "public"}
  """
  @spec credential(:v1|:v2, binary)
    :: %{version: binary, community: binary}
  def credential(version, community)

  def credential(:v1, community) do
    %{version: "1",
      community: community,
    }
  end

  def credential(:v2, community) do
    %{version: "2",
      community: community,
    }
  end

  @doc """
  Returns a keyword list containing the given SNMPv3
  noAuthNoPriv credentials.

  ## Examples

      iex> NetSNMP2.credential :v3, :no_auth_no_priv, "user"
      %{version: "3",
        sec_level: "noAuthNoPriv",
        sec_name: "user"
      }
  """
  @spec credential(:v3, :no_auth_no_priv, String.t)
    :: %{version:   binary,
         sec_level: binary,
         sec_name:  binary,
       }
  def credential(version, sec_level, sec_name)

  def credential(:v3, :no_auth_no_priv, sec_name) do
    %{version: "3",
      sec_level: "noAuthNoPriv",
      sec_name: sec_name,
    }
  end

  @doc """
  Returns a keyword list containing the given SNMPv3
  authNoPriv credentials.

  ## Examples

      iex> NetSNMP2.credential :v3, :auth_no_priv, "user", :sha, "authpass"
      %{version: "3",
        sec_level: "authNoPriv",
        sec_name: "user",
        auth_proto: "sha", auth_pass: "authpass"
      }
  """
  @spec credential(
    :v3,
    :auth_no_priv,
    binary,
    :md5|:sha,
    binary
  ) :: %{version:    binary,
         sec_level:  binary,
         sec_name:   binary,
         auth_proto: binary,
         auth_pass:  binary,
       }
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
    %{version: "3",
      sec_level: "authNoPriv",
      sec_name: sec_name,
      auth_proto: to_string(auth_proto),
      auth_pass: auth_pass,
    }
  end

  @doc """
  Returns a keyword list containing the given SNMPv3
  authPriv credentials.

  ## Examples

      iex> NetSNMP2.credential :v3, :auth_priv, "user", :sha, "authpass", :aes, "privpass"
      %{version: "3",
        sec_level: "authPriv",
        sec_name: "user",
        auth_proto: "sha", auth_pass: "authpass",
        priv_proto: "aes", priv_pass: "privpass"
      }
  """
  @spec credential(
    :v3,
    :auth_priv,
    binary,
    :md5|:sha,
    binary,
    :des|:aes,
    binary
  ) :: %{version:    binary,
         sec_level:  binary,
         sec_name:   binary,
         auth_proto: binary,
         auth_pass:  binary,
         priv_proto: binary,
         priv_pass:  binary,
       }

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
    %{version: "3",
      sec_level: "authPriv",
      sec_name: sec_name,
      auth_proto: to_string(auth_proto),
      auth_pass: auth_pass,
      priv_proto: to_string(priv_proto),
      priv_pass: priv_pass,
    }
  end

  defp _credential_to_args([], acc) do
    acc
    |> Enum.reverse
    |> Enum.join(" ")
  end

  defp _credential_to_args([{:version, v}|tail], acc) do
    v_arg =
      if v == "2"
      do "2c"
      else v
      end

    _credential_to_args(tail, ["-v #{v_arg}"] ++ acc)
  end

  defp _credential_to_args([head|tail], acc) do
    arg =
      case head do
        {:community,  v} -> "-c '#{v}'"
        {:sec_level,  v} -> "-l  #{v}"
        {:sec_name,   v} -> "-u '#{v}'"
        {:auth_proto, v} -> "-a  #{v}"
        {:auth_pass,  v} -> "-A '#{v}'"
        {:priv_proto, v} -> "-x  #{v}"
        {:priv_pass,  v} -> "-X '#{v}'"
                       _ -> ""
      end

    _credential_to_args(tail, [arg|acc])
  end

  defp credential_to_args(credential) do
    credential
    |> Enum.to_list
    |> _credential_to_args([])
  end

  defp uri_to_agent_string(uri),
    do: "udp:#{uri.host}:#{uri.port || 161}"

  defp varbinds_to_oids(varbinds) do
    Enum.map varbinds, fn varbind ->
      Parse.oid_list_to_string varbind.oid
    end
  end

  defp get_field_delimiter,
    do: Application.get_env(:net_snmp_ex, :field_delimiter)

  defp get_max_repetitions,
    do: Application.get_env(:net_snmp_ex, :max_repetitions)

  defp gen_snmpcmd(%{command: :get} = args) do
    [ "snmpget -Le -mALL -OUnet",
      "-n '#{args.context}'",
      credential_to_args(args.credential),
      uri_to_agent_string(args.uri)
    | varbinds_to_oids(args.varbinds)
    ] |> Enum.join(" ")
  end

  defp gen_snmpcmd(%{command: :set} = args) do
    set_strings =
      Enum.map args.varbinds, fn varbind ->
        oid_string =
          Parse.oid_list_to_string varbind.oid

        "#{oid_string} = #{varbind.value}"
      end

    [ "snmpset -Le -mALL -OUnet",
      "-n '#{args.context}'",
      credential_to_args(args.credential),
      uri_to_agent_string(args.uri)
    | set_strings
    ] |> Enum.join(" ")
  end

  defp gen_snmpcmd(%{command: :walk} = args) do
    [ "snmpwalk -Le -mALL -OUnet",
      "-n '#{args.context}'",
      credential_to_args(args.credential),
      uri_to_agent_string(args.uri)
    | varbinds_to_oids(args.varbinds)
    ] |> Enum.join(" ")
  end

  defp gen_snmpcmd(%{command: :table} = args) do
    max_reps = get_max_repetitions()
    delim    = get_field_delimiter()

    [ "snmptable -Le -mALL -Cr #{max_reps}",
      "-Clibf '#{delim}' -OXUet",
      "-n '#{args.context}'",
      credential_to_args(args.credential),
      uri_to_agent_string(args.uri)
    | varbinds_to_oids(args.varbinds)
    ] |> Enum.join(" ")
  end

  defp shell_cmd(command) do
    command
    |> :binary.bin_to_list
    |> :os.cmd
    |> :binary.list_to_bin
  end

  @type object_id
    :: binary
     | [non_neg_integer]

  @type req_varbind :: %{oid: object_id}
  @type request_args
    :: %{uri: URI.t,
         credential: %{},
         varbinds: [req_varbind],
       }

  @type object_name :: binary
  @type asn1_type   :: atom
  @type asn1_value  :: any
  @type varbind
    :: %{oid:   object_id,
         type:  asn1_type,
         value: asn1_value,
       }

  @type response :: {:ok, varbind}
  @type reason   :: atom | nil
  @type net_snmp_error
    :: {:error, :etimedout}
     | {:error, {   :api_error, reason}}
     | {:error, {:error_status, reason, object_id}}
     | {:error, {:was_that_a_table?, object_name}}

  @doc ~S"""
  Send an SNMP request to GET/SET objects or retrieve a
  table.

  All arguments are passed in a map. The following
  illustrates the minimum required keys.

      %{uri: %URI{scheme: "snmp", host: "192.0.2.1"},
        credential: %{version: "2", community: "public"},
        varbinds: [%{oid: "1.3.6.1.2.1.1.5.0"}],
      }

  The key `:context` may also be included.

  A varbind's structure dictates which request operation to
  perform.

  * A varbind with `:type` set to `:table` is
    interpreted as a table request.
  * A varbind for which `varbind[:value]` returns `nil` is
    interpreted as a GET request unless that varbind's
    `:type` is `:table`.
  * A varbind for which `varbind[:value]` does not return
    `nil` is interpreted as a SET request unless that
    varbind's `:type` is `:table`.


    | %{oid: _, type: :table}             | table request |
    | %{oid: _, type: :table, value: nil} | table request |
    | %{oid: _, type: :table, value:   _} | table request |
    | %{oid: _, value: nil}               | GET request   |
    | %{oid: _, value:   _}               | SET request   |

  """
  @spec request(request_args)
    :: [response|net_snmp_error]
  def request(
    %{varbinds: varbinds,
      uri:      %{host: host},
    } = args
  ) when not is_nil(host)
     and is_list(varbinds)
  do
    varbind_oid_string_to_list =
      fn varbind ->
        %{varbind |
          oid: Parse.oid_string_to_list(varbind.oid),
        }
      end

    varbinds
    |> Enum.map(&varbind_oid_string_to_list.(&1))
    |> Enum.group_by(fn varbind ->
      cond do
        varbind[:type] == :table ->
          :table

        !is_nil(varbind[:value]) ->
          :set

        true ->
          :get
      end
    end)
    |> Enum.flat_map(fn {cmd, cmd_varbinds} ->
      parse_output =
        fn output ->
          if cmd == :table do
            output
            |> Parse.parse_snmp_table_output
          else
            output
            |> Parse.parse_snmp_output
          end
        end

      args
      |> Map.put(:command, cmd)
      |> Map.put(:varbinds, cmd_varbinds)
      |> Map.put(:context, args[:context] || "")
      |> gen_snmpcmd
      |> shell_cmd
      |> parse_output.()
    end)
  end
end
