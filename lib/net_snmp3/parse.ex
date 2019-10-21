# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

defmodule NetSNMP3.Parse do
  @moduledoc false

  require Logger

  def oid_list_to_string(oid_list)
      when is_list oid_list
  do
    Enum.join(oid_list, ".")
  end

  def oid_list_to_string(term),
    do: term

  def oid_string_to_list(oid_string)
      when is_binary oid_string
  do
    oid_string
    |> String.split(".", trim: true)
    |> Enum.map(&String.to_integer/1)
  end

  def oid_string_to_list(term),
    do: term

  defp cast_value_to_type(nil),
    do: nil

  defp cast_value_to_type(varbind) do
    case varbind.type do
      type when type in [
        :integer,
        :counter32,
        :unsigned32,
        :gauge32,
        :time_ticks,
        :counter64,
        :unsigned64,
      ] ->
        %{varbind |
          value: String.to_integer(varbind.value),
        }

      :ip_address ->
        result =
          varbind.value
          |> :binary.bin_to_list
          |> :inet.ip

        case result do
          {:ok, next_value} ->
            %{varbind|value: next_value}

          _ ->
            :ok = Logger.warn "Unable to cast value #{inspect varbind.value} to type IpAddress"

            varbind
        end

      :oid ->
        result =
          varbind.value
          |> String.trim_leading(".")
          |> String.split(".")
          |> Enum.map(&String.to_integer/1)

        %{varbind|value: result}

      _ ->
        varbind
    end
  end

  # "STRING:"          -> :string
  # "Counter32:"       -> :counter32
  # "Network Address:" -> :network_address
  # "Hex-STRING:"      -> :hex_string
  # et cetera
  defp type_string_to_type(type_string) do
    type_string
    |> String.replace(~r/:$/, "")
    |> String.replace(["-", " "], "_")
    |> String.downcase
    |> String.to_atom
  end

  defp get_mib_parse_error(message) do
    # Messages taken from `snmplib/parse.c`.
    #
    messages =
      [ ~r/is a reserved word/,
        ~r/.* (EOF): At line \d* in .*/,
        ~r/.* (.*): At line \d* in .*/,
        ~r/.*: At line \d* in .*/,
        ~r/MIB search path: .*/,
        ~r/Can't find .* in tbuckets/,
        ~r/Can't find .* in .*'s children/,
        ~r/Warning: .*.\d* is both .* and .* (.*)/,
        ~r/Warning: .*.\d* is both .* and .* (.*)/,
        ~r/Warning: expected anonymous node (either .* or .*) in .*/,
        ~r/Did not find '.*' in module .* (.*)/,
        ~r/Unlinked OID in .*: .* ::= { .* \d* }/,
        ~r/Undefined identifier: .* near line \d* of .*/,
        ~r/Warning: Upper bound not handled correctly (.* != \d*): At line \d* in .*/,
        ~r/.* MACRO (lines \d*..\d* parsed and ignored)./,
        ~r/Loading replacement module .* for .* (.*)/,
        ~r/Importing .* from replacement module .* instead of .* (.*)/,
        ~r/Cannot adopt OID in .*: .* ::= { .* \d* }/,
        ~r/Warning: Module .* was in .* now is .*/,
        ~r"add_mibdir: strings scanned in from .*/.* ",
        ~r/Failed to parse MIB file .*/,
        ~r/failed to allocated memory for gpMibErrorString/,
        ~r/^Attempt to define a root oid/,
        ~r/^Bad ACCESS/,
        ~r/^Bad ACCESS type/,
        ~r/^Bad AUGMENTS list/,
        ~r/^Bad CONTACT-INFO/,
        ~r/^Bad day in timestamp/,
        ~r/^Bad DEFAULTVALUE/,
        ~r/^Bad DESCRIPTION/,
        ~r/^Bad format/,
        ~r/^Bad format for OBJECT-TYPE/,
        ~r/^Bad format of optional clauses/,
        ~r/^Bad group name/,
        ~r/^Bad hour in timestamp/,
        ~r/^Bad identifier/,
        ~r/^Bad INDEX list/,
        ~r/^Bad MIN-ACCESS spec/,
        ~r/^Bad minute in timestamp/,
        ~r/^Bad module name/,
        ~r/^Bad month in timestamp/,
        ~r/^Bad object identifier/,
        ~r/^Bad Object Identifier/,
        ~r/^Bad object name/,
        ~r/^Bad object name in list/,
        ~r/^Bad OBJECTS list/,
        ~r/^Bad operator/,
        ~r/^Bad ORGANIZATION/,
        ~r/^Bad parse of AGENT-CAPABILITIES/,
        ~r/^Bad parse of MACRO/,
        ~r/^Bad parse of MODULE-COMPLIANCE/,
        ~r/^Bad parse of MODULE-IDENTITY/,
        ~r/^Bad parse of NOTIFICATION-GROUP/,
        ~r/^Bad parse of NOTIFICATION-TYPE/,
        ~r/^Bad parse of OBJECT-GROUP/,
        ~r/^Bad parse of OBJECT IDENTIFIER/,
        ~r/^Bad parse of OBJECT-IDENTITY/,
        ~r/^Bad parse of OBJECT-TYPE/,
        ~r/^Bad parse of TRAP-TYPE/,
        ~r/^Bad REFERENCE/,
        ~r/^Bad REVISION/,
        ~r/^Bad SIZE syntax/,
        ~r/^Bad STATUS/,
        ~r/^Bad STATUS value/,
        ~r/^Bad syntax/,
        ~r/^Bad timestamp format/,
        ~r/^Bad timestamp format \(11 or 13 characters\)/,
        ~r/^Bad Trap Format/,
        ~r/^Bad UNITS/,
        ~r/^Bad VARIABLES list/,
        ~r/^Cannot find module/,
        ~r/^Cannot have both INDEX and AUGMENTS/,
        ~r/^DESCRIPTION must be string/,
        ~r/^DISPLAY-HINT must be string/,
        ~r/^Error, END before start of MIB/,
        ~r/^Error, nested MIBS/,
        ~r/^Expected "::="/,
        ~r/^Expected "\("/,
        ~r/^Expected "\)"/,
        ~r/^Expected "\]"/,
        ~r/^Expected "{"/,
        ~r/^Expected "}"/,
        ~r/^Expected a closing parenthesis/,
        ~r/^Expected "{" after DEFVAL/,
        ~r/^Expected "}" after group list/,
        ~r/^Expected "}" after list/,
        ~r/^Expected "\(" after SIZE/,
        ~r/^Expected "\)" after SIZE/,
        ~r/^Expected a number/,
        ~r/^Expected a Number/,
        ~r/^Expected CONTACT-INFO/,
        ~r/^Expected DESCRIPTION/,
        ~r/^Expected group name/,
        ~r/^Expected IDENTIFIER/,
        ~r/^Expected INCLUDES/,
        ~r/^Expected integer/,
        ~r/^Expected label or number/,
        ~r/^Expected LAST-UPDATED/,
        ~r/^Expected MODULE/,
        ~r/^Expected NUMBER/,
        ~r/^Expected ORGANIZATION/,
        ~r/^Expected PRODUCT-RELEASE/,
        ~r/^Expected SIZE/,
        ~r/^Expected STATUS/,
        ~r/^Expected STRING after PRODUCT-RELEASE/,
        ~r/^Expected "\)" to terminate SIZE/,
        ~r/^Group not found in module/,
        ~r/^Missing "}" after DEFVAL/,
        ~r/^Module not found/,
        ~r/^Need STRING for LAST-UPDATED/,
        ~r/^Object not found in module/,
        ~r/^Resource failure/,
        ~r/^Should be ACCESS/,
        ~r/^Should be STATUS/,
        ~r/^STATUS should be current or obsolete/,
        ~r/^Textual convention doesn't map to real type/,
        ~r/^Timestamp should end with Z/,
        ~r/^Too long OID/,
        ~r/^Too many imported symbols/,
        ~r/^Too many textual conventions/,
        ~r/^Unknown group/,
        ~r/^Unknown module/,
        ~r/^Warning: No known translation for type/,
        ~r/^Warning: string too long/,
        ~r/^Warning: This entry is pretty silly/,
        ~r/^Warning: token too long/,
      ]

    if Enum.any?(messages, &String.match?(message, &1)) do
      :mib_parse_error
    end
  end

  defp get_snmp_client_error(message) do
    # Messages taken from `snmp_errstring()` in
    #   `snmplib/snmp_client.c`. Names taken from
    #   `include/net-snmp/library/snmp.h`.
    %{"(noError) No Error" =>
        :no_error,
      "(tooBig) Response message would have been too large." =>
        :too_big,
      "(noSuchName) There is no such variable name in this MIB." =>
        :no_such_name,
      "(badValue) The value given has the wrong type or length." =>
        :bad_value,
      "(readOnly) The two parties used do not have access to use the specified SNMP PDU." =>
        :read_only,
      "(genError) A general failure occured" =>
        :gen_err,
      "noAccess" =>
        :no_access,
      "wrongType" =>
        :wrong_type,
      "wrongLength" =>
        :wrong_length,
      "wrongEncoding" =>
        :wrong_encoding,
      "wrongValue" =>
        :wrong_value,
      "noCreation" =>
        :no_creation,
      "inconsistentValue" =>
        :inconsistent_value,
      "resourceUnavailable" =>
        :resource_unavailable,
      "commitFailed" =>
        :commit_failed,
      "undoFailed" =>
        :undo_failed,
      "authorizationError" =>
        :authorization_error,
      "notWritable" =>
        :not_writable,
      "inconsistentName" =>
        :inconsistent_name,
      "Unknown Error" =>
        :unknown
    }[message]
  end

  defp get_snmp_api_error(message) do
    # Messages taken from `api_errors` in
    #   `snmplib/snmp_api.c`.
    %{"No error" =>
        :success,
      "Generic error" =>
        :generr,
      "Invalid local port" =>
        :bad_locport,
      "Unknown host" =>
        :bad_address,
      "Unknown session" =>
        :bad_session,
      "Too long" =>
        :too_long,
      "No socket" =>
        :no_socket,
      "Cannot send V2 PDU on V1 session" =>
        :v2_in_v1,
      "Cannot send V1 PDU on V2 session" =>
        :v1_in_v2,
      "Bad value for non-repeaters" =>
        :bad_repeaters,
      "Bad value for max-repetitions" =>
        :bad_repetitions,
      "Error building ASN.1 representation" =>
        :bad_asn1_build,
      "Failure in sendto" =>
        :bad_sendto,
      "Bad parse of ASN.1 type" =>
        :bad_parse,
      "Bad version specified" =>
        :bad_version,
      "Bad source party specified" =>
        :bad_src_party,
      "Bad destination party specified" =>
        :bad_dst_party,
      "Bad context specified" =>
        :bad_context,
      "Bad community specified" =>
        :bad_community,
      "Cannot send noAuth/Priv" =>
        :noauth_despriv,
      "Bad ACL definition" =>
        :bad_acl,
      "Bad Party definition" =>
        :bad_party,
      "Session abort failure" =>
        :abort,
      "Unknown PDU type" =>
        :unknown_pdu,
      "Timeout" =>
        :timeout,
      "Failure in recvfrom" =>
        :bad_recvfrom,
      "Unable to determine contextEngineID" =>
        :bad_eng_id,
      "No securityName specified" =>
        :bad_sec_name,
      "Unable to determine securityLevel" =>
        :bad_sec_level,
      "ASN.1 parse error in message" =>
        :asn_parse_err,
      "Unknown security model in message" =>
        :unknown_sec_model,
      "Invalid message" =>
        :invalid_msg,
      "Unknown engine ID" =>
        :unknown_eng_id,
      "Unknown user name" =>
        :unknown_user_name,
      "Unsupported security level" =>
        :unsupported_sec_level,
      "Authentication failure" =>
        :authentication_failure,
      "Not in time window" =>
        :not_in_time_window,
      "Decryption error" =>
        :decryption_err,
      "SCAPI general failure" =>
        :sc_general_failure,
      "SCAPI sub-system not configured" =>
        :sc_not_configured,
      "Key tools not available" =>
        :kt_not_available,
      "Unknown Report message" =>
        :unknown_report,
      "USM generic error" =>
        :usm_genericerror,
      "USM unknown security name" =>
        :usm_unknownsecurityname,
      "USM unsupported security level" =>
        :usm_unsupportedsecuritylevel,
      "USM encryption error" =>
        :usm_encryptionerror,
      "USM authentication failure" =>
        :usm_authenticationfailure,
      "USM parse error" =>
        :usm_parseerror,
      "USM unknown engineID" =>
        :usm_unknownengineid,
      "USM not in time window" =>
        :usm_notintimewindow,
      "USM decryption error" =>
        :usm_decryptionerror,
      "MIB not initialized" =>
        :nomib,
      "Value out of range" =>
        :range,
      "Sub-id out of range" =>
        :max_subid,
      "Bad sub-id in object identifier" =>
        :bad_subid,
      "Object identifier too long" =>
        :long_oid,
      "Bad value name" =>
        :bad_name,
      "Bad value notation" =>
        :value,
      "Unknown Object Identifier" =>
        :unknown_objid,
      "No PDU in snmp_send" =>
        :null_pdu,
      "Missing variables in PDU" =>
        :no_vars,
      "Bad variable type" =>
        :var_type,
      "Out of memory (malloc failure)" =>
        :malloc,
      "Kerberos related error" =>
        :krb5,
      "Protocol error" =>
        :protocol,
      "OID not increasing" =>
        :oid_nonincreasing,
      "Context probe" =>
        :just_a_context_probe,
      "Configuration data found but the transport can't be configured" =>
        :transport_no_config,
      "Transport configuration failed" =>
        :transport_config_error
    }[message]
  end

  defp parse_snmp_error([error_line|rest]) do
    error_words =
      error_line
      |> String.split(" (")
      |> List.first
      |> String.split

    case error_words do
      ["Timeout:"|_] ->
        {:error, :etimedout}

      ["Reason:"|reason_words] ->
        error =
          reason_words
          |> Enum.join(" ")
          |> get_snmp_client_error

        [next_line|rest2] = rest

        ["Failed", "object:", oid_string|_] =
          String.split(next_line)

        oid   = oid_string_to_list(oid_string)
        error = {:error, {error, oid}}

        %{error: error, lines: rest2}

      [object_name, "No", "entries"] ->
        object_name2 =
          String.trim_trailing(object_name, ":")

        {:error, {:no_entries, object_name2}}

      [oid, "=", "No", "Such", "Object"|_] ->
        {:error, {:no_such_object, oid}}

      [oid, "=", "No", "Such", "Instance"|_] ->
        {:error, {:no_such_instance, oid}}

      [oid, "=", "No", "more", "variables"|_] ->
        {:error, {:end_of_mib_view, oid}}

      ["Was", "that", "a", "table?", object_name|_] ->
        {:error, {:was_that_a_table?, object_name}}

      [program|reason_words]
          when program in [
            "snmpget:",
            "snmpset:",
            "snmpwalk:",
            "snmptable:",
          ]
      ->
        reason_string =
          Enum.join(reason_words, " ")

        reason =
          get_snmp_api_error reason_string

        if reason |> is_nil do
          :ok = Logger.warn "Received unknown error: '#{reason_string}'"
        end

        {:error, {:api_error, reason}}

      _ ->
        unknown = Enum.join(error_words, " ")

        :ok = Logger.debug "Received something we didn't understand: '#{unknown}'"

        nil
    end
  end

  defp parse_snmp_output_line([line|rest]) do
    try do
      case String.split(line, " ", parts: 3) do
        [oid, "=", "\"\""] ->
          %{oid:   oid,
            type:  :string,
            value: "",
          }

        [oid, "=", typed_value] ->
          case String.split(typed_value, ": ", parts: 2)
          do
            [type_string, value] ->
              type = type_string_to_type(type_string)

              %{oid:   oid,
                type:  type,
                value: value,
              }

            ["STRING:" = type_string] ->
              # Received empty or whitespace string
              #
              type = type_string_to_type(type_string)

              %{oid:   oid,
                type:  type,
                value: "",
              }

            [value] ->
              # Assume bare value is timetick.
              # Explode if it can't be parsed as integer.
              #
              _ = String.to_integer value

              formatted_value =
                String.replace(value, ~r/^"|"$/, "")

              %{oid:   oid,
                type:  :time_ticks,
                value: formatted_value,
              }
          end
      end
    rescue
      _ ->
        parse_snmp_error([line|rest])
    end
  end

  defp varbind_to_kw_list(nil),
    do: []

  defp varbind_to_kw_list(varbind),
    do: [ok: varbind]

  defp append_line_to_varbind(nil, _line),
    do: nil

  defp append_line_to_varbind(varbind, line) do
    %{varbind |
      value: "#{varbind.value}\n#{line}",
    }
  end

  # Overcomplicated parsing process imbued with fear and
  # uncertainty. Largely a product of having to treat
  # unencapsulated, multi-line output.
  #
  # 1. Try parsing the next line
  #   * If the line is a known error, append it to the
  #     accumulator
  #   * If the line is an oid-type-value tuple, append the
  #     oid-type-value tuple in progress (if there is one)
  #     to the accumulator and begin work on the new
  #     oid-type-value tuple
  #   * Otherwise, assume the line is part of the
  #     oid-type-value tuple in progress (if there is one),
  #     and append the line to the current value
  #
  # 2. When we run out of lines, append the last
  #    oid-type-value tuple (if there is one) and return the
  #    accumulator
  #
  defp _parse_snmp_output([], {nil, acc}),
    do: acc

  defp _parse_snmp_output([], {varbind, acc}) do
    acc ++ (
      varbind
      |> cast_value_to_type
      |> varbind_to_kw_list
    )
  end

  defp _parse_snmp_output([line|rest], {varbind, acc}) do
    case parse_snmp_output_line([line|rest]) do
      {:error, _} = error ->
        next_state = {nil, acc ++ [error]}

        _parse_snmp_output(rest, next_state)

      %{error: error, lines: rest2} ->
        next_state = {nil, acc ++ [error]}

        _parse_snmp_output(rest2, next_state)

      %{oid: _} = new_varbind ->
        kw_list =
          varbind
          |> cast_value_to_type
          |> varbind_to_kw_list

        next_varbind =
          %{new_varbind |
            oid: oid_string_to_list(new_varbind.oid),
          }

        next_state =
          {next_varbind, acc ++ kw_list}

        _parse_snmp_output(rest, next_state)

      nil ->
        next_varbind =
          append_line_to_varbind(varbind, line)

        next_state = {next_varbind, acc}

        _parse_snmp_output(rest, next_state)
    end
  end

  # Output may take any of the following forms and more:
  #
  # .1.3.6.1.2.1.1.1.0 = STRING: Cisco IOS Software, 3700 Software (C3725-ADVENTERPRISEK9-M), Version 12.4(25d), RELEASE SOFTWARE (fc1)
  # Technical Support: http://www.cisco.com/techsupport
  # Copyright (c) 1986-2010 by Cisco Systems, Inc.
  # Compiled Wed 18-Aug-10 07:55 by prod_rel_team
  # .1.3.6.1.2.1.1.2.0 = OID: .1.3.6.1.4.1.9.1.122
  # .1.3.6.1.2.1.1.7.0 = INTEGER: 78
  # .1.3.6.1.2.1.1.8.0 = 0
  #
  @spec parse_snmp_output(String.t)
    :: Keyword.t
  def parse_snmp_output(output) do
    output
    |> debug_inline(& "Output is: '#{&1}'")
    |> scrub_snmp_output
    |> debug_inline(& "Scrubbed output is: '#{Enum.join(&1, "\n")}'")
    |> _parse_snmp_output({nil, []})
  end

  defp debug_inline(output, message_fun) do
    :ok = Logger.debug message_fun.(output)

    output
  end

  def remove_mib_parse_errors(lines) do
    Stream.filter lines,
      (& get_mib_parse_error(&1) |> is_nil)
  end

  defp scrub_snmp_output(output) do
    output
    |> String.replace(~r/^\s*/, "")
    |> String.replace(~r/\s*$/, "")
    |> String.split("\n")
    |> Stream.filter(& &1 != "")
    |> remove_mib_parse_errors
    |> Stream.filter(& ! (&1 =~ ~r/^SNMP table: /))
    |> Enum.into([])
  end

  defp columns_and_values_to_data_model(columns, values) do
    columns
    |> Enum.zip(values)
    |> Enum.into(%{})
  end

  defp parse_column_headers(headers, delim) do
    headers
    |> String.split(delim)
    |> Enum.map(fn header ->
      header
      |> String.downcase
      |> String.to_atom
    end)
  end

  @doc """
      SNMP table: IP-FORWARD-MIB::ipCidrRouteTable

      Dest||Mask||Tos||NextHop||IfIndex||Type||Proto||Age||Info||NextHopAS||Metric1||Metric2||Metric3||Metric4||Metric5||Status
      192.0.2.0||255.255.255.252||0||0.0.0.0||2||3||2||170234||SNMPv2-SMI::zeroDotZero||0||0||-1||-1||-1||-1||?

  becomes

      [%{age: "173609", dest: "192.0.2.0", ifindex: "2",
         info: "SNMPv2-SMI::zeroDotZero", mask: "255.255.255.252", metric1: "0",
         metric2: "-1", metric3: "-1", metric4: "-1", metric5: "-1",
         nexthop: "0.0.0.0", nexthopas: "0", proto: "2", status: "?", tos: "0",
         type: "3"}]
  """
  @spec parse_snmp_table_output(String.t)
    :: [%{}]
  def parse_snmp_table_output(output, field_delim \\ "||")
  do
    [headers|rows] =
      output
      |> debug_inline(& "Output is: '#{&1}'")
      |> scrub_snmp_output
      |> debug_inline(& "Scrubbed output is: '#{Enum.join(&1, "\n")}'")

    cond do
      String.contains?(headers, " ") ->
        [headers|rows]
        |> Enum.join("\n")
        |> parse_snmp_output
        |> List.wrap
        |> List.flatten

      rows == [] ->
        headers
        |> parse_snmp_output
        |> List.wrap
        |> List.flatten

      true ->
        rows
        |> Stream.map(&String.split(&1, field_delim))
        |> Enum.map(fn values ->
          headers
          |> parse_column_headers(field_delim)
          |> columns_and_values_to_data_model(values)
        end)
    end
  end
end
