# Copyright © 2015 Jonathan Storm <the.jonathan.storm@gmail.com>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING.WTFPL file for more details.

defmodule NetSNMP.Parse do
  @moduledoc false

  require Logger

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
        ~r|add_mibdir: strings scanned in from .*/.* |,
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
        ~r"^Expected a closing parenthesis",
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
        :snmp_err_noerror,
      "(tooBig) Response message would have been too large." =>
        :snmp_err_toobig,
      "(noSuchName) There is no such variable name in this MIB." =>
        :snmp_err_nosuchname,
      "(badValue) The value given has the wrong type or length." =>
        :snmp_err_badvalue,
      "(readOnly) The two parties used do not have access to use the specified SNMP PDU." =>
        :snmp_err_readonly,
      "(genError) A general failure occured" =>
        :snmp_err_generr,
      "noAccess" =>
        :snmp_err_noaccess,
      "wrongType" =>
        :snmp_err_wrongtype,
      "wrongLength" =>
        :snmp_err_wronglength,
      "wrongEncoding" =>
        :snmp_err_wrongencoding,
      "wrongValue" =>
        :snmp_err_wrongvalue,
      "noCreation" =>
        :snmp_err_nocreation,
      "inconsistentValue" =>
        :snmp_err_inconsistentvalue,
      "resourceUnavailable" =>
        :snmp_err_resourceunavailable,
      "commitFailed" =>
        :snmp_err_commitfailed,
      "undoFailed" =>
        :snmp_err_undofailed,
      "authorizationError" =>
        :snmp_err_authorizationerror,
      "notWritable" =>
        :snmp_err_notwritable,
      "inconsistentName" =>
        :snmp_err_inconsistentname,
      "Unknown Error" =>
        :snmp_err_unknown
    }[message]
  end

  defp get_snmp_api_error(message) do
    # Messages taken from `api_errors` in
    #   `snmplib/snmp_api.c`.
    %{"No error" =>
        :snmperr_success,
      "Generic error" =>
        :snmperr_generr,
      "Invalid local port" =>
        :snmperr_bad_locport,
      "Unknown host" =>
        :snmperr_bad_address,
      "Unknown session" =>
        :snmperr_bad_session,
      "Too long" =>
        :snmperr_too_long,
      "No socket" =>
        :snmperr_no_socket,
      "Cannot send V2 PDU on V1 session" =>
        :snmperr_v2_in_v1,
      "Cannot send V1 PDU on V2 session" =>
        :snmperr_v1_in_v2,
      "Bad value for non-repeaters" =>
        :snmperr_bad_repeaters,
      "Bad value for max-repetitions" =>
        :snmperr_bad_repetitions,
      "Error building ASN.1 representation" =>
        :snmperr_bad_asn1_build,
      "Failure in sendto" =>
        :snmperr_bad_sendto,
      "Bad parse of ASN.1 type" =>
        :snmperr_bad_parse,
      "Bad version specified" =>
        :snmperr_bad_version,
      "Bad source party specified" =>
        :snmperr_bad_src_party,
      "Bad destination party specified" =>
        :snmperr_bad_dst_party,
      "Bad context specified" =>
        :snmperr_bad_context,
      "Bad community specified" =>
        :snmperr_bad_community,
      "Cannot send noAuth/Priv" =>
        :snmperr_noauth_despriv,
      "Bad ACL definition" =>
        :snmperr_bad_acl,
      "Bad Party definition" =>
        :snmperr_bad_party,
      "Session abort failure" =>
        :snmperr_abort,
      "Unknown PDU type" =>
        :snmperr_unknown_pdu,
      "Timeout" =>
        :snmperr_timeout,
      "Failure in recvfrom" =>
        :snmperr_bad_recvfrom,
      "Unable to determine contextEngineID" =>
        :snmperr_bad_eng_id,
      "No securityName specified" =>
        :snmperr_bad_sec_name,
      "Unable to determine securityLevel" =>
        :snmperr_bad_sec_level,
      "ASN.1 parse error in message" =>
        :snmperr_asn_parse_err,
      "Unknown security model in message" =>
        :snmperr_unknown_sec_model,
      "Invalid message" =>
        :snmperr_invalid_msg,
      "Unknown engine ID" =>
        :snmperr_unknown_eng_id,
      "Unknown user name" =>
        :snmperr_unknown_user_name,
      "Unsupported security level" =>
        :snmperr_unsupported_sec_level,
      "Authentication failure" =>
        :snmperr_authentication_failure,
      "Not in time window" =>
        :snmperr_not_in_time_window,
      "Decryption error" =>
        :snmperr_decryption_err,
      "SCAPI general failure" =>
        :snmperr_sc_general_failure,
      "SCAPI sub-system not configured" =>
        :snmperr_sc_not_configured,
      "Key tools not available" =>
        :snmperr_kt_not_available,
      "Unknown Report message" =>
        :snmperr_unknown_report,
      "USM generic error" =>
        :snmperr_usm_genericerror,
      "USM unknown security name" =>
        :snmperr_usm_unknownsecurityname,
      "USM unsupported security level" =>
        :snmperr_usm_unsupportedsecuritylevel,
      "USM encryption error" =>
        :snmperr_usm_encryptionerror,
      "USM authentication failure" =>
        :snmperr_usm_authenticationfailure,
      "USM parse error" =>
        :snmperr_usm_parseerror,
      "USM unknown engineID" =>
        :snmperr_usm_unknownengineid,
      "USM not in time window" =>
        :snmperr_usm_notintimewindow,
      "USM decryption error" =>
        :snmperr_usm_decryptionerror,
      "MIB not initialized" =>
        :snmperr_nomib,
      "Value out of range" =>
        :snmperr_range,
      "Sub-id out of range" =>
        :snmperr_max_subid,
      "Bad sub-id in object identifier" =>
        :snmperr_bad_subid,
      "Object identifier too long" =>
        :snmperr_long_oid,
      "Bad value name" =>
        :snmperr_bad_name,
      "Bad value notation" =>
        :snmperr_value,
      "Unknown Object Identifier" =>
        :snmperr_unknown_objid,
      "No PDU in snmp_send" =>
        :snmperr_null_pdu,
      "Missing variables in PDU" =>
        :snmperr_no_vars,
      "Bad variable type" =>
        :snmperr_var_type,
      "Out of memory (malloc failure)" =>
        :snmperr_malloc,
      "Kerberos related error" =>
        :snmperr_krb5,
      "Protocol error" =>
        :snmperr_protocol,
      "OID not increasing" =>
        :snmperr_oid_nonincreasing,
      "Context probe" =>
        :snmperr_just_a_context_probe,
      "Configuration data found but the transport can't be configured" =>
        :snmperr_transport_no_config,
      "Transport configuration failed" =>
        :snmperr_transport_config_error
    }[message]
  end

  defp parse_snmp_error(error_line) do
    error_words =
      error_line
      |> String.split(" (")
      |> List.first
      |> String.split

    case error_words do
      ["Timeout:" | _] ->
        {:error, :etimedout}

      ["Reason:" | reason_words] ->
        reason =
          reason_words
          |> Enum.join(" ")
          |> get_snmp_client_error

        {:error, reason}

      [_, "=", "No", "Such", "Object"|_] ->
        {:error, :snmp_nosuchobject}

      [_, "=", "No", "Such", "Instance"|_] ->
        {:error, :snmp_nosuchinstance}

      [_, "=", "No", "more", "variables"|_] ->
        {:error, :snmp_endofmibview}

      ["Was", "that", "a", "table?"|_] ->
        {:error, :was_that_a_table?}

      [_, "No", "entries"] ->
        []

      [program|reason_words]
          when program in [
            "snmpget:",
            "snmpset:",
            "snmpwalk:",
            "snmptable:"
          ]
      ->
        reason_string = Enum.join(reason_words, " ")
        reason =
          get_snmp_api_error reason_string

        if reason |> is_nil do
          :ok = Logger.warn "Received unknown error: '#{reason_string}'"
        end

        {:error, reason}

      _ ->
        unknown = Enum.join(error_words, " ")

        :ok = Logger.debug "Received something we didn't understand: '#{unknown}'"

        nil
    end
  end

  defp parse_snmp_output_line(line) do
    try do
      case String.split(line, " ", parts: 3) do
        [oid, "=", "\"\""] ->
          {oid, :string, ""}

        [oid, "=", typed_value] ->
          {type, value} =
            case String.split(typed_value, ": ", parts: 2)
            do
              [type_string, value] ->
                type = type_string_to_type type_string

                {type, value}

              [value] ->
                # Assume bare value is timetick.
                # Explode if it can't be parsed as integer.
                #
                _ = String.to_integer value

                {:timeticks, value}
            end

          formatted_value =
            String.replace(value, ~r/^"|"$/, "")

          {oid, type, formatted_value}
      end
    rescue
      _ ->
        parse_snmp_error line
    end
  end

  defp otv_tuple_to_object_kw_list({}),
    do: []

  defp otv_tuple_to_object_kw_list({oid, type, value}),
    do: [ok: SNMPMIB.object(oid, type, value)]

  defp append_line_to_otv_tuple({}, _line),
    do: {}

  defp append_line_to_otv_tuple({oid, type, value}, line),
    do: {oid, type, "#{value}\n#{line}"}

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
  defp _parse_snmp_output([], {{}, acc}),
    do: acc

  defp _parse_snmp_output([], {otv_tuple, acc}),
    do: acc ++ otv_tuple_to_object_kw_list(otv_tuple)

  defp _parse_snmp_output([line|rest], {otv_tuple, acc}) do
    next_state =
      case parse_snmp_output_line(line) do
        [] ->
          {otv_tuple, acc}

        {:error, :mib_parse_error} ->
          {otv_tuple, acc}

        {:error, _} = error ->
          {{}, acc ++ [error]}

        {_oid, _type, _value} = result ->
          kw_list = otv_tuple_to_object_kw_list otv_tuple

          {result, acc ++ kw_list}

        nil ->
          next_otv_tuple =
            append_line_to_otv_tuple(otv_tuple, line)

          {next_otv_tuple, acc}
      end

    _parse_snmp_output(rest, next_state)
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
    |> _parse_snmp_output({{}, []})
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
      192.0.2.0||255.255.255.252||0||0.0.0.0||2||3||2||170234||SNMPv2-SMI::zeroDotZero||0||0||-1||-1||-1||-1||1

  becomes

      [%{age: "173609", dest: "192.0.2.0", ifindex: "2",
         info: "SNMPv2-SMI::zeroDotZero", mask: "255.255.255.252", metric1: "0",
         metric2: "-1", metric3: "-1", metric4: "-1", metric5: "-1",
         nexthop: "0.0.0.0", nexthopas: "0", proto: "2", status: "1", tos: "0",
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
      |> debug_inline(&"Scrubbed output is: '#{Enum.join(&1, "\n")}'")

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
