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
  defp output_type_string_to_type(type_string) do
    type_string
      |> String.rstrip(?:)
      |> String.replace(["-", " "], "_")
      |> String.downcase
      |> String.to_atom
  end

  defp get_snmpcmd_error(message) do
    %{"(noError) No Error"                                                                           => :snmp_err_noerror,
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
      ["Timeout:" | _] ->
        {:error, :timeout}

      ["Reason:" | reason_words] ->
        cause =
          reason_words
            |> Enum.join(" ")
            |> get_snmpcmd_error

        {:error, cause}

      [_, "=", "No", "Such", "Object" | _] ->
        {:error, :snmp_nosuchobject}

      [_, "=", "No", "Such", "Instance" | _] ->
        {:error, :snmp_nosuchinstance}

      [_, "=", "No", "more", "variables" | _] ->
        {:error, :snmp_endofmibview}

      ["Was", "that", "a", "table?" | _] ->
        {:error, :was_that_a_table?}

      _ ->
        raise "Unknown error occurred: '#{error_line}'"
    end
  end

  defp parse_snmp_output_line(line) do
    try do
      case String.split line, " ", parts: 3 do
        [oid, "=", type_string_and_value] ->
          case String.split(type_string_and_value, ": ", parts: 2) do
            [type_string, value] ->
              type = output_type_string_to_type type_string

              {oid, type, value}

            [value] ->
              # Displaying timeticks as a number strips them of their type,
              #   requiring we restore the correct type. To the best of my
              #   knowledge, this is unique to timeticks.
              # Regardless, `value` could still be an error, and we need to make
              #   sure it parses to an integer.
              _ = String.to_integer value

              {oid, :timeticks, value}
          end

        _ ->
          nil
      end

    rescue
      _ ->
        parse_snmp_error line
    end
  end

  defp otv_tuple_to_object_kw_list({}), do: []
  defp otv_tuple_to_object_kw_list({oid, type, value}) do
    [ok: SNMPMIB.object(oid, type, value)]
  end

  defp append_line_to_otv_tuple({}, _line), do: {}
  defp append_line_to_otv_tuple({oid, type, value}, line) do
    {oid, type, "#{value}\n#{line}"}
  end

  # Overcomplicated parsing process imbued with fear and uncertainty. Largely a
  # product of having to treat unencapsulated, multi-line output.

  # 1. Try parsing the next line
  #     * If the line is a known error, append it to the accumulator
  #     * If the line is an oid-type-value tuple, append the oid-type-value tuple
  #       in progress (if there is one) to the accumulator and begin work on the
  #       new oid-type-value tuple
  #     * Otherwise, assume the line is part of the oid-type-value tuple in
  #       progress (if there is one), and append the line to the current value

  # 2. When we run out of lines, append the last oid-type-value tuple (if there
  #    is one) and return the accumulator
  #
  defp _parse_snmp_output([], {{}, acc}) do
    acc
  end
  defp _parse_snmp_output([], {otv_tuple, acc}) do
    acc ++ otv_tuple_to_object_kw_list(otv_tuple)
  end
  defp _parse_snmp_output([line | rest], {otv_tuple, acc}) do
    case parse_snmp_output_line(line) do
      {:error, _error} = result ->
        _parse_snmp_output rest, {{}, acc ++ [result]}

      {_oid, _type, _value} = result ->
        kw_list = otv_tuple_to_object_kw_list otv_tuple

        _parse_snmp_output rest, {result, acc ++ kw_list}

      nil ->
        next_otv_tuple = append_line_to_otv_tuple otv_tuple, line

        _parse_snmp_output rest, {next_otv_tuple, acc}
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
  @spec parse_snmp_output(String.t) :: Keyword.t
  def parse_snmp_output(output) do
    :ok = Logger.debug "Output is '#{output}'"

    output
      |> String.strip
      |> String.split("\n")
      |> _parse_snmp_output({{}, []})
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
  @spec parse_snmp_table_output(String.t) :: [Map.t]
  def parse_snmp_table_output(output, field_delim \\ "||") do
    :ok = Logger.debug "Output is '#{output}'"

    try do
      [headers | rows] =
        output
          |> String.strip
          |> String.split("\n")
          |> Enum.drop(1)
          |> Enum.filter(fn "" -> false; _ -> true end)

      rows
        |> Stream.map(&String.split(&1, field_delim))
        |> Enum.map(fn values ->
          headers
            |> parse_column_headers(field_delim)
            |> columns_and_values_to_data_model(values)
        end)

    rescue
      _ ->
        parse_snmp_error output
    end
  end
end
