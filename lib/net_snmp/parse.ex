# Copyright © 2015 Jonathan Storm <the.jonathan.storm@gmail.com>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING.WTFPL file for more details.

defmodule NetSNMP.Parse do
  require Logger

  @doc """
  "STRING:"          -> :string
  "Counter32:"       -> :counter32
  "Network Address:" -> :network_address
  "Hex-STRING:"      -> :hex_string
                    .
                    .
                    .
  """
  defp output_type_string_to_type(type_string) do
    type_string
      |> String.rstrip(?:)
      |> String.replace(["-", " "], "_")
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
        cause =
          reason_words
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
      [oid, "=", type_string_and_value] = String.split line, " ", parts: 3

      case String.split(type_string_and_value, ": ", parts: 2) do
        [type_string, value] ->
          type = output_type_string_to_type type_string

          {oid, type, value}

        [value] ->
          # Displaying timeticks as a number strips them of their type,
          #   requiring we restore the correct type. To the best of my
          #   knowledge, this is unique to timeticks
          {oid, :timeticks, value}
      end

    rescue
      _ ->
        parse_snmp_error line
    end
  end

  @doc """
  Overcomplicated parsing process imbued with fear and uncertainty. Largely a
  product of having to treat unencapsulated, multi-line output.

  * When not already processing an oid-type-value tuple, try parsing the next line
  ** If the line was a known error, append it to the accumulator
  ** If the line was an oid-type-value tuple, set it aside and process the next line
  ** Otherwise, ignore the line

  * When already processing an oid-type-value tuple, try parsing the next line
  ** If the line was a known error, append it to the accumulator
  ** If the line was an oid-type-value tuple, append the one we were already processing to the accumulator and process the next
  ** Otherwise, assume the line is part of the value for the tuple we're already processing and append it to the current value

  * When we're out of lines, append the last object (if there is one) and return the accumulator
  """
  defp _parse_snmp_output([], {{}, acc}) do
    acc
  end
  defp _parse_snmp_output([], {{oid, type, value}, acc}) do
    object = SNMPMIB.object oid, type, value

    acc ++ [ok: object]
  end
  defp _parse_snmp_output([line|rest], {{}, acc}) do
    case parse_snmp_output_line(line) do
      {:error, _error} = result ->
        _parse_snmp_output rest, {{}, acc ++ [result]}

      {_oid, _type, _value} = result ->
        _parse_snmp_output rest, {result, acc}

      nil ->
        _parse_snmp_output rest, {{}, acc}
    end
  end
  defp _parse_snmp_output([line|rest], {{oid, type, value}, acc}) do
    case parse_snmp_output_line(line) do
      {:error, _error} = result ->
        _parse_snmp_output rest, {{}, acc ++ [result]}

      {_oid, _type, _value} = result ->
        object = SNMPMIB.object oid, type, value

        _parse_snmp_output rest, {result, acc ++ [ok: object]}

      nil ->
        new_value = "#{value}\n#{line}"

        _parse_snmp_output rest, {{oid, type, new_value}, acc}
    end
  end

  @doc """
  Output may take any of the following forms and more:

  .1.3.6.1.2.1.1.1.0 = STRING: Cisco IOS Software, 3700 Software (C3725-ADVENTERPRISEK9-M), Version 12.4(25d), RELEASE SOFTWARE (fc1)
  Technical Support: http://www.cisco.com/techsupport
  Copyright (c) 1986-2010 by Cisco Systems, Inc.
  Compiled Wed 18-Aug-10 07:55 by prod_rel_team
  .1.3.6.1.2.1.1.2.0 = OID: .1.3.6.1.4.1.9.1.122
  .1.3.6.1.2.1.1.7.0 = INTEGER: 78
  .1.3.6.1.2.1.1.8.0 = 0
  """
  @spec parse_snmp_output(String.t) :: Keyword.t
  def parse_snmp_output(output) do
    Logger.debug "Output is '#{output}'"

    output
      |> String.strip
      |> String.split("\n")
      |> _parse_snmp_output({{}, []})
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
  def parse_snmp_table_output(output) do
    try do
      [headers | rows] =
        output
          |> String.strip
          |> String.split("\n")
          |> Enum.drop(1)
          |> Enum.filter(fn "" -> false; _ -> true end)

      rows
        |> Stream.map(&String.split(&1, "||"))
        |> Enum.map(fn values ->
          headers
            |> parse_column_headers
            |> columns_and_values_to_data_model(values)
        end)

    rescue
      _ ->
        parse_snmp_error output
    end
  end
end
