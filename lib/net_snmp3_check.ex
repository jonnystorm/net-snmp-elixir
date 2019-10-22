defmodule NetSNMP3Check do
  @moduledoc false

  import NetSNMP3

  # Trigger success typing in NetSNMP3 module
  #
  def check do
    _ =
      with [%{}|_] = rows <-
             %{uri: URI.parse("snmp://192.0.2.1"),
               context: "",
               credential: %{version: "2", community: "c"},
               varbinds: [
                 %{oid: ".1.1.1.1.1.1.1.1.1", type: :table, value: nil},
               ],
             }
             |> request
      do
        rows
      else
        e ->
          e
      end
  end
end
