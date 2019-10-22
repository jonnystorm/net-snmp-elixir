#!/bin/bash

function run
{
  mix clean &&
    env MIX_ENV=test ERL_COMPILER_OPTIONS=bin_opt_info \
      mix compile --force &&
    mix test \
      --include integrated \
      --include expensive &&
    mix dialyzer.build &&
    mix dialyzer --halt-exit-status
}

clear
run

while true
do
  inotifywait --exclude \..*\.sw. -re modify .
  clear
  run
done
