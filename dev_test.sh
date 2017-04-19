#!/bin/bash

while true; do
  inotifywait --exclude \..*\.sw. -re modify .
  clear
  mix compile &&
    mix test &&
    env MIX_ENV=test mix dialyzer --halt-exit-status
done
