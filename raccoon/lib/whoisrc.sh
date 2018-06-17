#!/usr/bin/env bash

readonly host="$1"

query () {
    whois "$1" | grep ":"
}

query "$host"