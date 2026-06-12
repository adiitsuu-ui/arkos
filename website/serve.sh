#!/usr/bin/env bash
exec python3 -m http.server 8080 --directory "$(dirname "$0")"
