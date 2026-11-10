#!/bin/sh
# HMAProxyPool build (Linux / macOS)
set -e
cd "$(dirname "$0")"
echo "== HMAProxyPool build =="
# -trimpath keeps local paths out of the binary, -s -w drops debug info.
go build -trimpath -ldflags "-s -w" -o hmaproxypool .
echo "Built: ./hmaproxypool"
echo "Run:   ./hmaproxypool   (opens http://127.0.0.1:8899)"