#!/bin/sh
# HMAProxyPool build (Linux / macOS)
set -e
cd "$(dirname "$0")"
echo "== HMAProxyPool build =="
go build -o hmaproxypool .
echo "Built: ./hmaproxypool"
echo "Run:   ./hmaproxypool   (opens http://127.0.0.1:8899)"
