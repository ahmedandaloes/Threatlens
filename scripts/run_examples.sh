#!/usr/bin/env bash
# Regenerate all sample reports in examples/output (offline, no key needed).
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PY:-python}"
$PY -m threatlens examples/clinic_booking.yaml -o examples/output --offline -q
$PY -m threatlens examples/ecommerce_store.yaml --openapi examples/ecommerce_openapi.yaml -o examples/output --offline -q
$PY -m threatlens examples/hr_payroll_portal.json -o examples/output --offline -q
$PY -m threatlens examples/pharmacy_delivery.txt -o examples/output --offline -q
