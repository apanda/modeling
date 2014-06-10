#!/bin/bash
for i in {0..5}; do python -u tests/appfw_proxy_scaling.py > $1/appfw_proxy_scaling & done
for i in {0..5}; do python -u tests/appfw_proxy_scaling.py > $1/appfw_proxy_scaling_5 & done
for i in {0..5}; do python -u tests/run_all_concrete.py 20 $1/concrete_raw_5 > $1/concrete_5 & done
for i in {0..5}; do python -u tests/path_length_test.py > $1/path_length_5 & done
for i in {0..5}; do python -u tests/lsrr_scaling_nopartial.py > $1/lsrr_scaling_5 & done
