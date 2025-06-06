# -*- coding: utf-8 -*-
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/binary-inspector for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os

from commoncode.testcase import FileDrivenTesting
from scancode.cli_test_utils import check_json_scan
from scancode.cli_test_utils import run_scan_click
from scancode_config import REGEN_TEST_FIXTURES

test_env = FileDrivenTesting()
test_env.test_data_dir = os.path.join(os.path.dirname(__file__), "data")


def test_scancode_plugin_with_winpe_symbol_option():
    test_file = test_env.get_test_loc("winpe/TranslucentTB-setup.exe")
    result_file = test_env.get_temp_file("json")
    args = ["--winpe-symbol", test_file, "--json", result_file]
    run_scan_click(args)
    expected = test_env.get_test_loc("winpe/TranslucentTB-symbols-plugin.json")
    check_json_scan(expected, result_file, regen=True)


def test_scancode_plugin_with_macho_symbol_option():
    test_file = test_env.get_test_loc("macho/Lumen")
    result_file = test_env.get_temp_file("json")
    args = ["--macho-symbol", test_file, "--json", result_file]
    run_scan_click(args)
    expected = test_env.get_test_loc("macho/Lumen-symbols-plugin.json")
    check_json_scan(expected, result_file, regen=True)
