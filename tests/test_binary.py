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
from scancode.cli_test_utils import check_json
from scancode_config import REGEN_TEST_FIXTURES

from binary_inspector import binary
from binary_inspector.blint_binary import parse_symbols

test_env = FileDrivenTesting()
test_env.test_data_dir = os.path.join(os.path.dirname(__file__), "data")


def test_is_executable_binary_macho():
    macho_binary = test_env.get_test_loc("macho/Lumen")
    assert binary.is_executable_binary(macho_binary)


def test_parse_macho_binary_does_not_fail():
    macho_binary = test_env.get_test_loc("macho/Lumen")
    binary.parse_binary(macho_binary)


def test_parsed_macho_binary_has_symbols():
    macho_binary = test_env.get_test_loc("macho/Lumen")
    parsed_binary = binary.parse_binary(macho_binary)
    assert parsed_binary.symbols


def test_can_parse_and_demangle_macho_binary_symbols():
    macho_binary = test_env.get_test_loc("macho/Lumen")
    macho_symbols = binary.collect_and_parse_macho_symbols(macho_binary)
    expected = test_env.get_test_loc("macho/Lumen-symbols.json")
    check_json(expected, macho_symbols, regen=REGEN_TEST_FIXTURES)


def test_is_executable_binary_winpe():
    winpe_binary = test_env.get_test_loc("winpe/TranslucentTB-setup.exe")
    assert binary.is_executable_binary(winpe_binary)


def test_parse_macho_binary_does_not_fail():
    winpe_binary = test_env.get_test_loc("winpe/TranslucentTB-setup.exe")
    binary.parse_binary(winpe_binary)


def test_parsed_macho_binary_has_symbols():
    winpe_binary = test_env.get_test_loc("winpe/TranslucentTB-setup.exe")
    parsed_binary = binary.parse_binary(winpe_binary)
    assert parsed_binary.symbols or parsed_binary.imports


def test_can_parse_and_demangle_macho_binary_symbols():
    winpe_binary = test_env.get_test_loc("winpe/TranslucentTB-setup.exe")
    winpe_symbols = binary.collect_and_parse_winpe_symbols(winpe_binary)
    expected = test_env.get_test_loc("winpe/TranslucentTB-symbols.json")
    check_json(expected, winpe_symbols, regen=REGEN_TEST_FIXTURES)
