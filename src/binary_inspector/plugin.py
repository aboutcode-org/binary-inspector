# -*- coding: utf-8 -*-
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/binary-inspector for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging

import attr
from commoncode.cliutils import SCAN_GROUP
from commoncode.cliutils import PluggableCommandLineOption
from plugincode.scan import ScanPlugin
from plugincode.scan import scan_impl

from binary_inspector.binary import collect_and_parse_macho_symbols
from binary_inspector.binary import collect_and_parse_winpe_symbols

"""
Extract symbols information from macho binaries.
"""
logger = logging.getLogger(__name__)


@scan_impl
class WinPESymbolScannerPlugin(ScanPlugin):
    """
    Scan a Windows binary for symbols using blint, lief and symbolic.
    """

    resource_attributes = dict(
        winpe_symbols=attr.ib(default=attr.Factory(dict), repr=False),
    )

    options = [
        PluggableCommandLineOption(
            ("--winpe-symbol",),
            is_flag=True,
            default=False,
            help="Collect WinPE symbols from windows binaries.",
            help_group=SCAN_GROUP,
            sort_order=100,
        ),
    ]

    def is_enabled(self, winpe_symbol, **kwargs):
        return winpe_symbol

    def get_scanner(self, **kwargs):
        return collect_and_parse_winpe_symbols


@scan_impl
class MachOSymbolScannerPlugin(ScanPlugin):
    """
    Scan a Macho binary for symbols using blint, lief and symbolic.
    """

    resource_attributes = dict(
        macho_symbols=attr.ib(default=attr.Factory(dict), repr=False),
    )

    options = [
        PluggableCommandLineOption(
            ("--macho-symbol",),
            is_flag=True,
            default=False,
            help="Collect MachO symbols from macos binaries.",
            help_group=SCAN_GROUP,
            sort_order=100,
        ),
    ]

    def is_enabled(self, macho_symbol, **kwargs):
        return macho_symbol

    def get_scanner(self, **kwargs):
        return collect_and_parse_macho_symbols
