# -*- coding: utf-8 -*-
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/binary-inspector for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


# Symbols are often surrounded by these character/char sequences after demangling
# For example:
# /System/Library/Frameworks/AppKit.framework/Versions/C/AppKit::_OBJC_METACLASS_$_NSWindowController
# We need to split by these characters to get individual symbol strings for matching
SPLIT_CHARACTERS_MACHO = ["::", "_", "$"]


# Standard symbols present in mach0 binaries which are not usually from c/c++/obj-c
# source files, and sometimes they are standard library symbols
STANDARD_SYMBOLS_MACHO = [
    "objc",
    "OBJC",
    "CLASS",
    "METACLASSsleep",
    "empty",
    "async",
    "cache",
    "chk",
    "SHA256",
    "execute",
]

# Standard symbols present in  c/c++/obj-c source files,
# which the mach0 binaries are created from
STANDARD_SYMBOLS_MACHO_SOURCE = [
    "main",
    "argc",
    "argv",
]
