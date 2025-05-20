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
import lief
from typecode import contenttype
from typecode.contenttype import get_type

from binary_inspector.blint_binary import get_mach0_metadata
from binary_inspector.blint_binary import get_pe_metadata
from binary_inspector.config import SPLIT_CHARACTERS_MACHO
from binary_inspector.config import STANDARD_SYMBOLS_MACHO


def is_macho(location):
    """
    Return True if the file at ``location`` is in macOS/Darwin's Mach-O format, otherwise False.
    """
    t = get_type(location)
    return t.filetype_file.lower().startswith("mach-o") or t.mimetype_file.lower().startswith(
        "application/x-mach-binary"
    )


def is_executable_binary(location):
    """
    Return True if the file at ``location`` is an executable binary.
    """
    if not os.path.exists(location):
        return False

    if not os.path.isfile(location):
        return False

    typ = contenttype.Type(location)

    if not (typ.is_elf or typ.is_winexe or is_macho(location=location)):
        return False

    return True


def parse_binary(location):
    """
    Get a parsed lief._lief.ELF.Binary object from parsing the macho binary
    present at `location`.
    """
    return lief.parse(location)


def might_have_macho_symbols(string_with_symbols):
    """
    Given a demangled symbol string obtained from a macho binary, return True if
    there are macho symbols present in the string which could be mapped to macho
    source symbols potentially, return False otherwise.
    """
    ignore_chars = [":/"]

    if not string_with_symbols:
        return False

    # fully numberic strings are not macho symbols
    if string_with_symbols.isnumeric():
        return False

    if len(string_with_symbols) < 2:
        return False

    if any(ignore_char in string_with_symbols for ignore_char in ignore_chars):
        return False

    return True


def remove_standard_symbols(macho_symbols, standard_symbols=STANDARD_SYMBOLS_MACHO):
    """
    Remove standard symbols usually found in macho binaries. Given a list of machot
    symbol strings, return a list of symbol strings which are most likely non-standard.
    """
    return [symbol for symbol in macho_symbols if symbol not in standard_symbols]


def split_strings_by_char(split_strings, split_char):
    """
    Given a list of strings, return another list of strings with all
    the substrings from each string, split by the `split_char`.
    """
    final_split_strings = []
    for split_str in split_strings:
        if split_char in split_str:
            split_strings = split_str.split(split_char)
            final_split_strings.extend(split_strings)
        else:
            final_split_strings.append(split_str)

    return [split_string for split_string in final_split_strings if split_string]


def split_strings_into_macho_symbols(strings_to_split, split_by_chars=SPLIT_CHARACTERS_MACHO):
    """
    Given a list of strings containing a group of macho symbols, get a list
    of strings with the extracted individual symbol strings, using a list of
    `split_by_chars` which are common characters found between macho symbols in
    demangled macho string containing multiple symbols.
    """
    split_strings = []
    split_strings_log = []
    for split_char in split_by_chars:
        if not split_strings:
            split_strings = strings_to_split

        split_strings = split_strings_by_char(split_strings, split_char)
        split_strings_log.append(split_strings)

    return split_strings


def cleanup_symbols(symbols, include_stdlib=False, unique=True, sort_symbols=False):
    """
    Given a list of `symbols` strings, return a list of cleaned up
    symbol strings, removing strings which does not have symbols.

    If `include_stdlib` is False, remove standard macho symbols.
    If `unique` is True, only return unique symbol strings.
    If `sort_symbols` is True, return a sorted list of symbols.
    """
    macho_symbols = []
    for split_string in symbols:
        if might_have_macho_symbols(split_string):
            macho_symbols.append(split_string)

    if not include_stdlib:
        macho_symbols = remove_standard_symbols(macho_symbols)

    if unique:
        macho_symbols = list(set(macho_symbols))

    if sort_symbols:
        macho_symbols = sorted(macho_symbols)

    return macho_symbols


def extract_strings_with_symbols(
    symbols_data, include_stdlib=False, unique=True, sort_symbols=False
):
    """
    From a list of macho0 symbols data parsed and demangled from a binary,
    return a list of individual symbols (after cleanup) found in the strings.
    """
    strings_with_symbols = []
    for symbol_data in symbols_data:
        # TODO: get and match using fully qualified "name"
        symbol_name = symbol_data.get("short_name")
        strings_with_symbols.append(symbol_name)

    split_symbols = split_strings_into_macho_symbols(strings_to_split=strings_with_symbols)
    macho_symbols = cleanup_symbols(
        symbols=split_symbols,
        include_stdlib=include_stdlib,
        unique=unique,
        sort_symbols=sort_symbols,
    )

    return macho_symbols


def collect_and_parse_macho_symbols(location, include_stdlib=False, sort_symbols=True, **kwargs):
    """
    Return a mapping of Mach0 symbols of interest for the Mach0 binary file at ``location``.
    Return an empty mapping if there is no symbols or if this is not a binary.
    """
    if not is_executable_binary(location):
        return

    macho_parsed_obj = parse_binary(location=location)
    if not macho_parsed_obj:
        return {}

    macho_metadata = get_mach0_metadata(exe_file=location, parsed_obj=macho_parsed_obj)
    return collect_and_parse_macho_symbols_from_data(
        macho_metadata=macho_metadata,
        include_stdlib=include_stdlib,
        unique=True,
        sort_symbols=sort_symbols,
    )


def collect_and_parse_macho_symbols_from_data(
    macho_metadata, include_stdlib=False, unique=True, sort_symbols=False, **kwargs
):
    """
    Return a mapping of Mach0 symbols of interest for the mapping of Mach0 binary of ``macho_metadata``.
    Return an empty mapping if there is no symbols or if this is not a binary.
    """
    if not macho_metadata:
        return {}

    # Cleanup and get individual symbols which could be macho symbols
    symbols_data = macho_metadata.get("symtab_symbols")
    symbol_strings = extract_strings_with_symbols(
        symbols_data=symbols_data,
        include_stdlib=include_stdlib,
        unique=unique,
        sort_symbols=sort_symbols,
    )

    return dict(macho_symbols=symbol_strings)


def collect_and_parse_winpe_symbols(location, include_stdlib=False, sort_symbols=True, **kwargs):
    """
    Return a mapping of Mach0 symbols of interest for the Mach0 binary file at ``location``.
    Return an empty mapping if there is no symbols or if this is not a binary.
    """
    if not is_executable_binary(location):
        return

    winpe_parsed_obj = parse_binary(location=location)
    if not winpe_parsed_obj:
        return {}

    winpe_metadata = get_pe_metadata(exe_file=location, parsed_obj=winpe_parsed_obj)
    return collect_and_parse_winpe_symbols_from_data(
        winpe_metadata=winpe_metadata,
        include_stdlib=include_stdlib,
        unique=True,
        sort_symbols=sort_symbols,
    )


def collect_and_parse_winpe_symbols_from_data(
    winpe_metadata, include_stdlib=False, unique=True, sort_symbols=False, **kwargs
):
    """
    Return a mapping of Mach0 symbols of interest for the mapping of Mach0 binary of ``macho_metadata``.
    Return an empty mapping if there is no symbols or if this is not a binary.
    """
    if not winpe_metadata:
        return {}

    # Cleanup and get individual symbols which could be macho symbols
    symbols_data = winpe_metadata.get("symtab_symbols")
    if not symbols_data:
        symbols_data = winpe_metadata.get("imports")
    symbol_strings = extract_strings_with_symbols(
        symbols_data=symbols_data,
        include_stdlib=include_stdlib,
        unique=unique,
        sort_symbols=sort_symbols,
    )

    return dict(winpe_symbols=symbol_strings)
