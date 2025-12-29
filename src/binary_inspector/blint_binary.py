#
# Copyright (c) OWASP Foundation
# SPDX-License-Identifier: MIT
#
# Originally taken from
# https://github.com/owasp-dep-scan/blint/blob/1e1250a4bf6c25eccba8970bd877901ee56070c7/blint/lib/binary.py
# Used after minor modifications.
#

import codecs
import contextlib
import json
import lief
from symbolic._lowlevel import ffi
from symbolic._lowlevel import lib
from symbolic.utils import decode_str
from symbolic.utils import encode_str
from symbolic.utils import rustcall


def demangle_symbolic_name(symbol, lang=None, no_args=False):
    """
    Return a demangled symbol string, given a symbol string.

    Demangles symbols obtained from a rust binary using llvm demangle (using symbolic),
    falling back to some heuristics. Also covers legacy rust.
    """
    try:
        func = lib.symbolic_demangle_no_args if no_args else lib.symbolic_demangle
        lang_str = encode_str(lang) if lang else ffi.NULL
        demangled = rustcall(func, encode_str(symbol), lang_str)
        demangled_symbol = decode_str(demangled, free=True).strip()
        # demangling didn't work
        if symbol and symbol == demangled_symbol:
            for ign in ("__imp_anon.", "anon.", ".L__unnamed"):
                if symbol.startswith(ign):
                    return "anonymous"
            if symbol.startswith("GCC_except_table"):
                return "GCC_except_table"
            if symbol.startswith("@feat.00"):
                return "SAFESEH"
            if (
                symbol.startswith("__imp_")
                or symbol.startswith(".rdata$")
                or symbol.startswith(".refptr.")
            ):
                symbol_without_prefix = (
                    symbol.removeprefix("__imp_").removeprefix(".rdata$").removeprefix(".refptr.")
                )
                symbol = f"__declspec(dllimport) {symbol_without_prefix}"
            demangled_symbol = (
                symbol.replace("..", "::")
                .replace("$SP$", "@")
                .replace("$BP$", "*")
                .replace("$LT$", "<")
                .replace("$u5b$", "[")
                .replace("$u7b$", "{")
                .replace("$u3b$", ";")
                .replace("$u20$", " ")
                .replace("$u5d$", "]")
                .replace("$u7d$", "}")
                .replace("$GT$", ">")
                .replace("$RF$", "&")
                .replace("$LP$", "(")
                .replace("$RP$", ")")
                .replace("$C$", ",")
                .replace("$u27$", "'")
            )
        # In case of rust symbols, try and trim the hash part from the end of the symbols
        if demangled_symbol.count("::") > 2:
            last_part = demangled_symbol.split("::")[-1]
            if len(last_part) == 17:
                demangled_symbol = demangled_symbol.removesuffix(f"::{last_part}")
        return demangled_symbol
    except AttributeError:
        return symbol


def is_shared_library(parsed_binary_obj):
    """
    Return True if the given parsed binary object represents a shared library.
    """
    if not parsed_binary_obj:
        return False
    if parsed_binary_obj.format == lief.Binary.FORMATS.ELF:
        return parsed_binary_obj.header.file_type == lief.ELF.Header.FILE_TYPE.DYN
    if parsed_binary_obj.format == lief.Binary.FORMATS.PE:
        return parsed_binary_obj.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.DLL)
    if parsed_binary_obj.format == lief.Binary.FORMATS.MACHO:
        return parsed_binary_obj.header.file_type == lief.MachO.Header.FILE_TYPE.DYLIB
    return False


def parse_notes(parsed_binary_obj):
    """
    Return a list of metadata dictionaries, each representing the notes
    from the given parsed binary object.
    """
    data = []
    notes = parsed_binary_obj.notes
    if isinstance(notes, lief.lief_errors):
        return data
    data += [extract_note_data(idx, note) for idx, note in enumerate(notes)]
    return data


def extract_note_data(idx, note):
    """
    Extract metadata from a note object and returns a dictionary.
    """
    note_str = ""
    build_id = ""
    if note.type == lief.ELF.Note.TYPE.GNU_BUILD_ID:
        note_str = str(note)
    if "ID Hash" in note_str:
        build_id = note_str.rsplit("ID Hash:", maxsplit=1)[-1].strip()
    description = note.description
    description_str = " ".join(map(integer_to_hex_str, description[:64]))
    if len(description) > 64:
        description_str += " ..."
    if note.type == lief.ELF.Note.TYPE.GNU_BUILD_ID:
        build_id = description_str.replace(" ", "")
    type_str = note.type
    type_str = str(type_str).rsplit(".", maxsplit=1)[-1]
    note_details = ""
    sdk_version = ""
    ndk_version = ""
    ndk_build_number = ""
    abi = ""
    version_str = ""
    if type_str == "ANDROID_IDENT":
        sdk_version = note.sdk_version
        ndk_version = note.ndk_version
        ndk_build_number = note.ndk_build_number
    elif type_str.startswith("GNU_ABI_TAG"):
        version = [str(i) for i in note.version]
        version_str = ".".join(version)
    else:
        with contextlib.suppress(AttributeError):
            note_details = note.details
            version = note_details.version
            abi = str(note_details.abi)
            version_str = f"{version[0]}.{version[1]}.{version[2]}"
    if not version_str and build_id:
        version_str = build_id
    return {
        "index": idx,
        "description": description_str,
        "type": type_str,
        "details": note_details,
        "sdk_version": sdk_version,
        "ndk_version": ndk_version,
        "ndk_build_number": ndk_build_number,
        "abi": abi,
        "version": version_str,
        "build_id": build_id,
    }


def integer_to_hex_str(e):
    """
    Convert an integer to a hexadecimal string representation.
    """
    return "{:02x}".format(e)


def parse_relro(parsed_obj):
    """
    Determine the Relocation Read-Only (RELRO) protection level.
    """
    test_stmt = parsed_obj.get(lief.ELF.Segment.TYPE.GNU_RELRO)
    if isinstance(test_stmt, lief.lief_errors):
        return "no"
    dynamic_tags = parsed_obj.get(lief.ELF.DynamicEntry.TAG.FLAGS)
    bind_now, now = False, False
    if dynamic_tags and isinstance(dynamic_tags, lief.ELF.DynamicEntryFlags):
        bind_now = lief.ELF.DynamicEntryFlags.FLAG.BIND_NOW in dynamic_tags
    dynamic_tags = parsed_obj.get(lief.ELF.DynamicEntry.TAG.FLAGS_1)
    if dynamic_tags and isinstance(dynamic_tags, lief.ELF.DynamicEntryFlags):
        now = lief.ELF.DynamicEntryFlags.FLAG.NOW in dynamic_tags
    return "full" if bind_now or now else "partial"


def parse_functions(functions):
    """
    Parse a list of functions and returns a list of dictionaries.
    """
    func_list = []

    for idx, f in enumerate(functions):
        if f.name and f.address:
            cleaned_name = demangle_symbolic_name(f.name)
            func_list.append(
                {
                    "index": idx,
                    "name": cleaned_name,
                }
            )
    return func_list


def parse_symbols(symbols):
    """
    Parse symbols from a list of symbol strings and get a list of symbol
    data, with the demangled symbol string and other attributes for the symbol.
    """
    symbols_list = []

    for symbol in symbols:
        try:
            symbol_version = symbol.symbol_version if symbol.has_version else ""
            is_imported = False
            is_exported = False
            if symbol.imported and not isinstance(symbol.imported, lief.lief_errors):
                is_imported = True
            if symbol.exported and not isinstance(symbol.exported, lief.lief_errors):
                is_exported = True
            symbol_name = symbol.demangled_name
            if isinstance(symbol_name, lief.lief_errors):
                symbol_name = demangle_symbolic_name(symbol.name)
            else:
                symbol_name = demangle_symbolic_name(symbol_name)

            symbols_list.append(
                {
                    "name": symbol_name,
                    "type": str(symbol.type).rsplit(".", maxsplit=1)[-1],
                    "value": symbol.value,
                    "visibility": str(symbol.visibility).rsplit(".", maxsplit=1)[-1],
                    "binding": str(symbol.binding).rsplit(".", maxsplit=1)[-1],
                    "is_imported": is_imported,
                    "is_exported": is_exported,
                    "information": symbol.information,
                    "is_function": symbol.is_function,
                    "is_static": symbol.is_static,
                    "is_variable": symbol.is_variable,
                    "version": str(symbol_version),
                }
            )
        except (AttributeError, IndexError, TypeError):
            continue

    return symbols_list


def detect_exe_type(parsed_obj, metadata):
    """
    Detect the type of the parsed binary object based on its characteristics
    and metadata.
    """
    with contextlib.suppress(AttributeError, TypeError):
        if parsed_obj.has_section(".note.go.buildid"):
            return "gobinary"
        if (
            parsed_obj.has_section(".note.gnu.build-id")
            or "musl" in metadata.get("interpreter")
            or "ld-linux" in metadata.get("interpreter")
        ):
            return "genericbinary"
        if metadata.get("machine_type") and metadata.get("file_type"):
            return f"{metadata.get('machine_type')}-{metadata.get('file_type')}".lower()
        if metadata["relro"] in ("partial", "full"):
            return "genericbinary"
    return ""


def guess_exe_type(symbol_name):
    """
    Guess the executable type based on the symbol name.
    """
    exe_type = ""
    if "golang" in symbol_name or "_cgo_" in symbol_name:
        exe_type = "gobinary"
    if "_macho_" in symbol_name:
        exe_type = "genericbinary"
    if "DotNetRuntimeInfo" in symbol_name:
        exe_type = "dotnetbinary"
    return exe_type


def parse_pe_data(parsed_obj):
    """
    Parse the data directories from the given parsed PE binary object.
    """
    data_list = []

    data_directories = parsed_obj.data_directories
    if not data_directories or isinstance(data_directories, lief.lief_errors):
        return data_list
    for directory in data_directories:
        section_name = ""
        section_chars = ""
        section_entropy = ""
        dir_type = str(directory.type).rsplit(".", maxsplit=1)[-1]
        if not dir_type.startswith("?") and directory.size:
            if directory.has_section:
                if directory.section.has_characteristic:
                    section_chars = ", ".join(
                        [
                            str(chara).rsplit(".", maxsplit=1)[-1]
                            for chara in directory.section.characteristics_lists
                        ]
                    )
                section_name = directory.section.name
                section_entropy = directory.section.entropy
            data_list.append(
                {
                    "name": section_name,
                    "type": dir_type,
                    "rva": directory.rva,
                    "size": directory.size,
                    "section_characteristics": section_chars,
                    "section_entropy": section_entropy,
                }
            )
    return data_list


def process_pe_resources(parsed_obj):
    """
    Process the resources of the parsed PE (Portable Executable) binary object
    and returns metadata about the resources.
    """
    rm = parsed_obj.resources_manager
    if not rm or isinstance(rm, lief.lief_errors):
        return {}
    resources = {}
    version_metadata = {}

    version_info = rm.version if rm.has_version else None
    if isinstance(version_info, list) and len(version_info):
        if not isinstance(version_info[0], lief.lief_errors):
            version_info = version_info[0]
    if version_info and hasattr(version_info, "string_file_info"):
        string_file_info: lief.PE.ResourceStringFileInfo = version_info.string_file_info
        for lc_item in string_file_info.children:
            if lc_item.entries:
                for e in lc_item.entries:
                    version_metadata[e.key] = e.value

    try:
        resources = {
            "has_accelerator": rm.has_accelerator,
            "has_dialogs": rm.has_dialogs,
            "has_html": rm.has_html,
            "has_icons": rm.has_icons,
            "has_manifest": rm.has_manifest,
            "has_string_table": rm.has_string_table,
            "has_version": rm.has_version,
            "manifest": (
                rm.manifest.replace("\\xef\\xbb\\xbf", "").removeprefix("\ufeff")
                if rm.has_manifest
                else None
            ),
            "version_info": str(rm.version) if rm.has_version else None,
            "html": rm.html if rm.has_html else None,
        }
        if version_metadata:
            resources["version_metadata"] = version_metadata
    except (AttributeError, UnicodeError):
        return resources
    return resources


def process_pe_signature(parsed_obj):
    """
    Process the signatures of the parsed PE (Portable Executable) binary
    object and returns information about the signatures.
    """
    signature_list = []
    with contextlib.suppress(AttributeError, TypeError, KeyError):
        for sig in parsed_obj.signatures:
            ci = sig.content_info
            signature_obj = {
                "version": sig.version,
                "digest_algorithm": str(sig.digest_algorithm).rsplit(".", maxsplit=1)[-1],
                "content_info": {
                    "content_type": lief.PE.oid_to_string(ci.content_type),
                    "digest_algorithm": str(ci.digest_algorithm).rsplit(".", maxsplit=1)[-1],
                    "digest": ci.digest.hex(),
                },
            }
            signers_list = []
            for signer in sig.signers:
                signer_obj = {
                    "version": signer.version,
                    "serial_number": signer.serial_number.hex(),
                    "issuer": str(signer.issuer),
                    "digest_algorithm": str(signer.digest_algorithm).rsplit(".", maxsplit=1)[-1],
                    "encryption_algorithm": str(signer.encryption_algorithm).rsplit(
                        ".", maxsplit=1
                    )[-1],
                    "encrypted_digest": signer.encrypted_digest.hex(),
                }
                signers_list.append(signer_obj)
            signature_obj["signers"] = signers_list
            signature_list.append(signature_obj)
    return signature_list


def parse_pe_symbols(symbols):
    """
    Parse the symbols and determines the executable type.
    """

    symbols_list = []
    exe_type = ""
    for symbol in symbols:
        if not symbol:
            continue

        if symbol.section and symbol.section.name:
            section_nb_str = symbol.section.name
        else:
            section_nb_str = "section<{:d}>".format(symbol.section_number)

        if not exe_type:
            exe_type = guess_exe_type(symbol.name.lower())
        if symbol.name:
            symbols_list.append(
                {
                    "name": demangle_symbolic_name(symbol.name),
                    "value": symbol.value,
                    "id": section_nb_str,
                    "base_type": str(symbol.base_type).rsplit(".", maxsplit=1)[-1],
                    "complex_type": str(symbol.complex_type).rsplit(".", maxsplit=1)[-1],
                    "storage_class": str(symbol.storage_class).rsplit(".", maxsplit=1)[-1],
                }
            )

    return symbols_list, exe_type


def parse_pe_imports(imports):
    """
    Parse the imports and returns lists of imported symbols and DLLs.
    """
    imports_list = []
    dlls = set()
    if not imports or isinstance(imports, lief.lief_errors):
        return imports_list, []
    for import_ in imports:
        try:
            entries = import_.entries
        except AttributeError:
            break
        if isinstance(entries, lief.lief_errors):
            break
        for entry in entries:
            try:
                if entry.name:
                    dlls.add(import_.name)
                    imports_list.append(
                        {
                            "name": f"{import_.name}::{demangle_symbolic_name(entry.name)}",
                            "short_name": demangle_symbolic_name(entry.name),
                            "data": entry.data,
                            "iat_value": entry.iat_value,
                            "hint": entry.hint,
                        }
                    )
            except AttributeError:
                continue
    dll_list = [{"name": d, "tag": "NEEDED"} for d in list(dlls)]
    return imports_list, dll_list


def parse_pe_exports(exports):
    """
    Parse the exports and returns a list of exported symbols.
    """
    exports_list = []
    if not exports or isinstance(exports, lief.lief_errors):
        return exports_list
    if not (entries := exports.entries) or isinstance(exports.entries, lief.lief_errors):
        return exports_list
    for entry in entries:
        metadata = {}
        extern = "[EXTERN]" if entry.is_extern else ""
        if entry.name:
            metadata = {
                "name": demangle_symbolic_name(entry.name),
                "ordinal": entry.ordinal,
                "extern": extern,
            }
        fwd = entry.forward_information if entry.is_forwarded else None
        metadata["is_forwarded"] = entry.is_forwarded
        if fwd:
            metadata["fwd_library"] = fwd.library
            metadata["fwd_function"] = fwd.function
        if metadata:
            exports_list.append(metadata)
    return exports_list


def parse_macho_symbols(symbols):
    """
    Parse the symbols and determines the executable type.
    """

    symbols_list = []
    exe_type = ""
    if not symbols or isinstance(symbols, lief.lief_errors):
        return symbols_list, exe_type
    for symbol in symbols:
        try:
            libname = ""
            if symbol.has_binding_info and symbol.binding_info.has_library:
                libname = symbol.binding_info.library.name
            symbol_value = (
                symbol.value
                if symbol.value > 0 or not symbol.has_binding_info
                else symbol.binding_info.address
            )
            symbol_name = symbol.demangled_name
            if not symbol_name or isinstance(symbol_name, lief.lief_errors):
                symbol_name = demangle_symbolic_name(symbol.name)
            else:
                symbol_name = demangle_symbolic_name(symbol_name)
            if not exe_type:
                exe_type = guess_exe_type(symbol_name)
            symbols_list.append(
                {
                    "name": (f"{libname}::{symbol_name}" if libname else symbol_name),
                    "short_name": symbol_name,
                    "type": symbol.type,
                    "num_sections": symbol.numberof_sections,
                    "description": symbol.description,
                    "value": symbol_value,
                }
            )
        except (AttributeError, TypeError):
            continue
    return symbols_list, exe_type


def parse(exe_file):  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    """
    Parse the executable using lief and capture the metadata
    """
    metadata = {"file_path": exe_file}

    parsed_obj = lief.parse(exe_file)
    metadata["is_shared_library"] = is_shared_library(parsed_obj)
    # ELF Binary
    if isinstance(parsed_obj, lief.ELF.Binary):
        elf_metadata = get_elf_metadata(exe_file, parsed_obj)
        metadata.update(elf_metadata)
    elif isinstance(parsed_obj, lief.PE.Binary):
        # PE
        winpe_metadata = get_pe_metadata(exe_file, parsed_obj)
        metadata.update(winpe_metadata)
    elif isinstance(parsed_obj, lief.MachO.Binary):
        macho_metadata = get_mach0_metadata(exe_file, parsed_obj)
        metadata.update(macho_metadata)

    return cleanup_dict_lief_errors(metadata)


def cleanup_dict_lief_errors(old_dict):
    """
    Remove lief_errors from a dictionary recursively.
    """
    new_dict = {}
    for key, value in old_dict.items():
        if isinstance(value, lief.lief_errors):
            continue
        if isinstance(value, dict):
            entry = cleanup_dict_lief_errors(value)
        elif isinstance(value, list):
            entry = cleanup_list_lief_errors(value)
        else:
            entry = value
        new_dict[key] = entry
    return new_dict


def cleanup_list_lief_errors(d):
    """
    Clean up a list by removing lief errors recursively.
    """
    new_lst = []
    for dl in d:
        if isinstance(dl, lief.lief_errors):
            continue
        if isinstance(dl, dict):
            entry = cleanup_dict_lief_errors(dl)
        elif isinstance(dl, list):
            entry = cleanup_list_lief_errors(dl)
        else:
            entry = dl
        new_lst.append(entry)
    return new_lst


def get_elf_metadata(exe_file, parsed_obj):
    """
    Return ELF metadata to from the parsed binary object.
    """
    metadata = {}

    metadata["binary_type"] = "ELF"
    header = parsed_obj.header
    identity = header.identity
    metadata["magic"] = ("{:<02x} " * 8).format(*identity[:8]).strip()
    metadata = add_elf_header(header, metadata)
    metadata["name"] = exe_file
    metadata["imagebase"] = parsed_obj.imagebase
    metadata["interpreter"] = parsed_obj.interpreter
    metadata["is_pie"] = parsed_obj.is_pie
    metadata["virtual_size"] = parsed_obj.virtual_size
    metadata["has_nx"] = parsed_obj.has_nx
    metadata["relro"] = parse_relro(parsed_obj)
    metadata["exe_type"] = detect_exe_type(parsed_obj, metadata)
    # Canary check
    canary_sections = ["__stack_chk_fail", "__intel_security_cookie"]
    for section in canary_sections:
        if parsed_obj.get_symbol(section):
            if isinstance(parsed_obj.get_symbol(section), lief.lief_errors):
                metadata["has_canary"] = False
            else:
                metadata["has_canary"] = True
                break
    # rpath check
    rpath = parsed_obj.get(lief.ELF.DynamicEntry.TAG.RPATH)
    if isinstance(rpath, lief.lief_errors):
        metadata["has_rpath"] = False
    elif rpath:
        metadata["has_rpath"] = True
    # runpath check
    runpath = parsed_obj.get(lief.ELF.DynamicEntry.TAG.RUNPATH)
    if isinstance(runpath, lief.lief_errors):
        metadata["has_runpath"] = False
    elif runpath:
        metadata["has_runpath"] = True
    symtab_symbols = parsed_obj.symtab_symbols
    metadata["static"] = bool(symtab_symbols and not isinstance(symtab_symbols, lief.lief_errors))
    dynamic_entries = parsed_obj.dynamic_entries
    metadata = add_elf_dynamic_entries(dynamic_entries, metadata)
    metadata = add_elf_symbols(metadata, parsed_obj)
    metadata["notes"] = parse_notes(parsed_obj)
    metadata["symtab_symbols"], exe_type = parse_symbols(symtab_symbols)
    rdata_section = parsed_obj.get_section(".rodata")
    text_section = parsed_obj.get_section(".text")
    if exe_type:
        metadata["exe_type"] = exe_type
    metadata["dynamic_symbols"], exe_type = parse_symbols(parsed_obj.dynamic_symbols)
    if exe_type:
        metadata["exe_type"] = exe_type
    metadata["functions"] = parse_functions(parsed_obj.functions)
    metadata["ctor_functions"] = parse_functions(parsed_obj.ctor_functions)
    metadata["dotnet_dependencies"] = parse_overlay(parsed_obj)
    return metadata


def add_elf_header(header, metadata):
    """
    Add ELF header data to the metadata dictionary.
    """
    if not header or isinstance(header, lief.lief_errors):
        return metadata

    eflags_str = determine_elf_flags(header)
    metadata["class"] = str(header.identity_class).rsplit(".", maxsplit=1)[-1]
    metadata["endianness"] = str(header.identity_data).rsplit(".", maxsplit=1)[-1]
    metadata["identity_version"] = str(header.identity_version).rsplit(".", maxsplit=1)[-1]
    metadata["identity_os_abi"] = str(header.identity_os_abi).rsplit(".", maxsplit=1)[-1]
    metadata["identity_abi_version"] = header.identity_abi_version
    metadata["file_type"] = str(header.file_type).rsplit(".", maxsplit=1)[-1]
    metadata["machine_type"] = str(header.machine_type).rsplit(".", maxsplit=1)[-1]
    metadata["object_file_version"] = str(header.object_file_version).rsplit(".", maxsplit=1)[-1]
    metadata["entrypoint"] = header.entrypoint
    metadata["processor_flag"] = str(header.processor_flag) + eflags_str

    return metadata


def add_elf_symbols(metadata, parsed_obj):
    """
    Extract ELF symbols version information and adds it to the metadata dictionary.
    """
    symbols_version = parsed_obj.symbols_version
    if symbols_version and not isinstance(symbols_version, lief.lief_errors):
        metadata["symbols_version"] = []
        symbol_version_auxiliary_cache = {}
        for entry in symbols_version:
            symbol_version_auxiliary = entry.symbol_version_auxiliary
            if symbol_version_auxiliary and not symbol_version_auxiliary_cache.get(
                symbol_version_auxiliary.name
            ):
                symbol_version_auxiliary_cache[symbol_version_auxiliary.name] = True
                metadata["symbols_version"].append(
                    {
                        "name": demangle_symbolic_name(symbol_version_auxiliary.name),
                        "hash": symbol_version_auxiliary.hash,
                        "value": entry.value,
                    }
                )

    return metadata


def add_elf_dynamic_entries(dynamic_entries, metadata):
    """
    Extract ELF dynamic entries and adds them to the metadata dictionary.
    """
    metadata["dynamic_entries"] = []
    if isinstance(dynamic_entries, lief.lief_errors):
        return metadata
    for entry in dynamic_entries:
        if entry.tag == lief.ELF.DynamicEntry.TAG.NULL:
            continue
        if entry.tag in [
            lief.ELF.DynamicEntry.TAG.SONAME,
            lief.ELF.DynamicEntry.TAG.NEEDED,
        ]:
            metadata["dynamic_entries"].append(
                {
                    "name": demangle_symbolic_name(entry.name),
                    "tag": str(entry.tag).rsplit(".", maxsplit=1)[-1],
                    "value": entry.value,
                }
            )
            if "netcoredeps" in entry.name:
                metadata["exe_type"] = "dotnetbinary"
        if entry.tag in [
            lief.ELF.DynamicEntry.TAG.RUNPATH,
        ]:
            metadata["dynamic_entries"].append(
                {
                    "name": "runpath",
                    "tag": str(entry.tag).rsplit(".", maxsplit=1)[-1],
                    "value": entry.runpath,
                }
            )
        if entry.tag in [
            lief.ELF.DynamicEntry.TAG.RPATH,
        ]:
            metadata["dynamic_entries"].append(
                {
                    "name": "rpath",
                    "tag": str(entry.tag).rsplit(".", maxsplit=1)[-1],
                    "value": entry.rpath,
                }
            )
    return metadata


def determine_elf_flags(header):
    """
    Determine and return a string representing the ELF flags
    based on the given ELF header.
    """
    eflags_str = ""
    if header.machine_type == lief.ELF.ARCH.ARM and hasattr(header, "arm_flags_list"):
        eflags_str = " - ".join([str(s).rsplit(".", maxsplit=1)[-1] for s in header.arm_flags_list])
    if header.machine_type in [
        lief.ELF.ARCH.MIPS,
        lief.ELF.ARCH.MIPS_RS3_LE,
        lief.ELF.ARCH.MIPS_X,
    ]:
        eflags_str = " - ".join(
            [str(s).rsplit(".", maxsplit=1)[-1] for s in header.mips_flags_list]
        )
    if header.machine_type == lief.ELF.ARCH.PPC64:
        eflags_str = " - ".join(
            [str(s).rsplit(".", maxsplit=1)[-1] for s in header.ppc64_flags_list]
        )
    if header.machine_type == lief.ELF.ARCH.HEXAGON:
        eflags_str = " - ".join(
            [str(s).rsplit(".", maxsplit=1)[-1] for s in header.hexagon_flags_list]
        )
    return eflags_str


def parse_overlay(parsed_obj: lief.Binary):
    """
    Parse the overlay section to extract dotnet dependencies
    """
    deps = {}
    if hasattr(parsed_obj, "overlay"):
        overlay = parsed_obj.overlay
        overlay_str = (
            codecs.decode(overlay.tobytes(), encoding="utf-8", errors="backslashreplace")
            .replace("\0", "")
            .replace("\r\n", "")
            .replace("\n", "")
            .replace("  ", "")
        )
        if overlay_str.find('{"runtimeTarget') > -1:
            start_index = overlay_str.find('{"runtimeTarget')
            end_index = overlay_str.rfind("}}}")
            if end_index > -1:
                overlay_str = overlay_str[start_index : end_index + 3]
                try:
                    # deps should have runtimeTarget, compilationOptions, targets, and libraries
                    # Use libraries to construct BOM components and targets for the dependency tree
                    deps = json.loads(overlay_str)
                except json.JSONDecodeError:
                    pass
    return deps


def get_pe_metadata(exe_file: str, parsed_obj: lief.PE.Binary):
    """
    Return PE metadata from the parsed binary object.
    """
    metadata = {}

    metadata["binary_type"] = "PE"
    metadata["name"] = exe_file
    metadata["is_pie"] = parsed_obj.is_pie
    metadata["is_reproducible_build"] = parsed_obj.is_reproducible_build
    metadata["virtual_size"] = parsed_obj.virtual_size
    metadata["has_nx"] = parsed_obj.has_nx
    metadata["imphash_pefile"] = lief.PE.get_imphash(parsed_obj, lief.PE.IMPHASH_MODE.PEFILE)
    metadata["imphash_lief"] = lief.PE.get_imphash(parsed_obj, lief.PE.IMPHASH_MODE.LIEF)
    metadata = add_pe_header_data(metadata, parsed_obj)
    metadata["data_directories"] = parse_pe_data(parsed_obj)
    metadata["signatures"] = process_pe_signature(parsed_obj)
    metadata["resources"] = process_pe_resources(parsed_obj)
    metadata["symtab_symbols"], exe_type = parse_pe_symbols(parsed_obj.symbols)
    if exe_type:
        metadata["exe_type"] = exe_type
    (
        metadata["imports"],
        metadata["dynamic_entries"],
    ) = parse_pe_imports(parsed_obj.imports)
    # Attempt to detect if this PE is a driver
    if metadata["dynamic_entries"]:
        for e in metadata["dynamic_entries"]:
            if e["name"] == "ntoskrnl.exe":
                metadata["is_driver"] = True
                break
    rdata_section = parsed_obj.get_section(".rdata")
    text_section = parsed_obj.get_section(".text")
    # If there are no .rdata and .text section, then attempt to look for two alphanumeric sections
    if not rdata_section and not text_section:
        for section in parsed_obj.sections:
            if str(section.name).removeprefix(".").isalnum():
                if not rdata_section:
                    rdata_section = section
                else:
                    text_section = section

    metadata["exports"] = parse_pe_exports(parsed_obj.get_export())
    metadata["functions"] = parse_functions(parsed_obj.functions)
    metadata["ctor_functions"] = parse_functions(parsed_obj.ctor_functions)
    metadata["exception_functions"] = parse_functions(parsed_obj.exception_functions)
    # Detect if this PE might be dotnet
    for i, dd in enumerate(parsed_obj.data_directories):
        if i == 14 and dd.type.value == lief.PE.DataDirectory.TYPES.CLR_RUNTIME_HEADER.value:
            metadata["is_dotnet"] = True
    metadata["dotnet_dependencies"] = parse_overlay(parsed_obj)
    tls = parsed_obj.tls
    if tls and tls.sizeof_zero_fill:
        metadata["tls_address_index"] = tls.addressof_index
        metadata["tls_sizeof_zero_fill"] = tls.sizeof_zero_fill
        metadata["tls_data_template_len"] = len(tls.data_template)
        metadata["tls_characteristics"] = tls.characteristics
        metadata["tls_section_name"] = tls.section.name
        metadata["tls_directory_type"] = str(tls.directory.type)

    return metadata


def add_pe_header_data(metadata, parsed_obj):
    """
    Add PE header data to the metadata dictionary.
    """
    dos_header = parsed_obj.dos_header
    if dos_header and not isinstance(dos_header, lief.lief_errors):
        metadata["magic"] = str(dos_header.magic)
        header = parsed_obj.header
        metadata["used_bytes_in_the_last_page"] = dos_header.used_bytes_in_last_page
        metadata["file_size_in_pages"] = dos_header.file_size_in_pages
        metadata["num_relocation"] = dos_header.numberof_relocation
        metadata["header_size_in_paragraphs"] = dos_header.header_size_in_paragraphs
        metadata["minimum_extra_paragraphs"] = dos_header.minimum_extra_paragraphs
        metadata["maximum_extra_paragraphs"] = dos_header.maximum_extra_paragraphs
        metadata["initial_relative_ss"] = dos_header.initial_relative_ss
        metadata["initial_sp"] = dos_header.initial_sp
        metadata["checksum"] = dos_header.checksum
        metadata["initial_ip"] = dos_header.initial_ip
        metadata["initial_relative_cs"] = dos_header.initial_relative_cs
        metadata["overlay_number"] = dos_header.overlay_number
        metadata["oem_id"] = dos_header.oem_id
        metadata["oem_info"] = dos_header.oem_info
        metadata["characteristics"] = ", ".join(
            [str(chara).rsplit(".", maxsplit=1)[-1] for chara in header.characteristics_list]
        )
        metadata["num_sections"] = header.numberof_sections
        metadata["time_date_stamps"] = header.time_date_stamps
        metadata["pointer_symbol_table"] = header.pointerto_symbol_table
        metadata["num_symbols"] = header.numberof_symbols
        metadata["size_optional_header"] = header.sizeof_optional_header
    optional_header = parsed_obj.optional_header
    if optional_header and not isinstance(optional_header, lief.lief_errors):
        metadata = add_pe_optional_headers(metadata, optional_header)
    return metadata


def add_pe_optional_headers(metadata, optional_header):
    """
    Add PE optional headers data to the metadata dictionary.
    """
    with contextlib.suppress(IndexError, TypeError):
        metadata["dll_characteristics"] = ", ".join(
            [
                str(chara).rsplit(".", maxsplit=1)[-1]
                for chara in optional_header.dll_characteristics_lists
            ]
        )
        # Detect if this binary is a driver
        if "WDM_DRIVER" in metadata["dll_characteristics"]:
            metadata["is_driver"] = True
        metadata["subsystem"] = str(optional_header.subsystem).rsplit(".", maxsplit=1)[-1]
        metadata["is_gui"] = metadata["subsystem"] == "WINDOWS_GUI"
        metadata["exe_type"] = "PE32" if optional_header.magic == lief.PE.PE_TYPE.PE32 else "PE64"
        metadata["major_linker_version"] = optional_header.major_linker_version
        metadata["minor_linker_version"] = optional_header.minor_linker_version
        metadata["sizeof_code"] = optional_header.sizeof_code
        metadata["sizeof_initialized_data"] = optional_header.sizeof_initialized_data
        metadata["sizeof_uninitialized_data"] = optional_header.sizeof_uninitialized_data
        metadata["baseof_code"] = optional_header.baseof_code
        metadata["baseof_data"] = optional_header.baseof_data
        metadata["imagebase"] = optional_header.imagebase
        metadata["section_alignment"] = optional_header.section_alignment
        metadata["file_alignment"] = optional_header.file_alignment
        metadata["major_operating_system_version"] = optional_header.major_operating_system_version
        metadata["minor_operating_system_version"] = optional_header.minor_operating_system_version
        metadata["major_image_version"] = optional_header.major_image_version
        metadata["minor_image_version"] = optional_header.minor_image_version
        metadata["major_subsystem_version"] = optional_header.major_subsystem_version
        metadata["minor_subsystem_version"] = optional_header.minor_subsystem_version
        metadata["win32_version_value"] = optional_header.win32_version_value
        metadata["sizeof_image"] = optional_header.sizeof_image
        metadata["sizeof_headers"] = optional_header.sizeof_headers
        metadata["checksum"] = optional_header.checksum
        metadata["sizeof_stack_reserve"] = optional_header.sizeof_stack_reserve
        metadata["sizeof_stack_commit"] = optional_header.sizeof_stack_commit
        metadata["sizeof_heap_reserve"] = optional_header.sizeof_heap_reserve
        metadata["sizeof_heap_commit"] = optional_header.sizeof_heap_commit
        metadata["loader_flags"] = optional_header.loader_flags
        metadata["numberof_rva_and_size"] = optional_header.numberof_rva_and_size
    return metadata


def get_mach0_metadata(exe_file, parsed_obj):
    """
    Get MachO metadata from the parsed binary object.
    """
    metadata = {}

    metadata["binary_type"] = "MachO"
    metadata["name"] = exe_file
    metadata["imagebase"] = parsed_obj.imagebase
    metadata["is_pie"] = parsed_obj.is_pie
    metadata["has_nx"] = parsed_obj.has_nx
    metadata["exe_type"] = "MachO"
    metadata = add_mach0_versions(exe_file, metadata, parsed_obj)
    if parsed_obj.has_encryption_info and (encryption_info := parsed_obj.encryption_info):
        metadata["encryption_info"] = {
            "crypt_offset": encryption_info.crypt_offset,
            "crypt_size": encryption_info.crypt_size,
            "crypt_id": encryption_info.crypt_id,
        }
    if sinfo := parsed_obj.sub_framework:
        metadata["umbrella"] = sinfo.umbrella
    if cmd := parsed_obj.rpath:
        metadata["has_rpath"] = True
        metadata["rpath"] = cmd.path
    else:
        metadata["has_rpath"] = False

    if cmd := parsed_obj.uuid:
        uuid_str = " ".join(map(integer_to_hex_str, cmd.uuid))
        metadata["uuid"] = uuid_str

    metadata = add_mach0_libraries(exe_file, metadata, parsed_obj)
    metadata = add_mach0_header_data(exe_file, metadata, parsed_obj)
    metadata = add_mach0_commands(metadata, parsed_obj)
    metadata = add_mach0_functions(metadata, parsed_obj)
    metadata = add_mach0_signature(exe_file, metadata, parsed_obj)

    return metadata


def add_mach0_commands(metadata, parsed_obj: lief.MachO.Binary):
    """
    Extract MachO commands metadata from the parsed object and adds it to the metadata.
    """
    metadata["has_main"] = False
    metadata["has_thread_command"] = False
    if parsed_obj.main_command:
        metadata["has_main_command"] = not isinstance(parsed_obj.main_command, lief.lief_errors)
    if parsed_obj.thread_command:
        metadata["has_thread_command"] = not isinstance(parsed_obj.thread_command, lief.lief_errors)
    return metadata


def add_mach0_versions(exe_file, metadata, parsed_obj):
    """
    Extract MachO version metadata from the parsed object and adds it to the metadata.
    """
    version = parsed_obj.version_min.version if parsed_obj.version_min else ""
    sdk = parsed_obj.version_min.sdk if parsed_obj.version_min else ""
    source_version = parsed_obj.source_version.version if parsed_obj.source_version else ""
    if source_version:
        metadata["source_version"] = "{:d}.{:d}.{:d}.{:d}.{:d}".format(*source_version)
    if version:
        metadata["version"] = "{:d}.{:d}.{:d}".format(*version)
    if sdk:
        metadata["sdk"] = "{:d}.{:d}.{:d}".format(*sdk)

    return add_mach0_build_metadata(exe_file, metadata, parsed_obj)


def add_mach0_build_metadata(exe_file, metadata, parsed_obj):
    """
    Extract MachO build version metadata from the parsed object and adds it to the metadata.
    """
    build_version = parsed_obj.build_version
    if not build_version:
        return metadata
    metadata["platform"] = str(build_version.platform).rsplit(".", maxsplit=1)[-1]
    metadata["minos"] = "{:d}.{:d}.{:d}".format(*build_version.minos)
    metadata["sdk"] = "{:d}.{:d}.{:d}".format(*build_version.sdk)
    if tools := build_version.tools:
        metadata["tools"] = []
        for tool in tools:
            tool_str = str(tool.tool).rsplit(".", maxsplit=1)[-1]
            metadata["tools"].append(
                {
                    "tool": tool_str,
                    "version": "{}.{}.{}".format(*tool.version),
                }
            )

    return metadata


def add_mach0_libraries(exe_file, metadata, parsed_obj):
    """
    Process the libraries of a MachO binary and adds them to the metadata dictionary.
    """

    metadata["libraries"] = []
    if not parsed_obj.libraries:
        return metadata
    for library in parsed_obj.libraries:
        current_version_str = "{:d}.{:d}.{:d}".format(*library.current_version)
        compat_version_str = "{:d}.{:d}.{:d}".format(*library.compatibility_version)
        metadata["libraries"].append(
            {
                "name": library.name,
                "timestamp": library.timestamp,
                "version": current_version_str,
                "compatibility_version": compat_version_str,
            }
        )

    return metadata


def add_mach0_header_data(exe_file, metadata, parsed_obj):
    """
    Extract MachO header data from the parsed object and adds it to the metadata dictionary.
    """
    header = parsed_obj.header
    if not header:
        return metadata
    flags_str = ", ".join([str(s).rsplit(".", maxsplit=1)[-1] for s in header.flags_list])
    metadata["magic"] = str(header.magic).rsplit(".", maxsplit=1)[-1]
    metadata["is_neural_model"] = header.magic == lief.MachO.MACHO_TYPES.NEURAL_MODEL
    metadata["cpu_type"] = str(header.cpu_type).rsplit(".", maxsplit=1)[-1]
    metadata["cpu_subtype"] = header.cpu_subtype
    metadata["file_type"] = str(header.file_type).rsplit(".", maxsplit=1)[-1]
    metadata["flags"] = flags_str
    metadata["number_commands"] = header.nb_cmds
    metadata["size_commands"] = header.sizeof_cmds
    metadata["reserved"] = header.reserved

    return metadata


def add_mach0_functions(metadata, parsed_obj):
    """
    Extract MachO functions and symbols from the parsed object and adds them to the metadata.
    """
    metadata["functions"] = parse_functions(parsed_obj.functions)
    metadata["ctor_functions"] = parse_functions(parsed_obj.ctor_functions)
    metadata["unwind_functions"] = parse_functions(parsed_obj.unwind_functions)
    metadata["symtab_symbols"], exe_type = parse_macho_symbols(parsed_obj.symbols)
    if exe_type:
        metadata["exe_type"] = exe_type
    if parsed_obj.dylinker:
        metadata["dylinker"] = parsed_obj.dylinker.name
    return metadata


def add_mach0_signature(exe_file, metadata, parsed_obj):
    """
    Extract MachO code signature metadata from the parsed object and adds it to the metadata.
    """
    if parsed_obj.has_code_signature:
        code_signature = parsed_obj.code_signature
        metadata["code_signature"] = {
            "available": code_signature.size > 0,
            "data": str(code_signature.data.hex()),
            "data_size": str(code_signature.data_size),
            "size": str(code_signature.size),
        }
    if not parsed_obj.has_code_signature and parsed_obj.has_code_signature_dir:
        code_signature = parsed_obj.code_signature_dir
        metadata["code_signature"] = {
            "available": code_signature.size > 0,
            "data": str(code_signature.data.hex()),
            "data_size": str(code_signature.data_size),
            "size": str(code_signature.size),
        }
    if not parsed_obj.has_code_signature and not parsed_obj.has_code_signature_dir:
        metadata["code_signature"] = {"available": False}
    if parsed_obj.has_data_in_code:
        data_in_code = parsed_obj.data_in_code
        metadata["data_in_code"] = {
            "data": str(data_in_code.data.hex()),
            "data_size": str(data_in_code.data_size),
            "size": str(data_in_code.size),
        }

    return metadata
