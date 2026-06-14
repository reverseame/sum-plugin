# This file is part of the SUM (Similarity Unrelocated Module) plugin.
# Volatility 3 port of the original Volatility 2 plugin.
#
# SUM undoes the modifications done by the relocation process on modules
# (.exe/.dll) contained in a Windows memory image, then yields a similarity
# digest for each memory page of the unrelocated modules.
#
# Original work: https://www.sciencedirect.com/science/article/pii/S0167404820303928

import os
import re
import sys
import logging
import importlib.util

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, psscan, filescan

# The de-relocation engine lives in the sibling ``sum/`` directory, which is a
# package literally named ``sum`` that also contains a module ``sum.py``. That
# name clash makes ``from sum.sum import ...`` unreliable once Volatility's
# plugin loader has scanned the directory, so load the engine module directly
# by file path. The engine dir must be on sys.path first so the engine's own
# intra-package imports (derelocation, hashengine, marked_pefile) resolve.
_ENGINE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sum")
if _ENGINE_DIR not in sys.path:
    sys.path.insert(0, _ENGINE_DIR)

if "sum_engine" not in sys.modules:
    _spec = importlib.util.spec_from_file_location(
        "sum_engine", os.path.join(_ENGINE_DIR, "sum.py")
    )
    _engine = importlib.util.module_from_spec(_spec)
    sys.modules["sum_engine"] = _engine
    _spec.loader.exec_module(_engine)
else:
    _engine = sys.modules["sum_engine"]

SUM = _engine.SUM
PE = _engine.PE
PEFormatError = _engine.PEFormatError
section_name = _engine.section_name

vollog = logging.getLogger(__name__)

PAGE_SIZE = 4096
DEFAULT_ALGORITHM = ["tlsh"]


class SumPlugin(interfaces.plugins.PluginInterface):
    """SUM (Similarity Unrelocated Module): undoes relocation on modules in a
    memory image and yields a similarity digest per memory page."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include (all others excluded)",
                optional=True,
            ),
            requirements.StringRequirement(
                name="name",
                description="Regular expression matching process name(s)",
                optional=True,
            ),
            requirements.StringRequirement(
                name="module-name",
                description="Regular expression matching module name(s)",
                optional=True,
            ),
            requirements.IntRequirement(
                name="wow64",
                description="Filter Wow64 processes: 1 = only Wow64, 0 = only non-Wow64",
                optional=True,
            ),
            requirements.ListRequirement(
                name="algorithm",
                element_type=str,
                description="Similarity digest algorithm(s): tlsh, ssdeep, sdhash (default: tlsh)",
                default=DEFAULT_ALGORITHM,
                optional=True,
            ),
            requirements.StringRequirement(
                name="section",
                description="PE section(s) to hash (e.g. .text or .data,.rsrc or 'all')",
                optional=True,
            ),
            requirements.ListRequirement(
                name="compare-hash",
                element_type=str,
                description="Compare generated digests against the given digest(s)",
                optional=True,
            ),
            requirements.ListRequirement(
                name="compare-file",
                element_type=str,
                description="Compare against digests read from the given file(s), one per line",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="human-readable",
                description="Show human readable create time",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="time",
                description="Show computation times",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="list-sections",
                description="List the PE sections of each module",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="guided-derelocation",
                description="De-relocate guided by the .reloc section when recoverable",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="linear-sweep-derelocation",
                description="De-relocate by linear sweep disassembly",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="derelocation",
                description="Guided de-relocation when possible, else linear sweep",
                default=False,
                optional=True,
            ),
            requirements.StringRequirement(
                name="log-memory-pages",
                description="Log resident pages to the given file",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Dump the hashed sections to the output directory",
                default=False,
                optional=True,
            ),
        ]

    # -- module-name normalization & .reloc recovery -----------------------

    @staticmethod
    def _normalized_module_name(full_dll_name):
        if not full_dll_name:
            return None
        name = str(full_dll_name)
        if name[:1] != "\\":  # "C:\folder\.." style
            return name.lower()[2:]
        if re.search(r"\\SystemRoot", name, re.I):  # "\SystemRoot\.." style
            return re.sub(r"^\\SystemRoot\\", r"\\Windows\\", name).lower()
        return name.lower()

    def _acquire_system_files(self):
        """Map normalized file path -> _FILE_OBJECT for every disk file found
        by pool scanning (used to recover .reloc sections for guided mode)."""
        files = {}
        for file_obj in filescan.FileScan.scan_files(self.context, self.config["kernel"]):
            try:
                name = file_obj.file_name_with_device()
            except exceptions.InvalidAddressException:
                continue
            if not name or str(name) == "\\$Directory":
                continue
            files[str(name).lower()] = file_obj
        return files

    def _reconstruct_pe(self, file_obj):
        """Rebuild the on-disk PE image bytes from a FILE_OBJECT's
        ImageSectionObject control area, mirroring windows.dumpfiles."""
        try:
            sop = file_obj.SectionObjectPointer
            image_section = sop.ImageSectionObject
            if not image_section:
                return None
            control_area = image_section.dereference().cast("_CONTROL_AREA")
            if not control_area.is_valid():
                return None
        except exceptions.InvalidAddressException:
            return None

        primary = self.context.layers[self.config["kernel"]] if self.config["kernel"] in self.context.layers else None
        kernel = self.context.modules[self.config["kernel"]]
        primary_layer = self.context.layers[kernel.layer_name]
        memory_layer = self.context.layers[primary_layer.config["memory_layer"]]

        buf = bytearray()
        try:
            for memoffset, fileoffset, datasize in control_area.get_available_pages():
                data = memory_layer.read(memoffset, datasize, pad=True)
                if len(buf) < fileoffset + datasize:
                    buf.extend(b"\x00" * (fileoffset + datasize - len(buf)))
                buf[fileoffset:fileoffset + datasize] = data
        except exceptions.InvalidAddressException:
            return None

        if not buf:
            return None
        try:
            return PE(data=bytes(buf), fast_load=True)
        except PEFormatError:
            return None

    def _get_reloc(self, full_dll_name):
        """Return the raw .reloc section bytes for a module, or None."""
        norm = self._normalized_module_name(full_dll_name)
        if not norm:
            return None
        if norm in self._reloc_cache:
            return self._reloc_cache[norm]

        reloc_data = None
        file_obj = self._system_files.get(norm)
        if file_obj is not None:
            pe = self._reconstruct_pe(file_obj)
            if pe is not None:
                for sec in pe.sections:
                    if sec.Name[:6] == b".reloc":
                        reloc_data = sec.get_data()
                        break
                if reloc_data and any(reloc_data):
                    pass
                else:
                    reloc_data = None
        self._reloc_cache[norm] = reloc_data
        return reloc_data

    # -- memory helpers -----------------------------------------------------

    def _read_module(self, proc_layer, base, size):
        data = proc_layer.read(base, size, pad=True)
        valid_pages = []
        for off in range(0, size, PAGE_SIZE):
            phys = 0
            for m in proc_layer.mapping(base + off, 1, ignore_errors=True):
                phys = m[2]  # mapped_offset (physical address of the page)
                break
            valid_pages.append(phys)
        return data, valid_pages

    # -- output -------------------------------------------------------------

    def _columns(self, compare, show_time):
        cols = [
            ("Process", str), ("Pid", int), ("PPid", int), ("Create Time", str),
            ("Module Base", format_hints.Hex), ("Module End", format_hints.Hex),
            ("Module Name", str), ("Wow64", int),
            ("Section", str), ("Section Offset", format_hints.Hex),
            ("Section Size", format_hints.Hex), ("Algorithm", str),
            ("Pre-process", str), ("Generated Hash", str), ("Path", str),
            ("Num Page", int), ("Num Valid Page", int),
        ]
        if show_time:
            cols += [
                ("Computation Time", str), ("PE Memory Time", str),
                ("Pre-processing Time", str),
            ]
        cols.append(("Physical Pages", str))
        if compare:
            cols += [("Compared Digest", str), ("Compared Page", int), ("Similarity", str)]
            if show_time:
                cols.append(("Comparison Time", str))
        return cols

    @staticmethod
    def _phys_str(valid_pages):
        return str([hex(p) if p else "*" for p in valid_pages])

    def _generator(self, procs):
        compare = bool(self.config.get("compare-hash") or self.config.get("compare-file"))
        show_time = bool(self.config.get("time"))
        list_sections = bool(self.config.get("list-sections"))
        algorithms = self.config.get("algorithm") or DEFAULT_ALGORITHM

        guided = bool(self.config.get("guided-derelocation"))
        dereloc_opt = bool(self.config.get("derelocation"))
        linear = bool(self.config.get("linear-sweep-derelocation"))

        # For guided/derelocation we need the system file objects to recover .reloc
        self._system_files = {}
        self._reloc_cache = {}
        if guided or dereloc_opt:
            self._system_files = self._acquire_system_files()

        module_re = None
        if self.config.get("module-name"):
            module_re = re.compile(".*{0}.*".format(self.config["module-name"].replace(",", ".*|.*")), re.I)

        hashes = list(self.config.get("compare-hash") or []) or None
        hash_files = list(self.config.get("compare-file") or []) or None

        for proc in procs:
            try:
                wow64 = bool(proc.get_is_wow64())
            except Exception:
                wow64 = False
            if self.config.get("wow64") is not None:
                want = self.config["wow64"]
                if (want == 0 and wow64) or (want == 1 and not wow64):
                    continue

            try:
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException:
                continue
            proc_layer = self.context.layers[proc_layer_name]
            proc_name = proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors="replace")
            pid = int(proc.UniqueProcessId)
            ppid = int(proc.InheritedFromUniqueProcessId)
            try:
                create_time = proc.get_create_time()
                create_time = str(create_time) if self.config.get("human-readable") else str(int(create_time.timestamp()))
            except Exception:
                create_time = renderers.NotAvailableValue()

            for entry in proc.load_order_modules():
                try:
                    base = int(entry.DllBase)
                    size = int(entry.SizeOfImage)
                except exceptions.InvalidAddressException:
                    continue
                if not size:
                    continue
                try:
                    mod_name = str(entry.BaseDllName.get_string())
                except exceptions.InvalidAddressException:
                    mod_name = ""
                try:
                    full_name = str(entry.FullDllName.get_string())
                except exceptions.InvalidAddressException:
                    full_name = ""

                if module_re and not module_re.search(mod_name):
                    continue

                # Decide de-relocation method per module
                reloc = None
                derelocation = "raw"
                if guided or dereloc_opt:
                    reloc = self._get_reloc(full_name)
                    if reloc:
                        derelocation = "guide"
                    else:
                        vollog.warning("%s: .reloc section cannot be found", mod_name)
                        if guided:
                            continue
                if (dereloc_opt and not reloc) or linear:
                    derelocation = "linear"

                try:
                    data, valid_pages = self._read_module(proc_layer, base, size)
                except exceptions.InvalidAddressException:
                    continue

                try:
                    engine = SUM(
                        data=data,
                        algorithms=algorithms,
                        base_address=base,
                        derelocation=derelocation,
                        dump_dir=None,
                        list_sections=list_sections,
                        log_memory_pages=self.config.get("log-memory-pages"),
                        reloc=reloc,
                        section=self.config.get("section"),
                        virtual_layout=True,
                        valid_pages=valid_pages,
                        compare_file=hash_files,
                        compare_hash=hashes,
                    )
                    results = list(engine.calculate())
                except Exception as e:  # noqa - one bad module shouldn't kill the run
                    vollog.debug("SUM failed for %s (pid %d): %r", mod_name, pid, e)
                    continue

                if list_sections:
                    # The engine yields the section list as its first result.
                    sections = results[0].get("section") if results else []
                    head = [str(proc_name), pid, ppid, str(create_time),
                            format_hints.Hex(base), format_hints.Hex(base + size),
                            mod_name, int(wow64), ", ".join(sections),
                            format_hints.Hex(0), format_hints.Hex(0), "", "", "", full_name, 0, 0]
                    if show_time:
                        head += ["", "", ""]
                    head.append(self._phys_str([]))
                    if compare:
                        head += ["", 0, ""]
                        if show_time:
                            head.append("")
                    yield (0, tuple(head))
                    continue

                for digest in results:
                    row = [
                        str(proc_name), pid, ppid, str(create_time),
                        format_hints.Hex(base), format_hints.Hex(base + size),
                        mod_name if mod_name else str(digest.get("mod_name")), int(wow64),
                        str(digest.get("section")),
                        format_hints.Hex(int(digest.get("virtual_address") or 0)),
                        format_hints.Hex(int(digest.get("size") or 0)),
                        str(digest.get("algorithm")),
                        str(digest.get("preprocess")),
                        str(digest.get("digest")),
                        full_name,
                        int(digest.get("num_pages") or 0),
                        int(digest.get("num_valid_pages") or 0),
                    ]
                    if show_time:
                        row += [
                            str(digest.get("digesting_time")),
                            str(digest.get("pe_time")),
                            str(digest.get("pre_processing_time")),
                        ]
                    row.append(self._phys_str(digest.get("valid_pages") or []))
                    if compare:
                        row += [
                            str(digest.get("compared_digest")),
                            int(digest.get("compared_page") or 0),
                            str(digest.get("similarity")),
                        ]
                        if show_time:
                            row.append(str(digest.get("comparison_time")))
                    yield (0, tuple(row))

    def run(self):
        compare = bool(self.config.get("compare-hash") or self.config.get("compare-file"))
        show_time = bool(self.config.get("time"))
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        procs = pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            filter_func=filter_func,
        )
        return renderers.TreeGrid(self._columns(compare, show_time), self._generator(procs))
