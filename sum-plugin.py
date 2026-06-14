import os
import re
import json
import time
import hashlib

import volatility.obj as obj
import volatility.debug as debug
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.constants as constants
import volatility.exceptions as exceptions
import volatility.win32.modules as modules
from volatility.plugins.common import AbstractWindowsCommand
import volatility.plugins as plugins
import volatility.conf as conf

from PrintableObjects import ModuleObject, CompareObject
from sum.sum import SUM, PE, PEFormatError


MODE_32 = '32bit'
MODE_64 = '64bit'
PAGE_SIZE = 4096
DEFAULT_ALGORITHM = ['tlsh']

class SumPlugin(AbstractWindowsCommand):
    __doc__ = """SUM (Similarity Unrelocated Module)

        Undoes modifications done by relocation process on modules in memory dumps. Then it yields a Similarity Digest for each page of unrelocated modules.

        Options:
          -p: Process PID(s). Will hash given processes PIDs.
                (-p 252 | -p 252,452,2852)

          -n REGEX, --name REGEX: Process expression. Will hash processes that contain REGEX.
                (-n svchost | -n winlogon,explorer)
                
          -r REGEX, --module-name REGEX: Module expression. Will hash modules that contain REGEX.
                (-D ntdll | -D kernel,advapi)

          --wow64 [0|1]: Filter of Wow64 process.
                (--wow64 0 | --wow64 1)

          -A: Algorithm to use. Available: ssdeep, sdhash, tlsh. Default: tlsh
                (-A ssdeep | -A SSDeep | -A ssdeep,sdHash,tlsh)

          -S: Section to hash
               PE section (-S .text | -S .data,.rsrc)
               PE header (-S header | -S .data,header,.rsrc)
               All PE sections including main executable module (-S all)

          -c: Compare given hash against generated hashes.
                (E.g. -c '3:elHLlltXluBGqMLWvl:6HRlOBVrl')
          -C: Compare given hashes' file against generated hashes.
                (E.g. -C /tmp/hashfile.txt)

          -H: Human readable values (Create Time)
          -t: Show computation time

          -D DIR, --dump-dir=DIR: Temp folder to write all data

          --output-file=<file>: Plugin output will be writen to given file.
          --output=<format>: Output formatting. [text, dot, html, json, sqlite, quick, xlsx]

          --list-sections: Show PE sections

          --json: Json output formatting.

          --guided-derelocation: De-relocate modules guided by .reloc section when it is found

          --linear-sweep-derelocation: De-relocate modules by sweep linear disassembling, recognizing table patterns and de-relocating IAT

          --derelocation: De-relocate modules using guided pre-processing when it is posible, else use linear sweep de-relocation

          --log-memory-pages LOGNAME: Log pages which are in memory to LOGNAME

        Note:
          - Hashes' file given with -C must contain one hash per line.
          - Params -c and -C can be given multiple times (E.g. vol.py (...) -c <hash1> -c <hash2>)"""

    def __init__(self, config, *args, **kwargs):
        AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('PID', short_option='p', help='Process ID', action='store',type='str')
        self._config.add_option('NAME', short_option='n', help='Expression containing process name', action='store', type='str')
        self._config.add_option('MODULE-NAME', short_option='r', help='Modules matching MODULE-NAME', action='store', type='str')
        self._config.add_option('WOW64', help='Filter of wow64 process', action='store', type='str')
        self._config.add_option('ALGORITHM', short_option='A', default=DEFAULT_ALGORITHM, help='Hash algorithm', action='store', type='str')
        self._config.add_option('SECTION', short_option='S', help='PE section to hash', action='store', type='str')
        self._config.add_option('COMPARE-HASH', short_option='c', help='Compare to given hash', action='append', type='str')
        self._config.add_option('COMPARE-FILE', short_option='C', help='Compare to hashes\' file', action='append', type='str')
        self._config.add_option('HUMAN-READABLE', short_option='H', help='Show human readable values', action='store_true')
        self._config.add_option('TIME', short_option='t', help='Print computation time', action='store_true')
        self._config.add_option('DUMP-DIR', short_option='D', help='Directory in which to dump files', action='store', type='str')
        self._config.add_option('LIST-SECTIONS', help='Show PE sections', action='store_true')
        self._config.add_option('JSON', help='Print JSON output', action='store_true')
        self._config.add_option('GUIDED-DERELOCATION', help='De-relocate modules guided by .reloc section when it is found', action='store_true')
        self._config.add_option('LINEAR-SWEEP-DERELOCATION', help='De-relocate modules by sweep linear disassembling, recognizing table patterns and de-relocating IAT', action='store_true')
        self._config.add_option('DERELOCATION', short_option='u', help='De-relocate modules using guided pre-processing when it is posible, else use linear sweep de-relocation', action='store_true')
        self._config.add_option('LOG-MEMORY-PAGES', help='Log pages which are in memory to FILE', action='store', type='str')
        self.reloc_list = {}
        self.files_opened_in_system = {}

    def calculate(self):
        """Main volatility plugin function"""
        try:
            self.addr_space = utils.load_as(self._config)
            pids = self.get_processes()
            if not pids:
                debug.error('{0}: Could not find any process with those options'.format(self.get_plugin_name()))

            for dump in self.dll_dump(pids):
                yield dump

        except KeyboardInterrupt:
            debug.error('KeyboardInterrupt')

    def get_processes(self):
        """
        Return all processes id by either name, expresion or pids

        @returns a list containing all desired pids
        """

        pids = []

        if self._config.NAME:
            # Prepare all processes names as regular expresions
            names = '.*{0}.*'.format(self._config.NAME.replace(',', '.*,.*')).split(',')
            pids = self.get_proc_by_name(names)
        else:
            pids = self.get_proc_by_pid(self._config.PID)

        return pids

    def get_proc_by_name(self, names):
        """
        Search all processes by process name

        @para names: a list with all names to search

        @returns a list of pids
        """
        ret = []

        for proc in tasks.pslist(self.addr_space):
            mod = self.get_exe_module(proc)
            if not mod:
                continue
            for name in names:
                if re.search(name, str(mod.BaseDllName), flags=re.IGNORECASE):
                    ret += [proc.UniqueProcessId]
                    break
        return ret

    def get_exe_module(self, task):
        """
        Return main exe module

        @para task: process

        @returns exe module
        """
        for mod in task.get_load_modules():
            return mod

        return ''

    def get_proc_by_pid(self, pids):
        """
        Search all processes which its pid matches

        @para names: a list with all pids to search

        @returns a list of pids
        """

        ret = []

        if pids:
            pids = pids.split(',')
            for proc in tasks.pslist(self.addr_space):
                if not proc.ExitTime:
                    # Check if those pids exist in memory dump file
                    if str(proc.UniqueProcessId) in pids:
                        ret += [proc.UniqueProcessId]
        else:
            # Return all pids if none is provided
            for proc in tasks.pslist(self.addr_space):
                # Only return those which are currently running
                if not proc.ExitTime:
                    ret += [proc.UniqueProcessId]

        return ret

    def get_pe_sections(self, pe):
        """
        Return all section names from pe, deleting final zero bytes
        
        @param pe: PE structure 

        @returns a list containing all section names
        """
        ret = []
        for sec in pe.sections:
            ret += [sec.Name.translate(None, '\x00')]

        return ret

    def process_section(self, task, section_expr, pe):
        """
        Generate one dump file for every section

        @param task: process
        @param section: sections to dump
        @param dump_path: PE dump path to process

        @returns a list of dicts containing each section and dump path associated
        """
        if not section_expr:
            return [pe.sections[-1]]

        ret = []


        section_expr = section_expr.split(',')
        if 'all' in section_expr:
            return pe.sections[:-1]
        else:
            for section in pe.sections:
                for expresion in section_expr:
                    if re.search(expresion, section.Name):
                        ret.append(section)
                        break
        return ret

    def process_pe_header(self, pe, header):
        """
        Retrieve desired PE header

        @param pe: PE object
        @param header: PE header to search

        @return a dict containing header and dump file associated
        """

        try:
            if header == 'header':
                data = pe.__getattribute__(header)
            else:
                # Try to get specified PE header
                data = pe.__getattribute__(header.upper()).__pack__()
            return {'section': header, 'data': data, 'offset': 0, 'size': len(data)}
        except AttributeError:
            debug.error(
                '{0}: \'{1}\': Bad header option (DOS_HEADER, NT_HEADERS, FILE_HEADER, OPTIONAL_HEADER or header)'.format(
                    self.get_plugin_name(), header.split(':')[-1]))

    def dll_dump(self, pids):
        """
        Generate dump files containing all modules loaded by a process

        @param pids: pid list to dump

        @returns a list of DLLObject sorted by (pid, mod.BaseAddress)
        """
        if self._config.MODULE_NAME:
            dlls_expression = '.*{0}.*'.format(self._config.MODULE_NAME.replace(',', '.*|.*'))

        else:
            dlls_expression = None

        if self._config.DERELOCATION or self._config.GUIDED_DERELOCATION:
            # acquiring all dlls and exes that were opened in system
            acquire_sys_file_handlers(self, conf)

        for task in tasks.pslist(self.addr_space):

            # Wow64 filter
            if self._config.WOW64:
                if (self._config.WOW64 == '0' and task.IsWow64) or (self._config.WOW64 == '1' and not task.IsWow64):
                    continue

            if task.UniqueProcessId in pids:
                task_space = task.get_process_address_space()
                mods = dict((mod.DllBase.v(), mod) for mod in task.get_load_modules())
                for mod in mods.values():
                    mod_base = mod.DllBase.v()
                    mod_end = mod_base + mod.SizeOfImage
                    #if task_space.is_valid_address(mod_base):
                    mod_name = mod.BaseDllName.v()
                    if dlls_expression and type(mod_name) != obj.NoneObject:
                        if not re.search(dlls_expression, mod_name, flags=re.IGNORECASE):
                            continue
                    valid_pages = [task_space.vtop(mod.DllBase+i) for i in range(0, mod.SizeOfImage, PAGE_SIZE)]

                    vinfo = obj.Object("_IMAGE_DOS_HEADER", mod.DllBase, task_space).get_version_info()
                    create_time = str(task.CreateTime) if self._config.HUMAN_READABLE else int(
                        task.CreateTime)

                    reloc = None
                    derelocation = 'raw'
                    if self._config.DERELOCATION or self._config.GUIDED_DERELOCATION:
                        # Retrieving the .reloc section of the module
                        reloc = get_reloc_section(self, mod)
                        if reloc:
                            derelocation = 'guide'
                        else:
                            debug.warning('Warning: {0}\'s reloc section cannot be found.'.format(mod_name))
                            if self._config.GUIDED_DERELOCATION:
                                continue
                    if (self._config.DERELOCATION and not reloc) or self._config.LINEAR_SWEEP_DERELOCATION:
                        derelocation = 'linear'

                    if self._config.COMPARE_HASH:
                        hashes = self._config.COMPARE_HASH[0].split(',')
                    else:
                        hashes = None
                    if self._config.COMPARE_FILE:
                        hashe_files = self._config.COMPARE_FILE[0].split(',')
                    else:
                        hashe_files = None

                    for digest in SUM(data=task_space.zread(mod.DllBase, mod.SizeOfImage), algorithms=self._config.ALGORITHM.split(',') if self._config.ALGORITHM else DEFAULT_ALGORITHM, base_address=mod.DllBase.v(), derelocation=derelocation, dump_dir=self._config.DUMP_DIR, list_sections=self._config.LIST_SECTIONS, log_memory_pages=self._config.LOG_MEMORY_PAGES, reloc=reloc, section=self._config.SECTION, virtual_layout=True, valid_pages=valid_pages, compare_file=hashe_files, compare_hash=hashes).calculate():
                        # print(digest)

                        if type(mod_name) == obj.NoneObject:
                            mod_name = digest.get('mod_name')
                        
                        if self._config.COMPARE_HASH or self._config.COMPARE_FILE:
                             yield CompareObject(task, digest.get('digest'), digest.get('algorithm'), mod_base, mod_end, mod_name,
                                        digest.get('section'), create_time,
                                        vinfo.FileInfo.file_version() if vinfo else '',
                                        vinfo.FileInfo.product_version() if vinfo else '',
                                        mod.FullDllName.v() if type(mod.FullDllName.v()) != obj.NoneObject else '', digest.get('num_pages'), digest.get('num_valid_pages'), print_time=self._config.TIME,
                                        offset=digest.get('virtual_address'), size=digest.get('size'), pe_memory_time=digest.get('pe_time'), pre_processing_time=digest.get('pre_processing_time'),
                                        physical_addresses=digest.get('valid_pages'), preprocess=digest.get('preprocess'), warnings=digest.get('warnings'), digesting_time=digest.get('digesting_time'), valid_pages=digest.get('valid_pages'),
                                        compared_digest=digest.get('compared_digest'), compared_page=digest.get('compared_page'), similarity=digest.get('similarity'), comparison_time=digest.get('comparison_time'))
                        
                        else:
                            yield ModuleObject(task, digest.get('digest'), digest.get('algorithm'), mod_base, mod_end, mod_name,
                                        digest.get('section'), create_time,
                                        vinfo.FileInfo.file_version() if vinfo else '',
                                        vinfo.FileInfo.product_version() if vinfo else '',
                                        mod.FullDllName.v() if type(mod.FullDllName.v()) != obj.NoneObject else '', digest.get('num_pages'), digest.get('num_valid_pages'), print_time=self._config.TIME,
                                        offset=digest.get('virtual_address'), size=digest.get('size'), pe_memory_time=digest.get('pe_time'), pre_processing_time=digest.get('pre_processing_time'),
                                        physical_addresses=digest.get('valid_pages'), preprocess=digest.get('preprocess'), warnings=digest.get('warnings'), digesting_time=digest.get('digesting_time'), valid_pages=digest.get('valid_pages'))
                        
        if 'logfile' in locals():
            logfile.close()

    def compare_hash(self, dump, hash_):
        """Compare hash for every dump Object"""

        for h in hash_:
            yield CompareObject(dump, h, self._config.TIME)

    def read_hash_files(self, paths):
        ret = []

        try:
            for path in paths:
                with open(path) as f:
                    ret += [x.strip() for x in f.readlines()]
        except IOError:
            debug.error('{0}: \'{1}\': Can not open file'.format(self.get_plugin_name(), path))

        return ret

    def backup_file(self, path, data):
        with open(path, 'wb') as f:
            return f.write(data)

    def prepare_working_dir(self):
        if self._config.DUMP_DIR:
            temp_path = os.path.realpath(self._config.DUMP_DIR)
            if not os.path.exists(temp_path):
                os.makedirs(temp_path)
            return temp_path
        else:
            return ''

    def render_text(self, outfd, data):
        first = True
        for item in data:
            if self._config.JSON:
                outfd.write('{0}\n'.format(item._json()))
            else:
                if first:
                    self.table_header(outfd, item.get_unified_output())
                    first = False
                # Transform list to arguments with * operator
                self.table_row(outfd, *item.get_generator())

    def get_plugin_name(self):
        return os.path.splitext(os.path.basename(__file__))[0]

def acquire_sys_file_handlers(PFH, conf):
    ''' Acquiring all dlls and exes that were opened in system
    '''

    # FileScan needs a config without this plugin's own options, so we strip them
    config = conf.ConfObject()
    for option in ['PID', 'NAME', 'MODULE-NAME', 'WOW64', 'ALGORITHM', 'SECTION',
                   'COMPARE-HASH', 'COMPARE-FILE', 'HUMAN-READABLE', 'TIME', 'DUMP-DIR',
                   'LIST-SECTIONS', 'JSON', 'GUIDED-DERELOCATION', 'LINEAR-SWEEP-DERELOCATION',
                   'DERELOCATION', 'LOG-MEMORY-PAGES']:
        try:
            config.remove_option(option)
        except (KeyError, ValueError):
            pass

    # Filtering end file name
    fs = plugins.filescan.FileScan(config)
    for file_opened in fs.calculate():
        if file_opened.FileName == '\$Directory':
            continue
        PFH.files_opened_in_system[str(file_opened.FileName).lower()] = file_opened

def get_reloc_section(self, mod):
    mod_sys_name = get_normalized_module_name(mod)
    if mod_sys_name:
        reloc_data = self.reloc_list.get(mod_sys_name)  # Retrieving reloc section previously found
        if not reloc_data:
            file_handler = self.files_opened_in_system.get(mod_sys_name)  # Finding file handler
            if file_handler:
                try:
                    pe = get_pe_from_file_object(self, file_handler)
                    if pe:
                        reloc_section = get_section(pe, '.reloc')
                        if reloc_section:
                            reloc_data = reloc_section.get_data()
                        if reloc_data and valid_section(reloc_data):
                            self.reloc_list[mod_sys_name] = reloc_data
                        else:
                            self.reloc_list[mod_sys_name] = None
                            debug.debug('Invalid reloc section for {0}\n'.format(file_handler.FileName))
                            return None
                    else:
                        debug.debug('Error: PEfile coulde not be created for {0}\n'.format(file_handler.FileName))
                    del pe
                except PEFormatError as e:
                    debug.debug('Error retrieving Reloc for {0}\n'.format(file_handler.FileName))
                    self.reloc_list[mod_sys_name] = None
                    return None
            else:
                debug.debug('{0} does not have file_handler\n'.format(mod_sys_name))
        return reloc_data
    else: 
        debug.debug('Error retrieving module name\n')
        return None

def get_normalized_module_name(mod):
    # Normalizing module name
    if mod.FullDllName:
        if str(mod.FullDllName)[0] != '\\':  # "C:\folder1\folder2\.." or "D:\folder1\folder2\.."
            return str(mod.FullDllName).lower()[2::]
        elif re.search(r'\\SystemRoot', str(mod.FullDllName), re.I):  # "\SystemRoot\FolderX\.."
            return re.sub(r'^\\SystemRoot\\', r'\\Windows\\', str(mod.FullDllName)).lower()
        else:
            debug.debug('Warning: Module name pattern not recognized for {0}'.format(str(mod.FullDllName)))
            return str(mod.FullDllName).lower()
    else:
        return None

def get_pe_from_file_object(self, file_obj):
    try:
        # This code is copied from volatility/plugins/dumpfile
        all_list = []
        control_area_list = []
        offset = file_obj.obj_offset
        name = None

        if file_obj.FileName:
            name = str(file_obj.file_name_with_device())

        # The SECTION_OBJECT_POINTERS structure is used by the memory
        # manager and cache manager to store file-mapping and cache information
        # for a particular file stream. We will use it to determine what type
        # of FILE_OBJECT we have and how it should be parsed.
        if file_obj.SectionObjectPointer:
            DataSectionObject = file_obj.SectionObjectPointer.DataSectionObject
            ImageSectionObject = file_obj.SectionObjectPointer.ImageSectionObject

            # The ImageSectionObject is used to track state information for
            # an executable file stream. We will use it to extract memory
            # mapped binaries.

            if ImageSectionObject and ImageSectionObject != 0:
                summaryinfo = {}
                # It points to a image section object( CONTROL_AREA )
                control_area = ImageSectionObject.dereference_as('_CONTROL_AREA')

                if not control_area in control_area_list:
                    control_area_list.append(control_area)

                    # The format of the filenames: file.<pid>.<control_area>.[img|dat]
                    ca_offset_string = "0x{0:x}".format(control_area.obj_offset)
                    #file_string = ".".join(["file", str(pid), ca_offset_string, IMAGE_EXT])
                    #of_path = os.path.join(self._config.DUMP_DIR, file_string)
                    (mdata, zpad) = control_area.extract_ca_file(True) # Try to set True
                    summaryinfo['name'] = name
                    summaryinfo['type'] = "ImageSectionObject"
                    summaryinfo['present'] = mdata
                    summaryinfo['pad'] = zpad
                    summaryinfo['fobj'] = int(offset)
                    #summaryinfo['ofpath'] = of_path
                    all_list.append(summaryinfo)

            # The DataSectionObject is used to track state information for
            # a data file stream. We will use it to extract artifacts of
            # memory mapped data files.

            if DataSectionObject and DataSectionObject != 0:
                summaryinfo = {}
                # It points to a data section object (CONTROL_AREA)
                control_area = DataSectionObject.dereference_as('_CONTROL_AREA')

                if not control_area in control_area_list:
                    control_area_list.append(control_area)

                    # The format of the filenames: file.<pid>.<control_area>.[img|dat]
                    ca_offset_string = "0x{0:x}".format(control_area.obj_offset)

                    #file_string = ".".join(["file", str(pid), ca_offset_string, DATA_EXT])
                    #of_path = os.path.join(self._config.DUMP_DIR, file_string)

                    (mdata, zpad) = control_area.extract_ca_file(False)
                    summaryinfo['name'] = name
                    summaryinfo['type'] = "DataSectionObject"

                    summaryinfo['present'] = mdata
                    summaryinfo['pad'] = zpad
                    summaryinfo['fobj'] = int(offset)
                    #summaryinfo['ofpath'] = of_path
                    all_list.append(summaryinfo)

        output = []
        self.kaddr_space = utils.load_as(self._config)
        for summaryinfo in all_list:
            if summaryinfo['type'] == "DataSectionObject":
                if len(summaryinfo['present']) == 0:
                    continue

                for mdata in summaryinfo['present']:
                    rdata = None
                    if not mdata[0]:
                        continue

                    try:
                        rdata = self.kaddr_space.base.read(mdata[0], mdata[2])
                    except (IOError, OverflowError):
                        debug.debug("IOError: Pid: {0} File: {1} PhysAddr: {2} Size: {3}".format(summaryinfo['pid'], summaryinfo['name'], mdata[0], mdata[2]))

                    if not rdata:
                        continue
                    if len(output) < mdata[1]:
                        output += ['\x00'] * (mdata[1]-len(output))
                    if len(output) == mdata[1]:
                        output += rdata
                    if len(output) < mdata[1] + mdata[2]:
                        if len(output) < mdata[1] + mdata[2]:
                            output += ['\x00'] * (mdata[1] + mdata[2] - len(output))
                        for index in range(0, mdata[2]):
                            output[mdata[1] + index] = rdata[index]

                    continue

            elif summaryinfo['type'] == "ImageSectionObject":
                if len(summaryinfo['present']) == 0:
                    continue

                for mdata in summaryinfo['present']:
                    rdata = None
                    if not mdata[0]:
                        continue

                    try:
                        rdata = self.kaddr_space.base.read(mdata[0], mdata[2])
                    except (IOError, OverflowError):
                        debug.debug("IOError: Pid: {0} File: {1} PhysAddr: {2} Size: {3}".format(summaryinfo['pid'],
                                                                                                 summaryinfo['name'],
                                                                                                 mdata[0], mdata[2]))

                    if not rdata:
                        continue
                    if len(output) < mdata[1]:
                        output += ['\x00'] * (mdata[1]-len(output))
                    if len(output) == mdata[1]:
                        output += rdata
                        continue
                    if len(output) < mdata[1] + mdata[2]:
                        if len(output) < mdata[1] + mdata[2]:
                            output += ['\x00'] * (mdata[1] + mdata[2] - len(output))
                        for index in range(0, mdata[2]):
                            output[mdata[1] + index] = rdata[index]
                    continue
            else:
                debug.debug("Caso no esperado: {0}".format(summaryinfo['type']))
        if output:
            output = ''.join(output)
            try:
                pe = PE(data=output, fast_load=True)
                del output
                return pe
            except PEFormatError:
                pass
        else:
            return None
    except AttributeError:
        debug.debug("Warning: Something was wrong when retrieving {0} from dump".format(file_obj.FileName))
        return None

def get_section(pe, section_name):
    for section in pe.sections:
        if section.Name[:len(section_name)] == section_name:
            return section
    return None

def valid_section(page):
    for byte in page:
        if ord(byte) != 0:
            return True
    return False