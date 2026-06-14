# Similarity Unrelocated Module - Volatility Plugin

`sum-plugin` for Volatility 2.6 undoes modifications done by relocation process on modules (namely, processes of .exe and .dll files) contained in memory dumps. Then it yields a Similarity Digest for each memory page of unrelocated modules.

This plugin implements two de-relocation methods: 
- **Guided De-relocation** uses the `.reloc` section, when it is recoverable from the module dump, to identify the bytes affected by relocation and then de-relocate them.
- **Linear Sweep De-relocation** first identifies the fields in the PE header and well-known patterns of structures. Then it uses a linear sweep disassembler to find instructions affected by relocation and de-relocate all affected bytes.

A Similarity Digest Algorithm (also known as approximate matching algorithm) identifies similarities between digital artifacts. In particular, the algorithm outputs a digest that can then be compared with other digests, obtaining a similarity score (which normally ranges from 0 to 100).

At the moment of this writing, the algorithms included in this plugin are `ssdeep`, `SDhash`, and `TLSH`

The de-relocation methods implemented here (Guided and Linear Sweep De-relocation) are
described in our paper, published in *Computers & Security* (see [Reference](#reference)):
[Pre-processing memory dumps to improve similarity score of Windows modules](https://www.sciencedirect.com/science/article/pii/S0167404820303928).

## Installation

You can clone `sum-plugin` with its dependencies with:\
`git clone --depth 1 --recurse-submodules --shallow-submodules https://github.com/reverseame/sum-plugin.git`

You can install all dependencies with [installdeps.sh](installdeps.sh).

### Docker

A reference [Dockerfile](Dockerfile) is provided that builds a self-contained
Volatility 2.6 / Python 2.7 environment with every dependency the plugin needs
(`ssdeep`, `fuzzyhashlib`, `capstone`, `pefile`, ...):

```
docker build -t sum-vol2 -f Dockerfile .
docker run --rm -it -v "$PWD":/plugin -v /path/to/dumps:/shared sum-vol2
# inside the container ('vol2' is an alias for Volatility 2):
vol2 --plugins=/plugin --profile=WinXPSP2x86 -f /shared/memory.dump sumplugin -p 252 -A tlsh
```

## Usage

```
SUM-plugin

Undoes modifications done by relocation process on modules in memory dumps. Then it yields a Similarity Digest for each page of unrelocated modules.

Options:
    -p: Process PID(s). Will hash given processes PIDs.
        (-p 252 | -p 252,452,2852)

    -n REGEX, --name REGEX: Process expression. Will hash processes that contain REGEX.
        (-n svchost | -n winlogon,explorer)
        
    -r REGEX, --module-name REGEX: Module expression. Will hash modules that contain REGEX.
        (-r ntdll | -r kernel,advapi)

    -A: Algorithm to use. Available: ssdeep, sdhash, tlsh. Default: tlsh
        (-A ssdeep | -A SSDeep | -A ssdeep,sdHash,TLSH)

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
    - Params -c and -C can be given multiple times (E.g. vol.py (...) -c <hash1> -c <hash2>)

```
You need to provide the path to the plugin with the [`--plugins` option of Volatility](https://github.com/volatilityfoundation/volatility/wiki/Volatility-Usage#specifying-additional-plugin-directories).
Point it at the cloned `sum-plugin` directory. Note that Volatility registers the
command as `sumplugin` (after the `SumPlugin` class):

```
vol.py --plugins /path/to/sum-plugin --profile WinProfile -f /path/to/memory.dump sumplugin
Volatility Foundation Volatility Framework 2.6.1
Process   Pid PPid Create Time Module Base Module End Module Name Wow64 ... Section Section Size Algorithm Pre-process Generated Hash                          Path                        Num Page Num Valid Page
--------- --- ---- ----------- ----------- ---------- ----------- ----- --- ------- ------------ --------- ----------- --------------------------------------- --------------------------- -------- --------------
alg.exe   216  676 1281506799   0x1000000  0x100d000  alg.exe         0 ... PE          0xd000      TLSH      Raw         07814627B36AAF76...1B4EEE75A42D7106D4 C:\WINDOWS\System32\alg.exe 13       7

[... redacted ...]
```


## Reference

This plugin is the implementation accompanying our research paper. If you use it in
your work, please cite:

> Miguel Martín-Pérez, Ricardo J. Rodríguez, Davide Balzarotti.
> **Pre-processing memory dumps to improve similarity score of Windows modules.**
> *Computers & Security*, Volume 101, 2021, 102119.
> doi: [10.1016/j.cose.2020.102119](https://doi.org/10.1016/j.cose.2020.102119)

```bibtex
@article{MartinPerez2021,
  title   = {Pre-processing memory dumps to improve similarity score of Windows modules},
  author  = {Mart{\'\i}n-P{\'e}rez, Miguel and Rodr{\'\i}guez, Ricardo J. and Balzarotti, Davide},
  journal = {Computers \& Security},
  volume  = {101},
  pages   = {102119},
  year    = {2021},
  issn    = {0167-4048},
  doi     = {10.1016/j.cose.2020.102119},
  url     = {https://www.sciencedirect.com/science/article/pii/S0167404820303928}
}
```

## License

Licensed under the [GNU GPLv3](LICENSE) license.
