# Similarity Unrelocated Module - Volatility 3 Plugin

`sumplugin` for **Volatility 3** (Python 3) undoes the modifications done by the
relocation process on modules (processes' `.exe` and `.dll` files) contained in
memory images. It then yields a similarity digest for each memory page of the
unrelocated modules.

> This is the **Volatility 3 / Python 3** port. The original Volatility 2.6 /
> Python 2.7 plugin lives on the [`volatility2-latest`](../../tree/volatility2-latest)
> branch.

This plugin implements two de-relocation methods:
- **Guided De-relocation** uses the `.reloc` section, when it is recoverable, to
  identify the bytes affected by relocation and then de-relocate them.
- **Linear Sweep De-relocation** first identifies the fields in the PE header and
  well-known patterns of structures. Then it uses a linear sweep disassembler to
  find instructions affected by relocation and de-relocate all affected bytes.

A Similarity Digest Algorithm (also known as approximate matching algorithm)
identifies similarities between digital artifacts. The algorithm outputs a digest
that can be compared with other digests to obtain a similarity score.

The algorithms supported are `tlsh` (default), `ssdeep`, and `sdhash`.

The de-relocation methods implemented here are described in our paper, published
in *Computers & Security* (see [Reference](#reference)):
[Pre-processing memory dumps to improve similarity score of Windows modules](https://www.sciencedirect.com/science/article/pii/S0167404820303928).

## Installation

Clone the plugin with its (nested) submodules:

```
git clone --recurse-submodules -b volatility3 https://github.com/reverseame/sum-plugin.git
```

### Dependencies

The plugin runs inside a working [Volatility 3](https://github.com/volatilityfoundation/volatility3)
installation (Python 3). Beyond Volatility 3 itself it needs:

- `capstone` — required (linear sweep disassembly)
- `pefile` — required
- `tlsh` (the standalone [python-tlsh](https://github.com/trendmicro/tlsh)
  module) — required for the default algorithm
- `ssdeep` and `fuzzyhashlib` — **optional**, only needed for the `ssdeep` and
  `sdhash` algorithms. They are imported lazily; if absent, those algorithms are
  simply unavailable and `tlsh` still works.

```
pip install capstone pefile py-tlsh
# optional, for ssdeep / sdhash:
pip install ssdeep fuzzyhashlib
```

### Docker

A reference [Dockerfile](Dockerfile) builds a self-contained Volatility 3 /
Python 3 environment with the plugin and all of its dependencies:

```
docker build -t sum-vol3 -f Dockerfile .
# the entrypoint is `vol -p /opt/sum-plugin`, so only pass -f and the plugin:
docker run --rm -it -v /path/to/dumps:/shared sum-vol3 \
    -f /shared/memory.raw sumplugin.SumPlugin --pid 252
```

## Usage

Point Volatility 3 at the cloned `sum-plugin` directory with `-p`/`--plugin-dirs`.
Volatility registers the plugin as `sumplugin.SumPlugin` (after the file name and
the `SumPlugin` class):

```
vol -f <memory image> -p /path/to/sum-plugin sumplugin.SumPlugin [options]
```

### Options

```
  --pid PID [PID ...]            Process IDs to include (default: all)
  --name REGEX                   Only processes whose name matches REGEX
  --module-name REGEX            Only modules whose name matches REGEX
                                 (e.g. --module-name ntdll  |  --module-name "kernel,advapi")
  --wow64 {0,1}                  Filter Wow64 processes (1 = only Wow64, 0 = only non-Wow64)

  --algorithm ALG [ALG ...]      Similarity digest algorithm(s): tlsh, ssdeep, sdhash
                                 (default: tlsh)
  --section SEC                  PE section(s) to hash:
                                   a section   --section .text   |  --section ".data,.rsrc"
                                   the header  --section header
                                   everything  --section all
                                 (default: the whole module image, reported as the 'PE' section)

  --compare-hash H [H ...]       Compare generated digests against the given digest(s)
  --compare-file F [F ...]       Compare against digests read from file(s), one per line

  --guided-derelocation         De-relocate guided by the .reloc section when recoverable
  --linear-sweep-derelocation   De-relocate by linear sweep disassembly
  --derelocation                Guided when possible, else linear sweep ("best")

  --list-sections               List the PE sections of each module
  --human-readable              Show a human-readable create time
  --time                        Show computation times
  --log-memory-pages FILE       Log resident pages to FILE
  --dump                        (reserved) write hashed data to the output directory
```

Notes:
- A digest file given with `--compare-file` must contain one digest per line.
- Comparisons accept a single algorithm at a time.
- **Guided de-relocation** depends on the module's `.reloc` section being
  resident in the file cache. `.reloc` is marked *discardable* and is frequently
  paged out, in which case the plugin falls back (with `--derelocation`) or skips
  the module (with `--guided-derelocation`). This is expected behaviour, not a
  bug.

### Example

```
$ vol -q -f zeus.vmem -p /path/to/sum-plugin sumplugin.SumPlugin --pid 632 --module-name ntdll --section .text --linear-sweep-derelocation
Process       Pid  PPid  Create Time  Module Base  Module End  Module Name  Wow64  Section  Section Offset  Section Size  Algorithm  Pre-process  Generated Hash             Path                          Num Page  Num Valid Page  Physical Pages
winlogon.exe  632  544   1281506783   0x7c900000   0x7c9b0000  ntdll.dll    0      .text    0x1000          0x7b000       TLSH       Linear       ['T1B581DB02...', ...]     C:\WINDOWS\system32\ntdll.dll 123       54              ['0x3aa3000', '*', ...]
```

The **Generated Hash** column holds the list of per-page digests (`*` marks a
page that is absent/zero). With `--compare-hash`/`--compare-file`, the plugin
emits one row per valid page with the resulting **Similarity** score.

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
