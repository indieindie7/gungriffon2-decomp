# Gungriffon II (Sega Saturn, JP, Game Arts / ESP 1998) reverse-engineering names

Function names for the Saturn mech shooter **Gungriffon II** (disc id T-4511G V1.001). Every code program on the disc is
loaded as a raw SH-2 image and every function carries a name (0 `FUN_` placeholders left).

| Program (disc file) | Load base | Functions | Still `provisional` |
|---|---|---|---|
| loader "0" (IP.BIN) | 0x0600A000 | 56 | 56 |
| PROG1 (`1`) | 0x0600E800 | 56 | 54 |
| PROG2 (`2`) | 0x0600E800 | 258 | 256 |
| PROG3 (`3`) | 0x0600E800 | 187 | 185 |
| ROBSYS.BIN | 0x0600E800 | 640 | 616 |
| PROG4 (`4`) | 0x06010000 | 179 | 173 |
| LOGO2.BIN | 0x06010000 | 95 | 86 |
| **Total** | | **1,471** | **1,430** |

Skipped as data: `2_1`, `2_2`, `4_1`..`4_4`, `S*_PACK.*`, `*.REP`, `SCSPDRV.BIN` (68k sound driver), `GG2.EXB`, `.STB`.

**Names are heuristic.** About 300 come from Gungriffon 1 (`indieindie7/gungriffon-decomp`) by identical normalized body
(comment `[from GG1 ...]`). The rest were written from truncated decompile reading and are marked `provisional`:
library families (libc, soft-float, SMPC, SCU DMA, VDP) are reliable, game-logic names (`game_StepPlayerX`, `unit_BehaviorX`) are placeholders by role only.

**No game data is included**: no disc image, executables, decompiled C or game text.

## Layout
| Path | Content |
|---|---|
| `ghidra/hand_<PROG>.txt` | `0x<addr> func <name> hand <comment>` (ApplyNames.java, hand mode) |
| `ghidra/funcinfo_<PROG>.tsv` | per-function export: `F` address name source size, `C` callees |
| `ghidra/naming/q*.txt` | the naming slices as applied |
| `ghidra/scripts/` | FindSh2FunctionsMem, ApplyNames, ExportFuncInfo, CsDumpAll and helpers |
| `tools/` | basechk/basefind (load bases), xstage/carry (GG1 name carry), decmerge, qconv, others |

## Reproduce
1. Extract the disc files yourself (2352-byte raw track 1).
2. `tools/basechk.py` confirms each base; import as raw binary, language `SuperH:BE:32:SH-2`, base from the table (`ghidra/import.sh`, `importall.sh`).
3. Run `FindSh2FunctionsMem.java`, then `ghidra/run1.sh <PROG>` (merges `hand_<PROG>.txt`, applies names, re-exports).

Non-commercial study and preservation. Notes, names and tools: MIT (`LICENSE`). Gungriffon II belongs to its rights holders.
