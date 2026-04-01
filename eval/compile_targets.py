"""
compile_targets.py  –  Compile an input .c file two ways:

  1. debug build   : -g -O0 -no-pie   → DWARF symbols intact
                     Ghidra will read the debug info and use real names.

  2. stripped build: -O0 -no-pie, then `strip`
                     Ghidra sees only addresses → FUN_xxx / uVar1 placeholders.
                     This is the input the REtard agent will work on.
"""

import subprocess
import shutil
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _run(cmd: list[str], label: str) -> None:
    """Run a subprocess, raise on failure."""
    print(f"[compile] {label}")
    print(f"          $ {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"{label} failed (exit {result.returncode}):\n"
            f"STDOUT: {result.stdout}\n"
            f"STDERR: {result.stderr}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def compile_debug(source_file: str | Path, output_binary: str | Path) -> Path:
    """
    Compile *source_file* with full debug information (-g -O0 -no-pie).

    Ghidra can read the DWARF data and will present the original variable and
    function names in its decompilation – these become our ground-truth labels.

    Returns the path to the resulting ELF binary.
    """
    src  = Path(source_file).resolve()
    out  = Path(output_binary).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    cmd = ["gcc", "-g", "-O0", "-no-pie", str(src), "-o", str(out)]
    _run(cmd, "Debug compile")

    print(f"[compile] ✔  Debug binary  → {out}")
    return out


def compile_stripped(source_file: str | Path, output_binary: str | Path) -> Path:
    """
    Compile *source_file* without debug info and then strip all symbols.

    Steps
    -----
    1. gcc -O0 -no-pie  →  temporary ELF with minimal info
    2. strip --strip-all  →  removes symbol table + debug sections
    3. (optional) objcopy --remove-section=.comment for cleanliness

    The result is what an analyst would receive: no helpful names at all.

    Returns the path to the stripped binary.
    """
    src  = Path(source_file).resolve()
    out  = Path(output_binary).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    # Step 1 – compile
    cmd_compile = ["gcc", "-O0", "-no-pie", str(src), "-o", str(out)]
    _run(cmd_compile, "Stripped compile")

    # Step 2 – strip
    if shutil.which("strip"):
        cmd_strip = ["strip", "--strip-all", str(out)]
        _run(cmd_strip, "strip --strip-all")
    else:
        print("[compile] WARNING: `strip` not found – binary may retain some symbols.")

    print(f"[compile] ✔  Stripped binary → {out}")
    return out


def compile_both(
    source_file: str | Path,
    workspace: str | Path,
    debug_name: str   = "target_debug",
    stripped_name: str = "target_stripped",
) -> tuple[Path, Path]:
    """
    Convenience wrapper: compile debug and stripped versions into *workspace*.

    Returns (debug_binary, stripped_binary).
    """
    ws = Path(workspace)
    ws.mkdir(parents=True, exist_ok=True)

    debug_bin   = compile_debug(source_file,   ws / debug_name)
    stripped_bin = compile_stripped(source_file, ws / stripped_name)

    return debug_bin, stripped_bin
