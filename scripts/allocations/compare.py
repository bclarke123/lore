"""Allocation counts by request size of one lore command, for two builds.

Runs the command several times with each build under `allocount.c`, loaded with
`LD_PRELOAD` and `LORE_ALLOCATOR=system` so that lore's allocations reach glibc, and prints
each request size whose counts differ between the builds in every run, then the totals of each
run.
Linux only.

    python3 scripts/allocations/compare.py <base-lore> <new-lore> [--runs 5] \
        [--cwd <repository>] [--setup '<shell command>'] -- <lore arguments>

`--setup` runs before each run, for a command that changes the repository it runs in: for
example `rsync -a --delete /tmp/workload/ /tmp/run/` with `--cwd /tmp/run`.
"""

import argparse
import os
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent


def histogram(path):
    """Counts by request size, with requests of 1 MiB and more under the key `large`."""
    counts = {}
    for line in path.read_text().splitlines():
        fields = line.split()
        if fields[0] == "large":
            counts["large"] = (int(fields[1]), int(fields[2]))
        else:
            counts[int(fields[0])] = int(fields[1])
    return counts


def totals(counts):
    """The number and the bytes of the requests in `counts`."""
    number = sum(count for size, count in counts.items() if size != "large")
    size_bytes = sum(size * count for size, count in counts.items() if size != "large")
    if "large" in counts:
        number += counts["large"][0]
        size_bytes += counts["large"][1]
    return number, size_bytes


def run(binary, arguments, library, args, scratch, label):
    """One run of `binary` under the counter, returning its counts by size."""
    if args.setup:
        subprocess.run(args.setup, shell=True, check=True)
    output = scratch / f"{label}.hist"
    environment = dict(
        os.environ,
        LD_PRELOAD=str(library),
        LORE_ALLOCATOR="system",
        LORE_USE_SERVICE="0",
        LORE_ALLOC_HISTOGRAM_FILE=str(output),
        LORE_ALLOC_COUNT_FILE=str(scratch / "totals.txt"),
    )
    with open(scratch / f"{label}.log", "w") as log:
        result = subprocess.run(
            [binary, *arguments],
            cwd=args.cwd,
            env=environment,
            stdout=log,
            stderr=log,
            check=False,
        )
    if result.returncode != 0:
        sys.exit(f"{binary} exited with {result.returncode}; see {scratch / label}.log")
    return histogram(output)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("base")
    parser.add_argument("new")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--cwd", default=".")
    parser.add_argument("--setup")
    parser.add_argument("--rows", type=int, default=30)
    if "--" not in sys.argv:
        parser.error("the lore arguments follow --")
    split = sys.argv.index("--")
    args = parser.parse_args(sys.argv[1:split])
    arguments = sys.argv[split + 1 :]

    scratch = pathlib.Path(tempfile.mkdtemp(prefix="lore-allocations-"))
    library = scratch / "allocount.so"
    subprocess.run(
        [
            "cc",
            "-shared",
            "-fPIC",
            "-O2",
            "-o",
            str(library),
            str(HERE / "allocount.c"),
        ],
        check=True,
    )

    binaries = {"base": args.base, "new": args.new}
    for build, binary in binaries.items():
        if os.sep in binary:
            binaries[build] = os.path.abspath(binary)
    runs = {"base": [], "new": []}
    for index in range(args.runs):
        for build, binary in binaries.items():
            runs[build].append(
                run(binary, arguments, library, args, scratch, f"{build}-{index}")
            )

    sizes = {
        size
        for counts in runs["base"] + runs["new"]
        for size in counts
        if size != "large"
    }
    rows = []
    for size in sizes:
        base = [counts.get(size, 0) for counts in runs["base"]]
        new = [counts.get(size, 0) for counts in runs["new"]]
        if max(base) < min(new) or max(new) < min(base):
            change = size * (sum(new) - sum(base)) / args.runs
            rows.append((abs(change), size, change, base, new))
    for _, size, change, base, new in sorted(rows, reverse=True)[: args.rows]:
        print(f"{size:>10} bytes {change:>+14,.0f}  base {base} new {new}")
    for build in ("base", "new"):
        print(build, [totals(counts) for counts in runs[build]])


if __name__ == "__main__":
    main()
