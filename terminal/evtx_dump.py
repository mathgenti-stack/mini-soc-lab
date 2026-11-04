"""Print the records of an .evtx file as XML, for the lab's Get-WinEvent (PowerShell module SocLab).

The reader is the dashboard's own, soc_lab/evtx.py, mounted read-only at /opt/soc-lab/lib/evtx.py when
the terminal starts. The terminal and the dashboard therefore read .evtx files in exactly the same way.

Usage: python3 -I /opt/soc-lab/evtx_dump.py FILE.evtx
"""

import sys

sys.path.insert(0, "/opt/soc-lab/lib")

try:
    from evtx import EvtxError, read_evtx
except ImportError:
    sys.exit("The .evtx reader is missing. Start the terminal from the dashboard or with "
             "'python -m soc_lab.cli terminal start'.")


def main(arguments: list[str]) -> int:
    if len(arguments) != 1:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    path = arguments[0]
    try:
        with open(path, "rb") as handle:
            content = read_evtx(handle.read())
    except (OSError, EvtxError) as exc:
        print(f"cannot read {path}: {exc}", file=sys.stderr)
        return 1
    out = sys.stdout
    out.write("<Events>\n")
    for record in content.records:
        out.write(record + "\n")
    out.write("</Events>\n")
    if content.bad_records or content.bad_chunks:
        print(f"warning: skipped {content.bad_records} damaged record(s) and {content.bad_chunks} damaged chunk(s)",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
