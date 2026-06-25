"""Turn an open LSS wheel into a PyArmor-obfuscated, platform-specific wheel.

Takes the normally-built wheel + a `pyarmor gen` output dir, swaps every
lss/*.py for its obfuscated form, bundles the pyarmor_runtime_* package (which
contains a native .so → the wheel becomes platform-specific), retags WHEEL, and
regenerates RECORD.

    python tools/obfuscate_wheel.py <open.whl> <obf_dir> <out_dir> <platform_tag>
"""
import base64
import hashlib
import io
import sys
import zipfile
from pathlib import Path


def _digest(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def main() -> None:
    open_whl, obf_dir, out_dir, plat = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4]
    runtime_dirs = [d for d in obf_dir.iterdir() if d.is_dir() and d.name.startswith("pyarmor_runtime")]
    if not runtime_dirs:
        sys.exit("no pyarmor_runtime_* package found in the obfuscation output")

    zin = zipfile.ZipFile(open_whl)
    records, distinfo = [], None
    buf = io.BytesIO()
    zout = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)

    def add(arc: str, data: bytes) -> None:
        zout.writestr(arc, data)
        records.append((arc, _digest(data), str(len(data))))

    for n in zin.namelist():
        if n.endswith(".dist-info/RECORD"):
            distinfo = n.split("/")[0]
            continue  # regenerated last
        data = zin.read(n)
        if n.startswith("lss/") and n.endswith(".py"):
            obf = obf_dir / n
            if obf.exists():
                data = obf.read_bytes()            # swap in the obfuscated source
        if n.endswith(".dist-info/WHEEL"):
            data = data.replace(b"Tag: py3-none-any", f"Tag: py3-none-{plat}".encode())
        add(n, data)

    # bundle the pyarmor runtime package(s) — native .so lives here
    for rt in runtime_dirs:
        for f in sorted(rt.rglob("*")):
            if f.is_file() and "__pycache__" not in f.parts:
                add(f"{rt.name}/{f.relative_to(rt).as_posix()}", f.read_bytes())

    rec = f"{distinfo}/RECORD"
    zout.writestr(rec, "\n".join(f"{a},{d},{s}" for a, d, s in records) + f"\n{rec},,\n")
    zout.close()

    name = open_whl.name.replace("-py3-none-any.whl", f"-py3-none-{plat}.whl")
    out = out_dir / name
    out_dir.mkdir(parents=True, exist_ok=True)
    out.write_bytes(buf.getvalue())
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
