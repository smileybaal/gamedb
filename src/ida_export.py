def run(db):
    import datetime
    import hashlib
    import json
    import os
    from pathlib import Path
    import tempfile
    import ida_auto
    import ida_hexrays
    import ida_kernwin
    import ida_name
    import ida_segment
    import idautils

    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays decompiler is unavailable")
    destination = Path(EXPORT_DIRECTORY)
    failures = []
    imports = []
    functions = []
    digest = hashlib.sha256()
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination, suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            for ea in idautils.Functions():
                name = ida_name.get_name(ea)
                segment = ida_segment.getseg(ea)
                if segment is not None and segment.type == ida_segment.SEG_XTRN:
                    imports.append({"address": hex(ea), "name": name})
                    continue
                try:
                    function = ida_hexrays.decompile(ea)
                    if function is None:
                        raise RuntimeError("No pseudocode returned")
                    text = str(function).rstrip() + "\n\n"
                except Exception as exc:
                    failures.append({"address": hex(ea), "name": name, "error": str(exc)})
                    continue
                stream.write(text)
                digest.update(text.encode("utf-8"))
                functions.append({"address": hex(ea), "name": name})
            stream.flush()
            os.fsync(stream.fileno())
        if not functions:
            raise RuntimeError("No functions decompiled; existing export was preserved")
        temporary.replace(destination / "decompiled.c")
        temporary = None
        manifest = {
            "database": DATABASE_PATH,
            "backend": "ida",
            "kernel": ida_kernwin.get_kernel_version(),
            "exported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "sha256": digest.hexdigest(),
            "exported": len(functions),
            "failed": len(failures),
            "skipped_imports": imports,
            "functions": functions,
            "failures": failures,
        }
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination, suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(manifest, stream, indent=2)
            stream.write("\n")
        temporary.replace(destination / ".gamedb-export.json")
        temporary = None
        return {"backend": "ida", "exported": len(functions), "failed": len(failures), "skipped_imports": len(imports), "source": str(destination / "decompiled.c"), "manifest": str(destination / ".gamedb-export.json")}
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
