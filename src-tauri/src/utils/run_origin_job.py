"""
OriginBridge Python worker.

This is an alternative to the embedded PowerShell worker. It is designed for the
new "csv + plot.json" package shape and uses OriginLab's `originpro` package
when available.

The Rust app copies this file into `WorkDir` and executes it as a background
process, writing logs to `originbridge.log` and errors to `error.txt`.
"""

from __future__ import annotations

import argparse
import csv as _csv
import json
import os
import subprocess
import sys
import tempfile
import time
import traceback
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


def _env_truthy(v: Optional[str]) -> bool:
    if v is None:
        return False
    s = v.strip().lower()
    return s in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    s = raw.strip()
    if not s:
        return default
    try:
        return int(s)
    except Exception:
        return default


def _try_lock_file_nonblocking(f) -> bool:
    # We use a single-byte region lock so multiple Python workers can coordinate.
    # PowerShell workers use FileShare.None which blocks opening; this also works since
    # our open() call will fail while PS holds the lock file open.
    if os.name == "nt":
        import msvcrt  # type: ignore

        try:
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False

    try:
        import fcntl  # type: ignore

        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            return False
    except Exception:
        return False


def _unlock_file(f) -> None:
    try:
        if os.name == "nt":
            import msvcrt  # type: ignore

            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl  # type: ignore

            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception:
        pass


def _try_acquire_lock_path(path: Path) -> Optional[object]:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    try:
        f = path.open("a+b")
    except OSError:
        return None

    try:
        # Ensure the file is at least 1 byte long for region locking on Windows.
        try:
            f.seek(0, os.SEEK_END)
            if f.tell() < 1:
                f.write(b"\0")
                f.flush()
        except Exception:
            pass

        if _try_lock_file_nonblocking(f):
            return f
    except Exception:
        pass

    try:
        f.close()
    except Exception:
        pass
    return None


@contextmanager
def _origin_automation_gate(*, logger: "_Logger", ui_automation: bool, multi_instance_ui: bool):
    if not (ui_automation or multi_instance_ui):
        yield
        return

    timeout_ms = _env_int("ORIGINBRIDGE_ORIGIN_LOCK_TIMEOUT_MS", 600000)
    if timeout_ms < 1:
        timeout_ms = 1

    lock_dir = Path(tempfile.gettempdir()) / "OriginBridge"

    parallel_multi = multi_instance_ui and _env_truthy(os.environ.get("ORIGINBRIDGE_PARALLEL_MULTI_INSTANCE"))
    if parallel_multi:
        max_parallel = _env_int("ORIGINBRIDGE_PARALLEL_MULTI_INSTANCE_LIMIT", 3)
        if max_parallel < 1:
            max_parallel = 1
        if max_parallel > 10:
            max_parallel = 10

        logger.log(f"Waiting for multi-instance slot lock (maxParallel={max_parallel})")
        start = time.monotonic()
        while True:
            for i in range(max_parallel):
                slot_path = lock_dir / f"origin_multi_instance.slot.{i}.lock"
                handle = _try_acquire_lock_path(slot_path)
                if handle is not None:
                    logger.log(f"Multi-instance slot lock acquired: {i + 1}/{max_parallel} ({slot_path})")
                    try:
                        yield
                    finally:
                        _unlock_file(handle)
                        try:
                            handle.close()  # type: ignore[attr-defined]
                        except Exception:
                            pass
                    return

            if (time.monotonic() - start) * 1000.0 > float(timeout_ms):
                raise TimeoutError(
                    f"Timeout waiting for multi-instance slot lock (maxParallel={max_parallel}, timeout={timeout_ms} ms)."
                )
            time.sleep(0.25)

    lock_path = lock_dir / "origin_automation.lock"
    logger.log(f"Waiting for Origin automation lock: {lock_path}")
    start = time.monotonic()
    while True:
        handle = _try_acquire_lock_path(lock_path)
        if handle is not None:
            logger.log("Origin automation lock acquired.")
            try:
                yield
            finally:
                _unlock_file(handle)
                try:
                    handle.close()  # type: ignore[attr-defined]
                except Exception:
                    pass
            return

        if (time.monotonic() - start) * 1000.0 > float(timeout_ms):
            raise TimeoutError(f"Timeout waiting for Origin automation lock (timeout={timeout_ms} ms).")
        time.sleep(0.25)


@dataclass(frozen=True)
class _Paths:
    work_dir: Path
    extract_dir: Path
    origin_exe: Optional[Path]

    @property
    def log_path(self) -> Path:
        return self.work_dir / "originbridge.log"

    @property
    def error_path(self) -> Path:
        return self.work_dir / "error.txt"


class _Logger:
    def __init__(self, log_path: Path) -> None:
        self._log_path = log_path
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, message: str) -> None:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        line = f"[{ts}] {message}"
        try:
            # Best-effort: stdout may be detached when spawned by Tauri.
            print(line)
        except Exception:
            pass
        try:
            with self._log_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass


def _write_error(error_path: Path, message: str, work_dir: Path, log_path: Path) -> None:
    try:
        error_path.parent.mkdir(parents=True, exist_ok=True)
        body = (
            "OriginBridge failed.\n\n"
            + message
            + "\n\n"
            + f"WorkDir: {work_dir}\n"
            + f"Log: {log_path}\n"
        )
        error_path.write_text(body, encoding="utf-8")
    except Exception:
        pass


def _read_csv_header(csv_path: Path) -> List[str]:
    # utf-8-sig handles a BOM if present.
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = _csv.reader(f)
        try:
            row = next(reader)
        except StopIteration:
            return []
        return [c.strip() for c in row]


def _col_index_from_ref(ref: Union[int, str], header: List[str]) -> int:
    if isinstance(ref, int):
        if ref < 0:
            raise ValueError(f"Column index must be >= 0, got {ref}")
        return ref
    name = str(ref).strip()
    if not name:
        raise ValueError("Column name is empty")
    try:
        return header.index(name)
    except ValueError:
        raise ValueError(f"Column name not found in CSV header: {name}")


def _index_to_col_letter(idx0: int) -> str:
    # 0 -> A, 25 -> Z, 26 -> AA ...
    if idx0 < 0:
        raise ValueError(f"Column index must be >= 0, got {idx0}")
    n = idx0 + 1
    s = ""
    while n > 0:
        n, r = divmod(n - 1, 26)
        s = chr(ord("A") + r) + s
    return s


def _resolve_path(p: str, base_dir: Path) -> Path:
    pp = Path(p)
    if pp.is_absolute():
        return pp
    return base_dir / pp


def _choose_csv_fallback(extract_dir: Path) -> Optional[Path]:
    # Mirrors the PowerShell worker heuristic:
    # - ignore metrics*.csv when possible
    # - pick the most recently modified
    best_any: Optional[Path] = None
    best_non_metrics: Optional[Path] = None
    for path in extract_dir.rglob("*.csv"):
        if path.name.lower() == "originbridge_job.csv":
            continue
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        if best_any is None or mtime > best_any.stat().st_mtime:
            best_any = path
        if "metrics" not in path.name.lower():
            if best_non_metrics is None or mtime > best_non_metrics.stat().st_mtime:
                best_non_metrics = path
    return best_non_metrics or best_any


def _load_plot_spec(plot_json_path: Path) -> Dict[str, Any]:
    # utf-8-sig handles a BOM if present.
    raw = plot_json_path.read_text(encoding="utf-8-sig")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("plot.json must be an object")
    if data.get("version") != 1:
        raise ValueError("plot.json.version must be 1")
    graphs = data.get("graphs")
    if not isinstance(graphs, list) or not graphs:
        raise ValueError("plot.json.graphs must be a non-empty array")
    return data


def _build_graph_plan(
    *,
    header: List[str],
    spec: Optional[Dict[str, Any]],
    plot_mode: str,
) -> Tuple[List[Dict[str, Any]], Optional[str], Optional[str], Union[int, str]]:
    graphs: List[Dict[str, Any]]
    template_top: Optional[str] = None
    out_project_name: Optional[str] = None
    default_type: Union[int, str] = 202

    if spec:
        graphs = spec["graphs"]
        template_top = spec.get("template")
        out_project_name = (spec.get("output") or {}).get("projectName")
        return graphs, template_top, out_project_name, default_type

    if len(header) < 2:
        raise RuntimeError("CSV must have at least 2 columns for fallback plotting")

    # Pair columns: (0,1) (2,3) ...
    pairs = []
    for i in range(0, len(header), 2):
        if i + 1 >= len(header):
            break
        pairs.append({"x": i, "y": i + 1, "type": default_type})

    if plot_mode == "multi":
        graphs = [{"name": f"Pair{idx}", "layer": 0, "series": [pair]} for idx, pair in enumerate(pairs, start=1)]
    else:
        graphs = [{"name": "AllPairs", "layer": 0, "series": pairs}]
    return graphs, template_top, out_project_name, default_type


def _dry_run_validate(
    *,
    paths: _Paths,
    logger: _Logger,
    csv_path: Path,
    spec: Optional[Dict[str, Any]],
) -> None:
    plot_mode = (os.environ.get("ORIGINBRIDGE_PLOT_MODE") or "single").strip().lower()
    plot_mode = "multi" if plot_mode == "multi" else "single"
    logger.log(f"DRY RUN: plot mode={plot_mode}")

    header = _read_csv_header(csv_path)
    if not header:
        raise RuntimeError(f"CSV header is empty: {csv_path}")
    dupes = {h for h in header if h and header.count(h) > 1}
    if dupes:
        logger.log(f"Warning: duplicate CSV headers detected: {sorted(dupes)!r}")

    graphs, template_top, _, default_type = _build_graph_plan(header=header, spec=spec, plot_mode=plot_mode)

    logger.log(f"DRY RUN: selected CSV: {csv_path}")
    logger.log(f"DRY RUN: graphs={len(graphs)}")

    for gi, g in enumerate(graphs, start=1):
        g_template = g.get("template") or template_top
        layer_idx = int(g.get("layer", 0) or 0)
        series_list = g.get("series") or []
        if not isinstance(series_list, list) or not series_list:
            raise ValueError("graph.series must be a non-empty array")

        if g_template:
            tpl_path = _resolve_path(str(g_template), paths.extract_dir)
            if not tpl_path.exists():
                raise FileNotFoundError(f"Template not found: {tpl_path}")
            logger.log(f"DRY RUN: graph[{gi}] template={tpl_path} layer={layer_idx}")
        else:
            logger.log(f"DRY RUN: graph[{gi}] template=<built-in scatter> layer={layer_idx}")

        for si, s in enumerate(series_list, start=1):
            if not isinstance(s, dict):
                raise ValueError("series item must be an object")
            x_ref = s.get("x")
            y_ref = s.get("y")
            if x_ref is None or y_ref is None:
                raise ValueError("series.x and series.y are required")
            x_idx = _col_index_from_ref(x_ref, header)
            y_idx = _col_index_from_ref(y_ref, header)
            colx = _index_to_col_letter(x_idx)
            coly = _index_to_col_letter(y_idx)
            label = s.get("label")
            ptype = s.get("type", default_type)
            logger.log(
                f"DRY RUN:  series[{si}] X={colx}({x_ref}) Y={coly}({y_ref}) type={ptype} label={label!r}"
            )


def _plot_with_originpro(
    *,
    paths: _Paths,
    logger: _Logger,
    csv_path: Path,
    spec: Optional[Dict[str, Any]],
) -> None:
    import originpro as op

    ui_automation = _env_truthy(os.environ.get("ORIGINBRIDGE_UI_AUTOMATION"))
    multi_instance_ui = _env_truthy(os.environ.get("ORIGINBRIDGE_MULTI_INSTANCE_UI"))
    plot_mode = (os.environ.get("ORIGINBRIDGE_PLOT_MODE") or "single").strip().lower()
    plot_mode = "multi" if plot_mode == "multi" else "single"
    logger.log(f"Plot mode: {plot_mode}")
    logger.log(f"UI automation: {ui_automation}")
    logger.log(f"Multi-instance UI: {multi_instance_ui}")

    # Serialize Origin automation across jobs: selecting multiple ZIPs starts multiple workers.
    # Without a lock, concurrent COM commands can race and produce empty/partial workbooks.
    with _origin_automation_gate(logger=logger, ui_automation=ui_automation, multi_instance_ui=multi_instance_ui):
        # Attach to an existing Origin instance in single-window mode.
        # NOTE: Must attach BEFORE calling any LabTalk helpers (e.g. set_show), otherwise originpro may
        # spin up a separate OriginExt.Application instance first, making attach/exit much slower.
        if ui_automation:
            attach_timeout_ms = _env_int("ORIGINBRIDGE_ATTACH_TIMEOUT_MS", 60000)
            if attach_timeout_ms < 1:
                attach_timeout_ms = 1

            logger.log(f"Attaching to existing Origin instance (op.attach(), timeout={attach_timeout_ms} ms)")
            start = time.monotonic()
            attached = False
            last_err: Optional[Exception] = None
            attempt = 0
            while (time.monotonic() - start) * 1000.0 <= float(attach_timeout_ms):
                attempt += 1
                try:
                    op.attach()
                    attached = True
                    break
                except Exception as e:
                    last_err = e
                    time.sleep(0.6)
            if not attached:
                logger.log(f"Warning: op.attach() failed; falling back to op.new(). Last error: {last_err}")
                op.new()

        # New project for clean state unless we're explicitly trying to keep UI workspace.
        if not ui_automation:
            logger.log("Starting new Origin project (op.new())")
            op.new()

        # During automation we prefer headless; show window only when requested.
        show = _env_truthy(os.environ.get("ORIGINBRIDGE_PY_SHOW")) or ui_automation or multi_instance_ui
        try:
            op.set_show(show)
        except Exception as e:
            logger.log(f"Warning: originpro set_show({show}) failed: {e}")
        logger.log(f"Origin visibility (originpro): {show}")

        header = _read_csv_header(csv_path)
        if not header:
            raise RuntimeError(f"CSV header is empty: {csv_path}")

        logger.log(f"Importing CSV via originpro: {csv_path}")
        wks = op.new_sheet("w")
        # Remove Data Connector after import (matches docs pattern for batch processing).
        wks.from_file(str(csv_path), False)
        try:
            wks.activate()
        except Exception as e:
            logger.log(f"Warning: failed to activate worksheet: {e}")

        graphs, template_top, out_project_name, default_type = _build_graph_plan(
            header=header, spec=spec, plot_mode=plot_mode
        )

        created_graphs = 0
        last_graph = None
        for g in graphs:
            g_template = g.get("template") or template_top
            layer_idx = int(g.get("layer", 0) or 0)
            series_list = g.get("series") or []
            if not isinstance(series_list, list) or not series_list:
                raise ValueError("graph.series must be a non-empty array")

            if g_template:
                tpl_path = _resolve_path(str(g_template), paths.extract_dir)
                logger.log(f"Creating graph from template: {tpl_path}")
                gr = op.new_graph(template=str(tpl_path))
            else:
                # Fall back to a generic graph if no template is provided.
                logger.log("Creating graph from built-in template: scatter")
                gr = op.new_graph(template="scatter")

            last_graph = gr

            try:
                gl = gr[layer_idx]
            except Exception as e:
                raise RuntimeError(f"Template does not have layer index {layer_idx}: {e}")

            for s in series_list:
                if not isinstance(s, dict):
                    raise ValueError("series item must be an object")
                x_ref = s.get("x")
                y_ref = s.get("y")
                if x_ref is None or y_ref is None:
                    raise ValueError("series.x and series.y are required")
                x_idx = _col_index_from_ref(x_ref, header)
                y_idx = _col_index_from_ref(y_ref, header)
                colx = _index_to_col_letter(x_idx)
                coly = _index_to_col_letter(y_idx)

                label = s.get("label")
                if isinstance(label, str) and label.strip():
                    try:
                        wks.set_label(coly, val=label.strip(), type="L")
                    except Exception:
                        # Labeling is best-effort; plotting should still work.
                        logger.log(f"Warning: failed to set label for {coly}: {label!r}")

                ptype = s.get("type", default_type)
                try:
                    ptype_int = int(ptype)  # type: ignore[arg-type]
                    ptype = ptype_int
                except Exception:
                    # Keep string as-is for future aliases; originpro may reject it.
                    pass

                logger.log(f"Add plot: X={colx} Y={coly} type={ptype}")
                gl.add_plot(wks, coly=coly, colx=colx, type=ptype)  # type: ignore[arg-type]

            gl.rescale()
            created_graphs += 1

        logger.log(f"Created graphs: {created_graphs}")
        if last_graph is not None:
            try:
                last_graph.activate()
            except Exception as e:
                logger.log(f"Warning: failed to activate graph: {e}")

        # If we're in UI modes, keep the project open and return.
        if ui_automation or multi_instance_ui:
            logger.log("UI mode enabled; skipping Save()/Exit()/relaunch.")
            return

        # Save project next to ExtractDir (same behavior as PowerShell worker).
        project_name = out_project_name or "originbridge.opju"
        proj_path = paths.work_dir.parent / project_name
        if proj_path.exists():
            try:
                proj_path.unlink()
            except OSError:
                pass

        logger.log(f"Saving Origin project via originpro: {proj_path}")
        op.save(str(proj_path))

        # Exit Origin automation instance.
        if op.oext:
            logger.log("Exiting Origin (originpro op.exit())")
            op.exit()

        # Relaunch UI to open the saved project, if OriginExe is provided.
        if paths.origin_exe and paths.origin_exe.exists():
            try:
                logger.log(f"Launching Origin UI: {paths.origin_exe} {proj_path}")
                subprocess.Popen([str(paths.origin_exe), str(proj_path)], cwd=str(paths.work_dir.parent))
            except Exception as e:
                logger.log(f"Warning: failed to relaunch Origin UI: {e}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--extract-dir", required=True)
    parser.add_argument("--origin-exe", default="")
    parser.add_argument("--dry-run", action="store_true", help="Validate plot.json + CSV mapping without Origin.")
    args = parser.parse_args(argv)

    paths = _Paths(
        work_dir=Path(args.work_dir).resolve(),
        extract_dir=Path(args.extract_dir).resolve(),
        origin_exe=Path(args.origin_exe).resolve() if args.origin_exe else None,
    )
    paths.work_dir.mkdir(parents=True, exist_ok=True)
    logger = _Logger(paths.log_path)

    # Initialize log/error files similar to PowerShell worker.
    try:
        paths.log_path.write_text(f"OriginBridge log started: {datetime.now()}\n", encoding="utf-8")
    except Exception:
        pass
    try:
        paths.error_path.write_text("", encoding="utf-8")
    except Exception:
        pass

    logger.log(f"WorkDir: {paths.work_dir}")
    logger.log(f"ExtractDir: {paths.extract_dir}")
    if paths.origin_exe:
        logger.log(f"OriginExe: {paths.origin_exe}")

    try:
        plot_json = paths.extract_dir / "plot.json"
        spec: Optional[Dict[str, Any]] = None
        if plot_json.exists():
            logger.log(f"Loading plot spec: {plot_json}")
            spec = _load_plot_spec(plot_json)
        else:
            logger.log("No plot.json found; using fallback pairing strategy.")

        csv_path: Optional[Path] = None
        if spec and isinstance(spec.get("csv"), str) and spec["csv"].strip():
            csv_path = _resolve_path(spec["csv"], paths.extract_dir)
        if csv_path is None:
            csv_path = _choose_csv_fallback(paths.extract_dir)
        if csv_path is None or not csv_path.exists():
            raise RuntimeError("No usable .csv found in package")
        logger.log(f"Selected CSV: {csv_path}")

        if bool(getattr(args, "dry_run", False)):
            _dry_run_validate(paths=paths, logger=logger, csv_path=csv_path, spec=spec)
            logger.log("Python worker dry-run completed successfully.")
            return 0

        _plot_with_originpro(paths=paths, logger=logger, csv_path=csv_path, spec=spec)

        logger.log("Python worker completed successfully.")
        return 0
    except Exception as e:
        tb = traceback.format_exc()
        msg = f"{e}\n\n{tb}"
        logger.log(f"ERROR: {e}")
        _write_error(paths.error_path, msg, paths.work_dir, paths.log_path)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
