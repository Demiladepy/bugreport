"""
Run Halmos against cloned repos at specific commits.

Usage:
  python -m src.verify one <finding_id> --commit vulnerable
  python -m src.verify one <finding_id> --commit fix
  python -m src.verify one <finding_id> --commit vulnerable --dry-run
  python -m src.verify all --commit vulnerable
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel
from rich.console import Console

from .corpus import (
    ROOT,
    load_all_seed_findings,
    load_seed_finding,
    test_contract_name,
    test_file_path,
)

console = Console()

CommitKind = Literal["vulnerable", "fix"]
Outcome = Literal["PASS", "FAIL", "TIMEOUT", "BUILD_FAILED", "ERROR"]

VERIFY_DIR = ROOT / "results" / "verify"
HALMOS_TIMEOUT_S = 60
SOLC_VERSIONS = ("0.7.6", "0.8.13", "0.8.19", "0.8.20")
SYNTHETIC_DIR = ROOT / "data" / "synthetic"


def _ensure_foundry_svm_versions() -> None:
    """Mirror flat solc downloads into Foundry's ~/.svm/<version>/ layout."""
    svm_dir = Path.home() / ".svm"
    for version in SOLC_VERSIONS:
        flat = svm_dir / f"solc-{version}.exe"
        if not flat.exists():
            continue
        version_dir = svm_dir / version
        version_dir.mkdir(parents=True, exist_ok=True)
        dest = version_dir / f"solc-{version}"
        if not dest.exists():
            shutil.copy2(flat, dest)


def ensure_solc(repo: Path | None = None) -> None:
    """Bootstrap solc when foundry's svm CDN is unreachable (common on Windows)."""
    svm_dir = Path.home() / ".svm"
    svm_dir.mkdir(parents=True, exist_ok=True)
    for version in SOLC_VERSIONS:
        dest = svm_dir / f"solc-{version}.exe"
        if dest.exists():
            continue
        url = f"https://github.com/ethereum/solidity/releases/download/v{version}/solc-windows.exe"
        try:
            import urllib.request

            console.print(f"  [dim]downloading solc {version}...[/dim]")
            urllib.request.urlretrieve(url, dest)
        except Exception as exc:
            console.print(f"  [yellow]solc {version} download failed: {exc}[/yellow]")

    _ensure_foundry_svm_versions()

    if repo is not None:
        toml = repo / "foundry.toml"
        if toml.exists() and "auto_detect_solc" in toml.read_text(encoding="utf-8"):
            os.environ.pop("FOUNDRY_SOLC", None)
            return

    version = _repo_solc_version(repo) if repo else SOLC_VERSIONS[-1]
    solc_bin = svm_dir / f"solc-{version}.exe"
    if solc_bin.exists():
        os.environ["FOUNDRY_SOLC"] = str(solc_bin)
    else:
        latest = svm_dir / f"solc-{SOLC_VERSIONS[-1]}.exe"
        if latest.exists():
            os.environ.setdefault("FOUNDRY_SOLC", str(latest))


def _repo_solc_version(repo: Path | None) -> str:
    if repo is None:
        return SOLC_VERSIONS[-1]
    toml = repo / "foundry.toml"
    if not toml.exists():
        return SOLC_VERSIONS[-1]
    match = re.search(r"""solc\s*=\s*['"]([^'"]+)['"]""", toml.read_text(encoding="utf-8"))
    if not match:
        return SOLC_VERSIONS[-1]
    raw = match.group(1).strip()
    if raw.startswith("="):
        raw = raw[1:]
    return raw


class VerifyResult(BaseModel):
    finding_id: str
    commit_kind: CommitKind
    commit_sha: str
    halmos_outcome: Outcome
    counterexamples: list[dict] | None = None
    halmos_stdout: str = ""
    duration_seconds: float = 0.0
    ran_at: str


def ensure_halmos() -> None:
    _ensure_tool("halmos", "pip install halmos")
    _ensure_tool("forge", "Install Foundry: https://book.getfoundry.sh", extra_paths=[
        Path.home() / ".foundry" / "bin" / "forge.exe",
        Path.home() / ".foundry" / "bin" / "forge",
    ])


def _ensure_tool(name: str, install_hint: str, extra_paths: list[Path] | None = None) -> None:
    if shutil.which(name):
        return
    for p in extra_paths or []:
        if p.exists():
            os.environ["PATH"] = str(p.parent) + os.pathsep + os.environ.get("PATH", "")
            if shutil.which(name):
                return
    console.print(f"[red]{name} not found on PATH. {install_hint}[/red]")
    sys.exit(1)


def repo_workdir(finding_id: str, commit_kind: CommitKind) -> Path:
    return ROOT / "data" / "repos" / finding_id / commit_kind


def resolve_commit(finding, commit_kind: CommitKind) -> str:
    if commit_kind == "vulnerable":
        if not finding.vulnerable_commit:
            raise ValueError("vulnerable_commit is null")
        return finding.vulnerable_commit
    if not finding.fix_commit:
        raise ValueError("fix_commit is null — skip fix verification")
    return finding.fix_commit


def _wsl_path(path: Path) -> str:
    resolved = path.resolve()
    drive = resolved.drive.rstrip(":").lower()
    rest = resolved.as_posix().split(":", 1)[1]
    return f"/mnt/{drive}{rest}"


def _needs_wsl_clone(repo_url: str) -> bool:
    # Ronin repos track Foundry storage logs with ':' in paths — invalid on NTFS.
    return sys.platform == "win32" and "ronin-chain" in repo_url


def _checkout_commit(repo: Path, commit_sha: str) -> None:
    subprocess.run(["git", "fetch", "origin", commit_sha], cwd=repo, check=False, capture_output=True, text=True)
    proc = subprocess.run(["git", "checkout", commit_sha], cwd=repo, capture_output=True, text=True)
    if proc.returncode != 0:
        subprocess.run(["git", "fetch", "--unshallow"], cwd=repo, check=False, capture_output=True)
        subprocess.run(["git", "fetch", "origin", commit_sha], cwd=repo, check=False, capture_output=True, text=True)
        subprocess.run(["git", "checkout", commit_sha], cwd=repo, check=True, capture_output=True, text=True)


def clone_repo_wsl(repo_url: str, dest: Path, commit_sha: str) -> None:
    wsl_dest = _wsl_path(dest)
    wsl_tmp = f"/tmp/bugzy-clone-{dest.name}-{commit_sha[:8]}"
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    script = f"""
set -euo pipefail
rm -rf '{wsl_tmp}'
git clone '{repo_url}' '{wsl_tmp}'
cd '{wsl_tmp}'
git fetch origin '{commit_sha}' || true
git checkout '{commit_sha}'
git submodule update --init --recursive
tar -cf - --exclude=logs -C '{wsl_tmp}' . | tar -xf - -C '{wsl_dest}'
"""
    proc = subprocess.run(
        ["wsl", "-d", "Ubuntu", "--", "bash", "-lc", script],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0 and "Ubuntu" in (proc.stderr or ""):
        proc = subprocess.run(
            ["wsl", "--", "bash", "-lc", script],
            capture_output=True,
            text=True,
        )
    if proc.returncode != 0:
        raise RuntimeError(f"WSL clone failed:\n{proc.stderr}\n{proc.stdout}")
    if not (dest / ".git").exists():
        raise RuntimeError(f"WSL clone did not produce a git repo at {dest}")


def clone_repo(repo_url: str, dest: Path, commit_sha: str) -> None:
    if _needs_wsl_clone(repo_url):
        console.print("  [dim]clone via WSL (Windows-incompatible paths in repo)...[/dim]")
        clone_repo_wsl(repo_url, dest, commit_sha)
        return

    if dest.exists() and (dest / ".git").exists():
        subprocess.run(["git", "fetch", "--all"], cwd=dest, check=False, capture_output=True)
        _checkout_commit(dest, commit_sha)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        subprocess.run(
            ["git", "clone", repo_url, str(dest)],
            check=True,
            capture_output=True,
            text=True,
        )
        _checkout_commit(dest, commit_sha)
    subprocess.run(["git", "submodule", "update", "--init", "--recursive"], cwd=dest, check=False, capture_output=True)


def _patch_already_applied(text: str, patch_text: str) -> bool:
    added = [ln[1:] for ln in patch_text.splitlines() if ln.startswith("+") and not ln.startswith("+++")]
    added = [fragment.strip() for fragment in added if fragment.strip()]
    if not added:
        return False
    if "function increaseLiquidity" in patch_text or any("isAuthorizedForToken" in fragment for fragment in added):
        match = re.search(r"function increaseLiquidity[\s\S]*?\{", text)
        if match:
            return all(fragment in match.group(0) for fragment in added)
    if "_isAuthorized" in patch_text:
        match = re.search(r"function _isAuthorized[\s\S]*?\n\s*\}", text)
        if match:
            return all(fragment in match.group(0) for fragment in added)
    return False


def _manual_apply_patch(text: str, patch_text: str) -> str:
    removed = [ln[1:] for ln in patch_text.splitlines() if ln.startswith("-") and not ln.startswith("---")]
    added = [ln[1:] for ln in patch_text.splitlines() if ln.startswith("+") and not ln.startswith("+++")]
    if len(removed) == 1 and len(added) == 1 and removed[0] in text:
        return text.replace(removed[0], added[0], 1)
    if len(added) == 1 and len(removed) == 0:
        needle = "checkDeadline(params.deadline)"
        insert = added[0].strip()
        if needle in text:
            header = text.split("function increaseLiquidity", 1)[1].split("{", 1)[0]
            if insert not in header:
                return text.replace(f"    {needle}", f"    {insert}\n    {needle}", 1)
    raise RuntimeError("unsupported synthetic patch format for manual apply")


def _adapt_test_source(test_src: str, repo: Path) -> str:
    if "halmos-cheatcodes/SymTest.sol" in test_src:
        return test_src
    repo_solc = _repo_solc_version(repo)
    if repo_solc.startswith("0.7."):
        test_src = re.sub(
            r"pragma solidity \^0\.8\.\d+;",
            f"pragma solidity ^{repo_solc};",
            test_src,
            count=1,
        )
    return test_src


def apply_synthetic_patch(finding_id: str, repo: Path, *, affected_file: str | None = None) -> None:
    patch = SYNTHETIC_DIR / f"{finding_id}.patch"
    if not patch.exists():
        raise FileNotFoundError(f"Synthetic patch not found: {patch}")
    proc = subprocess.run(
        ["git", "apply", "--whitespace=nowarn", str(patch)],
        cwd=repo,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        rel = affected_file or "contracts/SetterTopNPoolsStrategy.sol"
        target = repo / rel
        if not target.exists():
            raise RuntimeError(f"git apply failed: {proc.stderr}\n{proc.stdout}")
        text = target.read_text(encoding="utf-8")
        patch_text = patch.read_text(encoding="utf-8")
        if _patch_already_applied(text, patch_text):
            console.print("  [dim]synthetic patch already applied[/dim]")
            return
        updated = _manual_apply_patch(text, patch_text)
        target.write_text(updated, encoding="utf-8")
        console.print("  [dim]applied synthetic fix patch (manual fallback)[/dim]")


def ensure_ronin_operation_deps(repo: Path) -> None:
    """katana-operation-contracts remaps @openzeppelin-contracts-4.7.0 but omits the vendored copy."""
    remappings = repo / "remappings.txt"
    if not remappings.exists() or "@openzeppelin-contracts-4.7.0" not in remappings.read_text(encoding="utf-8"):
        return
    dep = repo / "dependencies" / "@openzeppelin-contracts-4.7.0"
    if dep.exists():
        return
    oz = repo / "lib" / "openzeppelin-contracts"
    if not oz.exists():
        return
    dep.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(oz, dep, dirs_exist_ok=True)
    console.print("  [dim]patched dependencies/@openzeppelin-contracts-4.7.0 from lib[/dim]")


RONIN_NPM_FINDINGS = frozenset({
    "2024-10-ronin-missing-authorization-check-in-increasel",
    "2024-10-ronin-unauthorized-liquidity-manipulation-in-n",
})


def _prebuild_ronin_artifacts(repo: Path, finding_id: str) -> None:
    if finding_id not in RONIN_NPM_FINDINGS:
        return
    nfpm = repo / "src" / "periphery" / "NonfungiblePositionManager.sol"
    if not nfpm.exists():
        return
    console.print("  [dim]prebuild NFPM artifact for deployCode...[/dim]")
    run_cmd(["forge", "build", "src/periphery/NonfungiblePositionManager.sol"], cwd=repo, timeout=600)


def _append_halmos_remapping(repo: Path) -> None:
    remappings = repo / "remappings.txt"
    line = "halmos-cheatcodes/=lib/halmos-cheatcodes/src/"
    if remappings.exists():
        text = remappings.read_text(encoding="utf-8")
        if "halmos-cheatcodes" not in text:
            remappings.write_text(text.rstrip() + "\n" + line + "\n", encoding="utf-8")
    else:
        remappings.write_text(line + "\n", encoding="utf-8")


def ensure_foundry_layout(repo: Path) -> None:
    foundry = repo / "foundry.toml"
    if foundry.exists() and (repo / "src").is_dir():
        text = foundry.read_text(encoding="utf-8")
        if "auto_detect_solc" not in text:
            if "[profile.default]" in text:
                text = text.replace(
                    "[profile.default]",
                    "[profile.default]\nauto_detect_solc = true",
                    1,
                )
            else:
                text = "auto_detect_solc = true\n" + text
        if "auto_detect_solc = true" in text:
            text = re.sub(r"^\s*solc\s*=\s*['\"][^'\"]+['\"]\s*\n", "", text, flags=re.MULTILINE)
        foundry.write_text(text, encoding="utf-8")
        _append_halmos_remapping(repo)
        return

    is_hardhat = (repo / "hardhat.config.js").exists() or (repo / "hardhat.config.ts").exists()
    if foundry.exists() and not is_hardhat:
        _append_halmos_remapping(repo)
        return

    if (repo / "foundry.toml").exists() and (repo / "remappings.txt").exists():
        text = (repo / "remappings.txt").read_text(encoding="utf-8")
        if "@openzeppelin/contracts/=" in text and "hardhat/=" in text:
            return
    console.print("  [dim]init foundry layout for hardhat repo...[/dim]")
    (repo / "foundry.toml").write_text(
        "[profile.default]\n"
        "src = 'contracts'\n"
        "out = 'out'\n"
        "libs = ['lib']\n"
        "solc = '0.8.13'\n"
        "optimizer = true\n"
        "optimizer_runs = 200\n"
        "via_ir = true\n",
        encoding="utf-8",
    )
    pkg = repo / "package.json"
    if pkg.exists() and not (repo / "node_modules" / "@openzeppelin").exists():
        console.print("  [dim]npm install (hardhat deps)...[/dim]")
        run_cmd(["npm", "install", "--legacy-peer-deps"], cwd=repo, timeout=600)
    lines: list[str] = []
    remappings = repo / "remappings.txt"
    if remappings.exists():
        lines = remappings.read_text(encoding="utf-8").splitlines()
    if (repo / "node_modules" / "@openzeppelin").exists():
        oz_entries = (
            "forge-std/=lib/forge-std/src/",
            "@openzeppelin/contracts/=node_modules/@openzeppelin/contracts/",
            "@openzeppelin/contracts-upgradeable/=node_modules/@openzeppelin/contracts-upgradeable/",
            "@cryptoalgebra/integral-core/=node_modules/@cryptoalgebra/integral-core/",
            "@cryptoalgebra/integral-periphery/=node_modules/@cryptoalgebra/integral-periphery/",
            "@cryptoalgebra/integral-base-plugin/=node_modules/@cryptoalgebra/integral-base-plugin/",
            "@cryptoalgebra/integral-farming/=node_modules/@cryptoalgebra/integral-farming/",
            "hardhat/=node_modules/hardhat/",
            "halmos-cheatcodes/=lib/halmos-cheatcodes/src/",
        )
    else:
        oz_entries = (
            "forge-std/=lib/forge-std/src/",
            "@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/",
            "@openzeppelin/contracts-upgradeable/=lib/openzeppelin-contracts/contracts-upgradeable/",
            "halmos-cheatcodes/=lib/halmos-cheatcodes/src/",
        )
    for entry in oz_entries:
        prefix = entry.split("=")[0]
        if not any(line.startswith(prefix) for line in lines):
            lines.append(entry)
    lines = [line for line in lines if not line.startswith("@openzeppelin/=lib/openzeppelin-contracts/contracts/")]
    remappings.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if not (repo / "lib" / "forge-std").exists():
        run_cmd(["forge", "install", "foundry-rs/forge-std", "--no-commit"], cwd=repo, timeout=600)
    if not (repo / "node_modules" / "@openzeppelin").exists() and not (
        repo / "lib" / "openzeppelin-contracts"
    ).exists():
        run_cmd(
            ["forge", "install", "OpenZeppelin/openzeppelin-contracts@v4.9.3", "--no-commit"],
            cwd=repo,
            timeout=600,
        )


def detect_test_dir(repo: Path) -> Path:
    if (repo / "test").is_dir():
        return repo / "test"
    if (repo / "tests").is_dir():
        return repo / "tests"
    td = repo / "test"
    td.mkdir(exist_ok=True)
    return td


def run_cmd(cmd: list[str], cwd: Path, timeout: int = 600) -> subprocess.CompletedProcess:
    if cmd and cmd[0] == "npm" and sys.platform == "win32":
        cmd = ["npm.cmd", *cmd[1:]]
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def ensure_halmos_cheatcodes(repo: Path) -> None:
    lib = repo / "lib" / "halmos-cheatcodes"
    symtest = lib / "src" / "SymTest.sol"
    if not symtest.exists():
        if lib.exists():
            shutil.rmtree(lib, ignore_errors=True)
        proc = run_cmd(
            ["git", "clone", "--depth", "1", "https://github.com/a16z/halmos-cheatcodes.git", str(lib)],
            cwd=repo,
            timeout=600,
        )
        if proc.returncode != 0:
            run_cmd(["forge", "install", "a16z/halmos-cheatcodes", "--no-commit"], cwd=repo, timeout=600)
    remappings = repo / "remappings.txt"
    line = "halmos-cheatcodes/=lib/halmos-cheatcodes/src/\n"
    if remappings.exists():
        text = remappings.read_text(encoding="utf-8")
        if "halmos-cheatcodes" not in text:
            remappings.write_text(text.rstrip() + "\n" + line, encoding="utf-8")
    else:
        remappings.write_text(line, encoding="utf-8")


def forge_install(repo: Path) -> None:
    ensure_foundry_layout(repo)
    ensure_ronin_operation_deps(repo)
    if (repo / "foundry.toml").exists() or (repo / "lib" / "forge-std").exists():
        run_cmd(["forge", "install"], cwd=repo, timeout=600)
    run_cmd(["git", "submodule", "update", "--init", "--recursive"], cwd=repo, timeout=600)
    ensure_halmos_cheatcodes(repo)


def forge_build(repo: Path, *, force: bool = False) -> tuple[bool, str, str]:
    force_args = ["--force"] if force else []
    scoped_paths = ["test/bugzy"]
    for extra in ([], ["--via-ir"]):
        proc = run_cmd(["forge", "build", *scoped_paths, *extra, *force_args], cwd=repo, timeout=600)
        if proc.returncode == 0:
            return True, proc.stdout, proc.stderr
    proc = run_cmd(["forge", "build", *force_args], cwd=repo, timeout=600)
    if proc.returncode == 0:
        return True, proc.stdout, proc.stderr
    proc2 = run_cmd(["forge", "build", "--via-ir", *force_args], cwd=repo, timeout=600)
    return proc2.returncode == 0, proc2.stdout + proc.stdout, proc2.stderr + proc.stderr


def copy_test(repo: Path, finding_id: str) -> Path:
    src = test_file_path(finding_id)
    if not src.exists():
        raise FileNotFoundError(f"Generated test not found: {src}. Run codegen first.")
    test_root = detect_test_dir(repo)
    dest_dir = test_root / "bugzy"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{test_contract_name(finding_id)}.t.sol"
    test_src = _adapt_test_source(src.read_text(encoding="utf-8"), repo)
    dest.write_text(test_src, encoding="utf-8")
    return dest


def parse_contract_name(test_path: Path) -> str:
    text = test_path.read_text(encoding="utf-8")
    match = re.search(r"contract\s+(\w+)\s+is\s+", text)
    if match:
        return match.group(1)
    raise ValueError(f"Could not parse contract name from {test_path}")


def parse_check_functions(test_path: Path) -> list[str]:
    text = test_path.read_text(encoding="utf-8")
    return re.findall(r"function\s+(check_\w+)\s*\(", text)


def build_halmos_cmd(repo: Path, *, contract_name: str, function_name: str) -> list[str]:
    json_out = repo / "halmos_result.json"
    return [
        "halmos",
        "--function",
        function_name,
        "--match-contract",
        contract_name,
        "--solver-timeout-assertion",
        "30000",
        "--json-output",
        str(json_out),
    ]


def format_halmos_cmd(cmd: list[str]) -> str:
    return " ".join(cmd)


def parse_halmos_json(path: Path) -> tuple[Outcome, list[dict] | None]:
    if not path.exists():
        return "ERROR", None

    data = json.loads(path.read_text(encoding="utf-8"))
    counterexamples: list[dict] = []
    saw_tests = False
    any_fail = False
    any_error = False

    test_results = data.get("test_results")
    if isinstance(test_results, dict):
        for suite_key, tests in test_results.items():
            if not isinstance(tests, list):
                continue
            for item in tests:
                saw_tests = True
                num_models = int(item.get("num_models") or 0)
                exitcode = int(item.get("exitcode", 1))
                models = item.get("models") or []

                if num_models > 0:
                    any_fail = True
                    for model in models if isinstance(models, list) else [models]:
                        counterexamples.append({
                            "test": item.get("name"),
                            "suite": suite_key,
                            "model": model,
                        })
                elif exitcode != 0:
                    any_error = True
                    counterexamples.append({
                        "test": item.get("name"),
                        "suite": suite_key,
                        "exitcode": exitcode,
                    })

    if saw_tests:
        if any_fail:
            return "FAIL", counterexamples or None
        if any_error:
            return "ERROR", counterexamples or None
        return "PASS", None

    # Legacy / empty schema fallback
    top_exit = data.get("exitcode")
    if top_exit not in (None, 0):
        return "ERROR", None
    return "ERROR", None


def parse_halmos_stdout(text: str) -> Outcome:
    lower = text.lower()
    if "timeout" in lower or "timed out" in lower:
        return "TIMEOUT"
    if re.search(r"symbolic test result:\s*\d+\s+passed;\s*0\s+failed", lower):
        return "PASS"
    if re.search(r"symbolic test result:\s*0\s+passed;\s*\d+\s+failed", lower):
        return "FAIL"
    if re.search(r"\[fail\]", lower):
        return "FAIL"
    if re.search(r"\[pass\]", lower):
        return "PASS"
    if "no tests with" in lower or "unrecognized arguments" in lower:
        return "ERROR"
    if "solver_output.error" in lower or re.search(r"\[error\]", lower):
        return "ERROR"
    return "ERROR"


def run_halmos(
    repo: Path,
    rel_test_path: Path,
    *,
    contract_name: str,
    test_source: Path,
    dry_run: bool = False,
) -> tuple[Outcome, list[dict] | None, str, list[str]]:
    check_fns = parse_check_functions(test_source)
    if not check_fns:
        raise ValueError(f"No check_ functions found in {test_source}")

    combined = ""
    all_counterexamples: list[dict] = []
    cmd = build_halmos_cmd(repo, contract_name=contract_name, function_name=check_fns[0])

    console.print(f"[verify] repo:     {repo}")
    console.print(f"[verify] test:     {rel_test_path.as_posix()}")
    console.print(f"[verify] contract: {contract_name}")
    console.print(f"[verify] functions: {', '.join(check_fns)}")
    console.print(f"[verify] command:  {format_halmos_cmd(cmd)}")

    if dry_run:
        return "PASS", None, "dry-run", cmd

    json_out = repo / "halmos_result.json"
    worst: Outcome = "PASS"

    for fn in check_fns:
        fn_cmd = build_halmos_cmd(repo, contract_name=contract_name, function_name=fn)
        if json_out.exists():
            json_out.unlink()
        try:
            proc = subprocess.run(fn_cmd, cwd=repo, capture_output=True, text=True, timeout=HALMOS_TIMEOUT_S)
        except subprocess.TimeoutExpired as exc:
            stdout = (exc.stdout or "") + (exc.stderr or "")
            console.print("[verify] outcome:  TIMEOUT")
            console.print("[verify] counterexamples: 0")
            return "TIMEOUT", None, stdout, fn_cmd

        chunk = proc.stdout + "\n" + proc.stderr
        combined += chunk + "\n"
        if json_out.exists():
            outcome, ces = parse_halmos_json(json_out)
            if outcome == "ERROR":
                outcome = parse_halmos_stdout(chunk)
        else:
            outcome = parse_halmos_stdout(chunk)
            ces = None

        if outcome == "FAIL":
            worst = "FAIL"
            if ces:
                all_counterexamples.extend(ces)
        elif outcome in ("ERROR", "TIMEOUT") and worst == "PASS":
            worst = outcome
        cmd = fn_cmd

    ce_count = len(all_counterexamples)
    console.print(f"[verify] outcome:  {worst}")
    console.print(f"[verify] counterexamples: {ce_count}")
    return worst, all_counterexamples or None, combined, cmd


def verify_one(finding_id: str, commit_kind: CommitKind, *, dry_run: bool = False) -> VerifyResult:
    ensure_halmos()
    finding = load_seed_finding(finding_id)
    commit_sha = resolve_commit(finding, commit_kind)
    if not finding.repo_url:
        raise ValueError("repo_url missing")

    t0 = time.perf_counter()
    workdir = repo_workdir(finding_id, commit_kind)
    console.print(f"[verify] commit:   {commit_sha}")

    if not dry_run:
        console.print(f"  [dim]clone {finding.repo_url} @ {commit_sha[:12]}...[/dim]")
        clone_repo(finding.repo_url, workdir, commit_sha)
        if commit_kind == "fix" and finding.synthetic_fix:
            console.print("  [dim]apply synthetic fix patch...[/dim]")
            apply_synthetic_patch(finding_id, workdir, affected_file=finding.affected_file)
        console.print("  [dim]forge install + submodules + halmos-cheatcodes...[/dim]")
        forge_install(workdir)

    ensure_solc(workdir if workdir.exists() else None)

    src_test = test_file_path(finding_id)
    contract_name = parse_contract_name(src_test)

    if dry_run:
        rel_test = Path("test/bugzy") / f"{test_contract_name(finding_id)}.t.sol"
        outcome, counterexamples, stdout, _ = run_halmos(
            workdir, rel_test, contract_name=contract_name, test_source=src_test, dry_run=True
        )
        return VerifyResult(
            finding_id=finding_id,
            commit_kind=commit_kind,
            commit_sha=commit_sha,
            halmos_outcome=outcome,
            counterexamples=counterexamples,
            halmos_stdout=stdout,
            duration_seconds=0.0,
            ran_at=datetime.now(timezone.utc).isoformat(),
        )

    console.print("  [dim]copy test + forge build...[/dim]")
    dest = copy_test(workdir, finding_id)
    rel_test = dest.relative_to(workdir)

    _prebuild_ronin_artifacts(workdir, finding_id)
    built, build_out, build_err = forge_build(workdir, force=False)
    if not built:
        console.print("  [red]BUILD_FAILED[/red]")
        result = VerifyResult(
            finding_id=finding_id,
            commit_kind=commit_kind,
            commit_sha=commit_sha,
            halmos_outcome="BUILD_FAILED",
            halmos_stdout=(build_out + build_err)[:5000],
            duration_seconds=time.perf_counter() - t0,
            ran_at=datetime.now(timezone.utc).isoformat(),
        )
        save_result(result)
        return result

    outcome, counterexamples, stdout, _ = run_halmos(
        workdir, rel_test, contract_name=contract_name, test_source=src_test
    )

    result = VerifyResult(
        finding_id=finding_id,
        commit_kind=commit_kind,
        commit_sha=commit_sha,
        halmos_outcome=outcome,
        counterexamples=counterexamples,
        halmos_stdout=stdout[:5000],
        duration_seconds=round(time.perf_counter() - t0, 2),
        ran_at=datetime.now(timezone.utc).isoformat(),
    )
    save_result(result)
    return result


def save_result(result: VerifyResult) -> Path:
    VERIFY_DIR.mkdir(parents=True, exist_ok=True)
    path = VERIFY_DIR / f"{result.finding_id}_{result.commit_kind}.json"
    path.write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return path


def cmd_one(finding_id: str, commit_kind: CommitKind, *, dry_run: bool = False) -> int:
    load_dotenv(ROOT / ".env")
    console.print(f"[bold]Verify[/bold] {finding_id} @ {commit_kind}")
    try:
        result = verify_one(finding_id, commit_kind, dry_run=dry_run)
    except ValueError as exc:
        console.print(f"[yellow]SKIP:[/yellow] {exc}")
        return 1
    except subprocess.CalledProcessError as exc:
        console.print(f"[red]GIT ERROR:[/red] {exc.stderr or exc}")
        return 1

    if dry_run:
        console.print("[green]dry-run complete[/green]")
        return 0

    style = {"PASS": "green", "FAIL": "red", "TIMEOUT": "yellow"}.get(result.halmos_outcome, "red")
    console.print(f"[{style}]{result.halmos_outcome}[/{style}] in {result.duration_seconds}s")
    console.print(f"Saved -> {VERIFY_DIR / (finding_id + '_' + commit_kind + '.json')}")
    return 0


def cmd_all(commit_kind: CommitKind) -> int:
    load_dotenv(ROOT / ".env")
    ok = skip = fail = 0
    for finding in load_all_seed_findings():
        if not test_file_path(finding.id).exists():
            console.print(f"[yellow]SKIP[/yellow] {finding.id}: no generated test")
            skip += 1
            continue
        try:
            result = verify_one(finding.id, commit_kind)
            if result.halmos_outcome in ("PASS", "FAIL"):
                ok += 1
            else:
                fail += 1
        except ValueError:
            skip += 1
        except Exception as exc:
            console.print(f"[red]FAILED[/red] {finding.id}: {exc}")
            fail += 1
    console.print(f"\n[bold]Done:[/bold] {ok} ran, {skip} skipped, {fail} failed")
    return 0 if fail == 0 else 1


def main() -> None:
    parser = argparse.ArgumentParser(description="BugMine Halmos verification")
    sub = parser.add_subparsers(dest="command", required=True)

    one_p = sub.add_parser("one")
    one_p.add_argument("finding_id")
    one_p.add_argument("--commit", choices=["vulnerable", "fix"], required=True)
    one_p.add_argument("--dry-run", action="store_true")

    all_p = sub.add_parser("all")
    all_p.add_argument("--commit", choices=["vulnerable", "fix"], required=True)
    all_p.add_argument("--dry-run", action="store_true")

    args = parser.parse_args()
    if args.command == "one":
        sys.exit(cmd_one(args.finding_id, args.commit, dry_run=args.dry_run))
    sys.exit(cmd_all(args.commit))


if __name__ == "__main__":
    main()
