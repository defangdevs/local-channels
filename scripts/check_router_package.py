"""Build and smoke-test installable router artifacts; setuptools/wheel are tooling only.

Run after installing the build requirements from local-router/pyproject.toml.
All builds and installations use temporary copies, never the checkout itself.
"""
import email.parser
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile


ROOT = Path(__file__).resolve().parents[1]


def run(argv, cwd, **kwargs):
    try:
        return subprocess.check_output(argv, cwd=cwd, text=True, **kwargs).strip()
    except subprocess.CalledProcessError as exc:
        print(exc.output, file=sys.stderr)
        raise


def build(source, output, kind):
    output.mkdir()
    # Call the declared PEP 517 backend without downloading anything. CI installs
    # its selected build-tool versions first, including the declared minimum.
    run([sys.executable, "-c",
         "from setuptools import build_meta; build_meta.build_%s(%r)" % (kind, str(output))],
        cwd=source)
    return next(output.glob("*.whl" if kind == "wheel" else "*.tar.gz"))


def check_wheel(wheel, notice, version, scratch):
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        licenses = [n for n in names if n.endswith("/LICENSE")]
        assert licenses, "wheel omits LICENSE"
        assert all(archive.read(n) == notice for n in licenses), "wheel notice differs"
        metadata = email.parser.Parser().parsestr(archive.read(
            next(n for n in names if n.endswith(".dist-info/METADATA"))).decode())
        assert metadata["Name"] == "local-router"
        assert metadata["Version"] == version
        assert metadata["Requires-Python"] == ">=3.9"
        assert metadata["License-Expression"] == "MIT"
        assert metadata.get_all("License-File") == ["LICENSE"]
        assert not metadata.get_all("Requires-Dist"), "unexpected runtime dependency"

    envdir = scratch / "installed"
    venv.EnvBuilder(with_pip=True).create(envdir)
    python = envdir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    cli = envdir / ("Scripts/local-router.exe" if os.name == "nt" else "bin/local-router")
    # Build tooling may be on PYTHONPATH. It must not hide a broken installation.
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    try:
        run([str(python), "-I", "-m", "pip", "install", "--no-index", "--no-deps",
             "--no-compile", str(wheel)], cwd=scratch, env=env)
        imported = run([str(python), "-I", "-c",
                        "import router, sys; from pathlib import Path; "
                        "assert Path(router.__file__).is_relative_to(Path(sys.prefix)); "
                        "assert router.route({'text': 'hi'}, [], None)['action'] == 'NEW'; "
                        "print(router.VERSION)"], cwd=scratch, env=env)
        assert imported == version, "installed module version differs"
        assert run([str(cli), "version"], cwd=scratch, env=env) == version
        decision = json.loads(run([str(cli), "route", "--backend", "none"], cwd=scratch,
                                  env=env, input='{"message":{"text":"hi"},"sessions":[]}'))
        assert decision["action"] == "NEW", decision
    finally:
        shutil.rmtree(envdir)
    print("Validated license, metadata, isolated import and installed CLI:", wheel.name)


def main():
    notice = (ROOT / "LICENSE").read_bytes()
    assert (ROOT / "local-router/LICENSE").read_bytes() == notice, "router license must match root"
    with tempfile.TemporaryDirectory(prefix="router-package-") as directory:
        scratch = Path(directory)
        source = scratch / "source"
        source.mkdir()
        # Start clean: stale egg-info/build files in a developer checkout must
        # not rescue missing package metadata or a missing source file.
        for name in ("router.py", "pyproject.toml", "README.md", "LICENSE"):
            shutil.copyfile(ROOT / "local-router" / name, source / name)
        version = run([sys.executable, str(source / "router.py"), "version"], cwd=scratch)
        wheel = build(source, scratch / "wheel", "wheel")
        check_wheel(wheel, notice, version, scratch)
        # Build the source archive independently of the wheel's generated files.
        shutil.rmtree(source / "build")
        for generated in source.glob("*.egg-info"):
            shutil.rmtree(generated)
        sdist = build(source, scratch / "sdist", "sdist")
        extracted = scratch / "extracted"
        extracted.mkdir()
        with tarfile.open(sdist) as archive:
            members = archive.getmembers()
            license_member = next(m for m in members if m.name.endswith("/LICENSE"))
            assert archive.extractfile(license_member).read() == notice, "sdist notice differs"
            # These are generated artifacts; still restrict extraction to this
            # scratch directory, on all supported Python versions.
            for member in members:
                target = (extracted / member.name).resolve()
                assert extracted in target.parents and (member.isfile() or member.isdir())
            # Filtering was backported to supported Python 3.9 patch releases.
            if hasattr(tarfile, "data_filter"):
                archive.extractall(extracted, filter="data")
            else:
                archive.extractall(extracted)
        rebuilt = build(next(extracted.iterdir()), scratch / "rebuilt-wheel", "wheel")
        check_wheel(rebuilt, notice, version, scratch)


if __name__ == "__main__":
    main()
