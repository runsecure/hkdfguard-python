"""Checks the built distributions before they are published.

    uv build --all-packages --out-dir dist
    python scripts/check-dist.py dist [--tag v1.0.0]

Refuses to pass unless, for the ten hkdfguard-* distributions:

* each has exactly one wheel and one sdist, and nothing else is in the directory;
* every one has the same version, and with ``--tag`` that version is the tag without its ``v``;
* every wheel carries the licence text and a README as its description, and its dependencies on
  sibling distributions resolve to a distribution that is being published;
* no wheel installs a top-level ``hkdfguard/__init__.py`` (it would turn the shared namespace into a
  regular package and break every sibling), and no two wheels install the same file.

Standard library only, so it runs before anything is installed.
"""

from __future__ import annotations

import argparse
import re
import sys
import tarfile
import zipfile
from collections import defaultdict
from email.parser import Parser
from pathlib import Path

EXPECTED = {
    "hkdfguard-abstractions",
    "hkdfguard-cache",
    "hkdfguard-cryptoprovider-aesgcm256",
    "hkdfguard-dataencryptionkey",
    "hkdfguard-diagnostics",
    "hkdfguard-keywrapping-awskms",
    "hkdfguard-keywrapping-azurekeyvault",
    "hkdfguard-keywrapping-v1",
    "hkdfguard-options",
    "hkdfguard-securefile",
}
WHEEL = re.compile(r"^(?P<name>[A-Za-z0-9_]+)-(?P<version>[^-]+)-py3-none-any\.whl$")
SDIST = re.compile(r"^(?P<name>[A-Za-z0-9_]+)-(?P<version>.+)\.tar\.gz$")


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


Found = dict[str, tuple[str, Path]]


def collect(directory: Path, problems: list[str]) -> tuple[Found, Found]:
    """The wheel and sdist of each distribution in ``directory``, by normalized name."""
    wheels: Found = {}
    sdists: Found = {}
    for path in sorted(directory.iterdir()):
        if path.name == ".gitignore":  # uv build writes one into its output directory
            continue
        if (match := WHEEL.match(path.name)) is not None:
            kind, target = "wheel", wheels
        elif (match := SDIST.match(path.name)) is not None:
            kind, target = "sdist", sdists
        else:
            problems.append(f"{path.name}: not a wheel or sdist of this project.")
            continue
        name = normalize(match["name"])
        if name in target:
            problems.append(f"{name}: more than one {kind}.")
        target[name] = (match["version"], path)
    return wheels, sdists


def check_completeness(wheels: Found, sdists: Found, tag: str | None, problems: list[str]) -> None:
    for label, found in (("wheel", wheels), ("sdist", sdists)):
        problems.extend(f"{missing}: no {label}." for missing in sorted(EXPECTED - found.keys()))
        problems.extend(f"{extra}: unexpected {label}." for extra in sorted(found.keys() - EXPECTED))

    versions = {version for version, _ in [*wheels.values(), *sdists.values()]}
    if len(versions) > 1:
        problems.append(f"distributions disagree on the version: {', '.join(sorted(versions))}.")
    if tag is not None and versions != {tag.removeprefix("v")}:
        problems.append(f"tag {tag} requires version {tag.removeprefix('v')}; the build has {', '.join(sorted(versions)) or 'none'}.")


def check_wheel(path: Path, installed: dict[str, list[str]], problems: list[str]) -> None:
    with zipfile.ZipFile(path) as wheel:
        names = wheel.namelist()
        metadata_name = next((n for n in names if n.endswith(".dist-info/METADATA")), None)
        if metadata_name is None:
            problems.append(f"{path.name}: no METADATA.")
            return
        metadata = Parser().parsestr(wheel.read(metadata_name).decode("utf-8"))

    if not any(n.endswith(".dist-info/licenses/LICENSE") for n in names):
        problems.append(f"{path.name}: the licence text is not in the wheel.")
    if not str(metadata.get_payload()).strip():
        problems.append(f"{path.name}: no README as the long description.")
    if metadata["License-Expression"] != "MPL-2.0":
        problems.append(f"{path.name}: License-Expression is {metadata['License-Expression']!r}, not 'MPL-2.0'.")

    for requirement in metadata.get_all("Requires-Dist") or []:
        dependency = normalize(re.split(r"[ ;<>=!~(\[]", requirement, maxsplit=1)[0])
        if dependency.startswith("hkdfguard-") and dependency not in EXPECTED:
            problems.append(f"{path.name}: requires {dependency}, which this project does not publish.")

    for member in names:
        if ".dist-info/" in member:
            continue
        installed[member].append(path.name)
        if member == "hkdfguard/__init__.py":
            problems.append(f"{path.name}: installs hkdfguard/__init__.py, which breaks the shared namespace package.")


def check_sdist(path: Path, problems: list[str]) -> None:
    with tarfile.open(path) as sdist:
        members = [m.name for m in sdist.getmembers()]
    if not any(m.endswith("/LICENSE") for m in members):
        problems.append(f"{path.name}: the licence text is not in the sdist.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--tag", help="the release tag, e.g. v1.0.0; every distribution's version must equal it")
    arguments = parser.parse_args()

    problems: list[str] = []
    wheels, sdists = collect(arguments.directory, problems)
    check_completeness(wheels, sdists, arguments.tag, problems)

    installed: dict[str, list[str]] = defaultdict(list)
    for _, path in sorted(wheels.values(), key=lambda entry: entry[1].name):
        check_wheel(path, installed, problems)
    problems.extend(f"{member}: installed by more than one wheel ({', '.join(owners)})."
                    for member, owners in sorted(installed.items()) if len(owners) > 1)
    for _, path in sorted(sdists.values(), key=lambda entry: entry[1].name):
        check_sdist(path, problems)

    if problems:
        print(f"{len(problems)} problem(s) in {arguments.directory}:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    versions = sorted({version for version, _ in wheels.values()})
    print(f"OK: {len(wheels)} wheels and {len(sdists)} sdists, version {', '.join(versions)}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
