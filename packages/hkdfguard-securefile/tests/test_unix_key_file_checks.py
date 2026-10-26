"""The Linux and macOS key-file location rules, checked against simulated filesystems so they run on
every platform. test_trusted_key_file.py runs them against the real filesystem."""

from __future__ import annotations

import pytest
from hkdfguard.securefile import KeyFileTrust
from hkdfguard.securefile._unix import UnixFileStatus, UnixFileType, UnixKeyFileChecks

ROOT = 0
DEPLOYER = 1001
APP = 1002
DEPLOYERS_GROUP = 2001

KEY_FILE = "/etc/hkdfguard/keys/v1.key"

DEPLOYER_TRUST = KeyFileTrust(unix_user_ids=[DEPLOYER], unix_group_ids=[DEPLOYERS_GROUP])


class FileSystem:
    """A simulated filesystem: what lstat sees, and what each symbolic link holds."""

    def __init__(self) -> None:
        self.entries: dict[str, UnixFileStatus] = {}
        self.links: dict[str, str] = {}

    def dir(self, path: str, owner: int = ROOT, mode: int = 0o755, group: int = ROOT) -> FileSystem:
        self.entries[path] = UnixFileStatus(owner, group, mode, UnixFileType.DIRECTORY)
        return self

    def file(self, path: str, owner: int = ROOT, mode: int = 0o640, group: int = ROOT) -> FileSystem:
        self.entries[path] = UnixFileStatus(owner, group, mode, UnixFileType.REGULAR_FILE)
        return self

    def link(self, path: str, target: str, owner: int = ROOT) -> FileSystem:
        self.entries[path] = UnixFileStatus(owner, owner, 0o777, UnixFileType.SYMBOLIC_LINK)
        self.links[path] = target
        return self

    def other(self, path: str) -> FileSystem:
        self.entries[path] = UnixFileStatus(ROOT, ROOT, 0o640, UnixFileType.OTHER)
        return self

    def resolve(self, path: str, trust: KeyFileTrust = KeyFileTrust.ADMINISTRATORS_ONLY) -> str:
        return UnixKeyFileChecks.resolve_trusted(path, trust, self.entries.get, self.links.get)


def standard() -> FileSystem:
    return FileSystem().dir("/").dir("/etc").dir("/etc/hkdfguard").dir("/etc/hkdfguard/keys")


def test_root_owned_throughout_resolves() -> None:
    assert standard().file(KEY_FILE).resolve(KEY_FILE) == KEY_FILE


def test_readable_by_others_is_never_refused() -> None:
    assert standard().file(KEY_FILE, mode=0o644).resolve(KEY_FILE) == KEY_FILE


def test_a_file_owned_by_the_application_is_refused() -> None:
    fs = standard().file(KEY_FILE, owner=APP, group=APP)

    with pytest.raises(PermissionError, match="uid 1002"):
        fs.resolve(KEY_FILE)


def test_a_file_owned_by_a_trusted_deployer_resolves() -> None:
    assert standard().file(KEY_FILE, owner=DEPLOYER, group=DEPLOYER).resolve(KEY_FILE, DEPLOYER_TRUST) == KEY_FILE


def test_a_directory_owned_by_an_untrusted_user_is_refused() -> None:
    fs = standard().dir("/etc/hkdfguard/keys", owner=APP, group=APP).file(KEY_FILE)

    with pytest.raises(PermissionError, match="'/etc/hkdfguard/keys'"):
        fs.resolve(KEY_FILE)


def test_an_untrusted_root_is_refused() -> None:
    fs = standard().dir("/", mode=0o777).file(KEY_FILE)

    with pytest.raises(PermissionError):
        fs.resolve(KEY_FILE)


def test_a_root_that_can_not_be_examined_is_refused() -> None:
    with pytest.raises(PermissionError):
        FileSystem().resolve(KEY_FILE)


def test_a_world_writable_directory_is_refused_even_with_the_sticky_bit() -> None:
    fs = FileSystem().dir("/").dir("/tmp", mode=0o1777).dir("/tmp/keys").file("/tmp/keys/v1.key")

    with pytest.raises(PermissionError, match="writable by every user"):
        fs.resolve("/tmp/keys/v1.key")


def test_a_world_writable_file_is_refused_whatever_is_trusted() -> None:
    with pytest.raises(PermissionError):
        standard().file(KEY_FILE, mode=0o777).resolve(KEY_FILE, DEPLOYER_TRUST)


def test_group_writable_is_refused_unless_the_group_is_trusted() -> None:
    fs = standard().dir("/etc/hkdfguard/keys", mode=0o775, group=DEPLOYERS_GROUP).file(KEY_FILE, mode=0o660, group=DEPLOYERS_GROUP)

    with pytest.raises(PermissionError, match="group 2001"):
        fs.resolve(KEY_FILE)
    assert fs.resolve(KEY_FILE, DEPLOYER_TRUST) == KEY_FILE


def test_group_writable_by_another_group_is_refused_even_with_a_trusted_group() -> None:
    with pytest.raises(PermissionError):
        standard().file(KEY_FILE, mode=0o660, group=APP).resolve(KEY_FILE, DEPLOYER_TRUST)


def test_a_root_owned_symbolic_link_is_followed_and_its_target_checked() -> None:
    # macOS: /etc is a root-owned link to private/etc.
    fs = (FileSystem().dir("/").link("/etc", "private/etc").dir("/private").dir("/private/etc").dir("/private/etc/hkdfguard")
          .file("/private/etc/hkdfguard/v1.key"))

    assert fs.resolve("/etc/hkdfguard/v1.key") == "/private/etc/hkdfguard/v1.key"


def test_an_absolute_symbolic_link_restarts_from_root() -> None:
    fs = standard().file(KEY_FILE).dir("/srv").link("/srv/current.key", KEY_FILE)

    assert fs.resolve("/srv/current.key") == KEY_FILE


def test_a_symbolic_link_owned_by_an_untrusted_user_is_not_followed() -> None:
    fs = standard().file(KEY_FILE).dir("/srv").link("/srv/current.key", KEY_FILE, owner=APP)

    with pytest.raises(PermissionError, match="symbolic link owned by uid 1002"):
        fs.resolve("/srv/current.key")


def test_a_symbolic_link_owned_by_a_trusted_deployer_is_followed() -> None:
    fs = standard().file(KEY_FILE).dir("/srv").link("/srv/current.key", KEY_FILE, owner=DEPLOYER)

    assert fs.resolve("/srv/current.key", DEPLOYER_TRUST) == KEY_FILE


def test_a_symbolic_link_into_an_untrusted_directory_is_refused() -> None:
    fs = (standard().dir("/home").dir("/home/app", owner=APP, group=APP).file("/home/app/v1.key", owner=APP, group=APP)
          .link(KEY_FILE, "/home/app/v1.key"))

    with pytest.raises(PermissionError):
        fs.resolve(KEY_FILE)


def test_a_symbolic_link_loop_is_refused() -> None:
    fs = FileSystem().dir("/").link("/a", "/b").link("/b", "/a")

    with pytest.raises(PermissionError, match=f"more than {UnixKeyFileChecks.MAX_SYMBOLIC_LINKS} symbolic links"):
        fs.resolve("/a")


def test_an_unreadable_symbolic_link_is_refused() -> None:
    fs = standard().file(KEY_FILE).dir("/srv").link("/srv/current.key", KEY_FILE)
    del fs.links["/srv/current.key"]

    with pytest.raises(PermissionError, match="could not be read as a symbolic link"):
        fs.resolve("/srv/current.key")


def test_dot_and_dot_dot_are_resolved_after_links_the_way_the_kernel_does() -> None:
    fs = standard().file(KEY_FILE)

    assert fs.resolve("/etc/./hkdfguard/keys/../keys//v1.key") == KEY_FILE
    assert fs.resolve("/../etc/hkdfguard/keys/v1.key") == KEY_FILE


def test_a_missing_file_is_not_found() -> None:
    with pytest.raises(FileNotFoundError):
        standard().resolve(KEY_FILE)


def test_a_path_through_a_file_is_not_found() -> None:
    with pytest.raises(FileNotFoundError):
        standard().file(KEY_FILE).resolve(KEY_FILE + "/more")


def test_a_directory_is_refused() -> None:
    with pytest.raises(PermissionError, match="not a regular file"):
        standard().resolve("/etc/hkdfguard/keys")


def test_a_device_is_refused() -> None:
    with pytest.raises(PermissionError):
        standard().other(KEY_FILE).resolve(KEY_FILE)


def test_a_relative_path_is_an_argument_error() -> None:
    with pytest.raises(ValueError, match="not an absolute path"):
        standard().resolve("keys/v1.key")


def test_an_error_examining_a_component_is_passed_on() -> None:
    def failing(path: str) -> UnixFileStatus | None:
        if path == "/etc/hkdfguard":
            raise PermissionError("EACCES")
        return standard().file(KEY_FILE).entries.get(path)

    with pytest.raises(PermissionError, match="EACCES"):
        UnixKeyFileChecks.resolve_trusted(KEY_FILE, KeyFileTrust.ADMINISTRATORS_ONLY, failing, lambda path: None)


@pytest.mark.parametrize(("path", "parent"), [("/etc/hkdfguard", "/etc"), ("/etc", "/"), ("/", "/")])
def test_parent_of_is_the_lexical_parent(path: str, parent: str) -> None:
    assert UnixKeyFileChecks.parent_of(path) == parent
