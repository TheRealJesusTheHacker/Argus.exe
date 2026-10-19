"""Tests for the one-executable launch routing (argus.entry).

The packaged Argus.exe is the GUI, the service host, and the
setup/uninstall helper in one file; route_invocation() decides
which from argv alone. These pin the classification — most
importantly that the SCM's ``--service`` launch can never fall
through to the GUI or the management handler.
"""

import pytest

from argus.entry import route_invocation


@pytest.mark.parametrize(
    "argv,expected",
    [
        ([], "gui"),  # a person double-clicking the file
        (["--page", "devtoolkit"], "gui"),  # GUI's own option
        (["--service"], "service"),  # the SCM starting protection
        (["--run-setup"], "setup"),  # the GUI's elevated helper
        (["--uninstall"], "uninstall"),
        (["install"], "manage"),
        (["start"], "manage"),
        (["stop"], "manage"),
        (["status"], "manage"),
        (["register"], "manage"),
        (["service", "status"], "manage"),
        (["--service", "anything"], "service"),  # marker wins
    ],
)
def test_route_invocation(argv, expected):
    assert route_invocation(argv) == expected
