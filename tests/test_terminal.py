"""androidqf's arrow-key menus, answered through the pseudo-terminal
(src/sta/terminal.py): a small program asks the same questions."""

import json
import sys

import pytest

from sta import acquire, common
from sta.common import StepError

# Asks each question like androidqf 1.8.3, then writes how many times Down was
# pressed before Enter. On POSIX the keys arrive as a line ("\x1b[B...\n").
# On Windows ConPTY turns them into key presses, which getwch() returns as
# "\xe0P" for Down and "\r" for Enter.
MENUS = r"""
import json, os, sys

def downs():
    if os.name != "nt":
        return sys.stdin.readline().count("\x1b[B")
    import msvcrt
    count = 0
    while (ch := msvcrt.getwch()) != "\r":
        if ch in ("\xe0", "\x00") and msvcrt.getwch() == "P":
            count += 1
    return count

got = {}
for label in sys.argv[2:]:
    print(f"? {label}: ", flush=True)
    got[label] = downs()
print("Press Enter to finish", flush=True)
downs()
with open(sys.argv[1], "w") as handle:
    handle.write(json.dumps(got))
"""


@pytest.fixture
def menus(tmp_path):
    script = tmp_path / "menus.py"
    script.write_text(MENUS)
    return script


def test_every_menu_gets_its_answer(tmp_path, menus):
    out, log = tmp_path / "answers.json", tmp_path / "logs" / "androidqf.log"
    answers = acquire.menu_answers(sms_backup=False)
    code = acquire.run_with_menus([sys.executable, str(menus), str(out), *answers], cwd=tmp_path,
                                  log=log, answers=answers, timeout=60)
    assert code == 0
    assert json.loads(out.read_text()) == answers
    assert "menus answered" in log.read_text(encoding="utf-8")


def test_a_program_that_runs_too_long_is_stopped(tmp_path, menus):
    with pytest.raises(StepError, match="more than 0 hours"):
        acquire.run_with_menus([sys.executable, str(menus), str(tmp_path / "x.json"), "Never"],
                               cwd=tmp_path, log=tmp_path / "x.log", answers={}, timeout=2)


def test_a_held_lock_names_its_holder(case):
    case.lock("acquire")
    with pytest.raises(StepError, match="acquire, pid"):
        common.Case(case.path).lock("report")
