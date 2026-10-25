"""A pseudo-terminal for a tool that only answers to a keyboard: androidqf up
to 1.8.x asks its questions with arrow-key menus.

Linux and macOS use pty. Windows has no pty: it uses ConPTY through pywinpty,
which hands the output over a local socket, so select() works there too.
Both give the same four calls: read, write, stop, close."""

import os
import select
import signal
import struct
from pathlib import Path

ROWS, COLS = 50, 160


class PosixTerminal:
    def __init__(self, cmd: list[str], cwd: Path):
        import fcntl
        import pty
        import termios
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(cwd)
            os.execv(cmd[0], cmd)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
        self.pid, self.fd = pid, fd

    def read(self, timeout: float) -> bytes | None:
        """Output that came within `timeout` seconds (b"" for none), or None
        when the program has ended."""
        ready, _, _ = select.select([self.fd], [], [], timeout)
        if not ready:
            return b""
        try:
            data = os.read(self.fd, 65536)
        except OSError:  # EIO: the program exited
            return None
        return data or None

    def write(self, data: bytes) -> None:
        os.write(self.fd, data)

    def stop(self) -> None:
        os.kill(self.pid, signal.SIGTERM)

    def close(self) -> int:
        os.close(self.fd)
        _, status = os.waitpid(self.pid, 0)
        return os.waitstatus_to_exitcode(status)


class WindowsTerminal:
    def __init__(self, cmd: list[str], cwd: Path):
        from winpty import PtyProcess  # pyright: ignore[reportMissingImports]  (Windows only)
        self.proc = PtyProcess.spawn(cmd, cwd=str(cwd), dimensions=(ROWS, COLS))

    def read(self, timeout: float) -> bytes | None:
        ready, _, _ = select.select([self.proc.fileobj], [], [], timeout)
        if not ready:
            return b""
        try:
            return self.proc.read(65536).encode("utf-8")
        except EOFError:
            return None

    def write(self, data: bytes) -> None:
        self.proc.write(data.decode("utf-8"))

    def stop(self) -> None:
        self.proc.terminate(force=True)

    def close(self) -> int:
        code = self.proc.wait()
        self.proc.close()
        return int(code or 0)


def open_terminal(cmd: list[str], cwd: Path) -> PosixTerminal | WindowsTerminal:
    return WindowsTerminal(cmd, cwd) if os.name == "nt" else PosixTerminal(cmd, cwd)
