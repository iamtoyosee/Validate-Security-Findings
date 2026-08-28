from pathlib import Path


class CodebaseTooLargeError(Exception):
    pass


class LocalPathSource:
    def __init__(self, path: Path, max_lines: int = 5000):
        self.path, self.max_lines = path, max_lines

    def materialize(self) -> Path:
        total_lines = sum(
            len(f.read_text().splitlines())
            for f in self.path.rglob("*.py")
        )
        if total_lines > self.max_lines:
            raise CodebaseTooLargeError(
                f"This codebase is too large to test right now ({total_lines} lines, "
                f"limit {self.max_lines}) — try one of our controlled examples, or "
                f"upload something smaller."
            )
        return self.path
