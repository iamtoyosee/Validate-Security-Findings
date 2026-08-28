from pathlib import Path

import pytest

from codebase_source import CodebaseTooLargeError, LocalPathSource

SAMPLE_APP = Path(__file__).parent.parent / "src" / "sample-apps" / "todo-list-app"


def test_materialize_returns_path_for_normal_sized_codebase():
    source = LocalPathSource(SAMPLE_APP)
    assert source.materialize() == SAMPLE_APP


def test_materialize_raises_for_oversized_codebase(tmp_path):
    big_file = tmp_path / "big.py"
    big_file.write_text("\n".join(f"x = {i}" for i in range(200)))

    source = LocalPathSource(tmp_path, max_lines=100)

    with pytest.raises(CodebaseTooLargeError, match="too large to test right now"):
        source.materialize()
