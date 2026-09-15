import json
from pathlib import Path

from benchmarks.compare_capabilities import compare, load


def test_capability_matrix_does_not_infer_competitor_results():
    matrix = load(str(Path(__file__).parents[1] / "benchmarks" / "capability_matrix.json"))
    result = compare(matrix)
    rows = {row["system"]: row for row in result["systems"]}
    assert rows["KMN-CyberSeek"]["comparison_allowed"] is True
    assert rows["PentestGPT"]["assessment"] == "unassessed"
    assert rows["PentestGPT"]["comparison_allowed"] is False
