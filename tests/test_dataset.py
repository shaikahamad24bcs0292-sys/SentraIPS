"""
Unit and integration tests for Dataset Builder and label generation (Phase 2).
"""

from pathlib import Path
import pandas as pd
import pytest

from dataset.builder import DatasetBuilder


def test_dataset_builder_execution(project_root: Path):
    """Verify DatasetBuilder synchronizes captures, processes features, and generates labels.csv."""
    builder = DatasetBuilder(base_dir=project_root)
    res = builder.build_dataset()

    assert res["total_captures_processed"] > 0
    assert Path(res["labels_file"]).exists()
    assert Path(res["processed_dir"]).exists()

    df = pd.read_csv(res["labels_file"])
    assert len(df) == res["total_captures_processed"]

    # Verify required schema columns exist
    for col in DatasetBuilder.LABEL_COLUMNS:
        assert col in df.columns, f"Missing column '{col}' in labels.csv"

    # Verify at least one processed feature JSON file exists
    proc_files = list(Path(res["processed_dir"]).glob("*_features.json"))
    assert len(proc_files) > 0
