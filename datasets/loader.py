import json
from pathlib import Path

from core.memory.repository import MemoryRepository


class EnterpriseDatasetLoader:

    def __init__(self, repository: MemoryRepository):
        self.repository = repository

    def load(self, dataset_path: str | Path):
        path = Path(dataset_path)

        if not path.exists():
            raise FileNotFoundError(
                f"Dataset not found: {path}"
            )

        with path.open(
            "r",
            encoding="utf-8-sig"
        ) as file:
            records = json.load(file)

        if not isinstance(records, list):
            raise ValueError(
                "Dataset must contain a list of memory records."
            )

        loaded = []

        for record in records:
            required = {
                "memory_id",
                "content",
                "source",
                "source_type"
            }

            missing = required - record.keys()

            if missing:
                raise ValueError(
                    f"Missing fields for {record.get('memory_id', 'unknown')}: "
                    f"{sorted(missing)}"
                )

            memory = self.repository.create(
                memory_id=record["memory_id"],
                content=record["content"],
                source=record["source"],
                source_type=record["source_type"]
            )

            loaded.append(memory)

        return loaded
