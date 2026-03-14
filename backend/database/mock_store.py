"""
In-memory data store used as a fallback when MongoDB is unavailable.
Mirrors the MongoDB collection interface used throughout the application.
"""

from __future__ import annotations
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional
import copy

# ---------------------------------------------------------------------------
# Simple in-memory collections
# ---------------------------------------------------------------------------

_store: Dict[str, List[Dict]] = defaultdict(list)


def _now_iso() -> str:
    return datetime.utcnow().isoformat()


class InMemoryCollection:
    """Minimal async-compatible collection that mimics motor's API."""

    def __init__(self, name: str):
        self.name = name

    @property
    def _data(self) -> List[Dict]:
        return _store[self.name]

    async def insert_one(self, document: Dict) -> Any:
        doc = copy.deepcopy(document)
        if "_id" not in doc:
            doc["_id"] = str(len(self._data) + 1)
        self._data.append(doc)

        class Result:
            inserted_id = doc["_id"]

        return Result()

    async def find(self, query: Dict = None, sort=None, limit: int = 0) -> List[Dict]:
        results = copy.deepcopy(self._data)
        if query:
            results = [r for r in results if _matches(r, query)]
        if sort:
            for key, direction in reversed(sort):
                results.sort(key=lambda x: x.get(key, ""), reverse=(direction == -1))
        if limit:
            results = results[:limit]
        return results

    async def find_one(self, query: Dict = None) -> Optional[Dict]:
        results = await self.find(query)
        return results[0] if results else None

    async def count_documents(self, query: Dict = None) -> int:
        results = await self.find(query)
        return len(results)

    async def update_one(self, query: Dict, update: Dict) -> None:
        for doc in self._data:
            if _matches(doc, query):
                if "$set" in update:
                    doc.update(update["$set"])
                break

    async def delete_many(self, query: Dict = None) -> None:
        if not query:
            _store[self.name].clear()
        else:
            _store[self.name] = [d for d in self._data if not _matches(d, query)]


def _matches(doc: Dict, query: Dict) -> bool:
    for k, v in query.items():
        if isinstance(v, dict):
            # Support simple operators
            doc_val = doc.get(k)
            for op, op_val in v.items():
                if op == "$gte" and not (doc_val >= op_val):
                    return False
                if op == "$lte" and not (doc_val <= op_val):
                    return False
                if op == "$in" and doc_val not in op_val:
                    return False
        else:
            if doc.get(k) != v:
                return False
    return True


# Singleton accessors
_collections: Dict[str, InMemoryCollection] = {}


def get_mock_collection(name: str) -> InMemoryCollection:
    if name not in _collections:
        _collections[name] = InMemoryCollection(name)
    return _collections[name]
