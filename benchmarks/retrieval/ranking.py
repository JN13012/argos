"""Small, deterministic lexical baseline and document-level ranking metrics."""

import math
import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Fragment:
    document: str
    locator: str
    title: str
    text: str
    collection: str = "public"


def chunk(document: str, raw: str, mode: str) -> list[Fragment]:
    front = re.match(r"\A---\s*\n(.*?)\n---\s*\n", raw, re.S)
    title = document
    if front:
        match = re.search(r"(?m)^title:\s*(.+)$", front[1])
        if match:
            title = match[1].strip("'\"")
        raw = raw[front.end() :]
    sections = [(title, raw)]
    if mode != "fixed":
        sections = []
        heading, body, fence = title, [], ""
        for line in raw.splitlines(keepends=True):
            marker = re.match(r"^\s*(`{3,}|~{3,})", line)
            if marker and not fence:
                fence = marker[1]
            elif marker and marker[1].startswith(fence):
                fence = ""
            match = None if fence else re.match(r"^#{1,6}\s+(.+)", line)
            if match:
                sections.append((heading, "".join(body)))
                heading, body = match[1].strip(), []
            else:
                body.append(line)
        sections.append((heading, "".join(body)))

    result = []
    for section, (heading, body) in enumerate(sections):
        while body.strip():
            width = 1024
            if mode == "recursive" and len(body) > width:
                window = body[:width]
                for separator in ("\n\n", "\n", " "):
                    split = window.rfind(separator)
                    if split >= width // 2:
                        width = split + len(separator)
                        break
            text, body = body[:width].strip(), body[width:]
            if text:
                result.append(
                    Fragment(
                        document,
                        f"{section}:{len(result)}",
                        f"{title} | {heading}",
                        text,
                    )
                )
    return result


def deduplicate(fragments):
    """Remove duplicate fragments only within the same document and collection."""
    seen = set()
    result = []
    for item in fragments:
        key = (item.collection, item.document, item.title, item.text)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def document_ranking(matches, limit=40):
    seen = set()
    result = []
    for item in matches:
        if item[0] not in seen:
            seen.add(item[0])
            result.append(item)
            if len(result) == limit:
                break
    return result


class Lexical:
    def __init__(self, fragments, allowed, path: Path | str = ":memory:"):
        self.db = sqlite3.connect(path)
        self.db.execute(
            "CREATE VIRTUAL TABLE passages USING fts5(doc UNINDEXED, locator UNINDEXED,"
            " title, text, tokenize='unicode61 remove_diacritics 2')"
        )
        with self.db:
            self.db.executemany(
                "INSERT INTO passages VALUES (?, ?, ?, ?)",
                (
                    (row.document, row.locator, row.title, row.text)
                    for row in fragments
                    if row.collection in allowed
                ),
            )

    @classmethod
    def reopen(cls, path: Path):
        index = cls.__new__(cls)
        index.db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
        return index

    def close(self):
        self.db.close()

    def search(self, query):
        words = list(dict.fromkeys(re.findall(r"[^\W_]+", query.lower())))[:40]
        if not words:
            return []
        expression = " OR ".join(f'"{word}"' for word in words)
        rows = self.db.execute(
            "SELECT doc, -bm25(passages,0,0,3,1) AS score, locator FROM passages "
            "WHERE passages MATCH ? ORDER BY score DESC,doc,locator LIMIT 1000",
            (expression,),
        )
        return document_ranking(rows)


def rrf(*rankings, k=60):
    scores = defaultdict(float)
    locators = {}
    for ranking in rankings:
        for rank, (identifier, _, locator) in enumerate(ranking, 1):
            scores[identifier] += 1 / (k + rank)
            locators.setdefault(identifier, locator)
    return [
        (key, scores[key], locators[key])
        for key in sorted(scores, key=lambda x: (-scores[x], x))
    ]


def metrics(rows):
    """Macro-average positive-query scores; abstention is evaluated separately."""
    sums = defaultdict(float)
    positive = 0
    exact = 0
    for row in rows:
        gold = row["grades"]
        ids = [value[0] for value in row["hits"]]
        if not gold:
            continue
        positive += 1
        for cutoff in (5, 10):
            sums[f"recall@{cutoff}"] += sum(
                gold.get(i, 0) > 0 for i in ids[:cutoff]
            ) / len(gold)
        sums["precision@5"] += sum(gold.get(i, 0) > 0 for i in ids[:5]) / 5
        sums["mrr"] += next(
            (1 / rank for rank, i in enumerate(ids, 1) if gold.get(i)), 0
        )
        dcg = sum(
            (2 ** gold.get(i, 0) - 1) / math.log2(rank + 2)
            for rank, i in enumerate(ids[:10])
        )
        ideal = sum(
            (2**grade - 1) / math.log2(rank + 2)
            for rank, grade in enumerate(sorted(gold.values(), reverse=True)[:10])
        )
        sums["ndcg@10"] += dcg / ideal
        if row["category"] == "exact":
            exact += 1
            sums["exact@1"] += bool(ids and gold.get(ids[0], 0))
    return {
        key: value / (exact if key == "exact@1" else positive)
        for key, value in sums.items()
    }


def abstention(rows, threshold):
    tp = sum(bool(row["grades"]) and top(row) >= threshold for row in rows)
    tn = sum(not row["grades"] and top(row) < threshold for row in rows)
    positives = sum(bool(row["grades"]) for row in rows)
    negatives = len(rows) - positives
    return {
        "answer_recall": tp / positives if positives else None,
        "no_answer_recall": tn / negatives if negatives else None,
        "no_answer_precision": tn / (tn + positives - tp)
        if tn + positives - tp
        else None,
        "tp": tp,
        "tn": tn,
        "positives": positives,
        "negatives": negatives,
    }


def top(row):
    return row["hits"][0][1] if row["hits"] else -1.0e20


def tune_threshold(rows):
    candidates = {top(row) for row in rows}
    candidates.add(max(candidates) + 1)
    best = (-1.0, -math.inf)
    for threshold in candidates:
        values = abstention(rows, threshold)
        answer = values["answer_recall"]
        no_answer = values["no_answer_recall"]
        if answer is None or no_answer is None:
            raise ValueError(
                "Development set must contain both positive and absent queries"
            )
        best = max(best, ((answer + no_answer) / 2, threshold))
    return best[1]
