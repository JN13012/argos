"""Exact candidate comparison and a checksum-keyed local embedding cache."""

import importlib
import json
import sqlite3
from hashlib import sha256
from time import monotonic, sleep
from urllib.request import ProxyHandler, Request, build_opener

MODELS = {
    "qwen3-embedding:0.6b": (1024, (256, 512, 1024)),
    "embeddinggemma:300m": (768, (256, 512, 768)),
    "bge-m3:567m": (1024, (1024,)),
}


def prepare(model, text, title=None):
    if model.startswith("qwen3") and title is None:
        return (
            "Instruct: Given a technical question, retrieve relevant documentation"
            " passages.\nQuery: " + text
        )
    if model.startswith("embeddinggemma"):
        if title is None:
            return f"task: search result | query: {text}"
        return f"title: {title} | text: {text}"
    return text if title is None else f"{title}\n{text}"


class Ollama:
    def __init__(self, port, model, cache: sqlite3.Connection):
        self.url = f"http://127.0.0.1:{port}/api"
        self.model = model
        self.cache = cache
        self.opener = build_opener(ProxyHandler({}))
        self.version = self.call("/version")["version"]
        installed = next(
            (m for m in self.call("/tags")["models"] if m["name"] == model), None
        )
        if not installed:
            raise ValueError(f"Model absent: {model}")
        self.digest = installed["digest"]
        self.cache.execute(
            "CREATE TABLE IF NOT EXISTS vectors(key TEXT PRIMARY KEY, value BLOB)"
        )
        self.hits = self.misses = 0
        self.last_api = {}

    def call(self, endpoint, payload=None):
        if payload is None:
            request = Request(self.url + endpoint)
        else:
            request = Request(
                self.url + endpoint,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
            )
        with self.opener.open(request, timeout=180) as response:
            return json.load(response)

    def embed(self, texts, *, cached=True):
        np = importlib.import_module("numpy")
        result = {}
        pending = {}
        for text in dict.fromkeys(texts):
            key = sha256(
                f"v1\0{self.version}\0{self.digest}\0{text}".encode()
            ).hexdigest()
            row = (
                self.cache.execute(
                    "SELECT value FROM vectors WHERE key=?", (key,)
                ).fetchone()
                if cached
                else None
            )
            if row:
                self.hits += 1
                result[text] = np.frombuffer(row[0], dtype="<f4")
            else:
                pending[text] = key
        if pending:
            self.misses += len(pending)
            reply = self.call(
                "/embed",
                {
                    "model": self.model,
                    "input": list(pending),
                    "truncate": False,
                    "keep_alive": "5m",
                },
            )
            self.last_api = {k: v for k, v in reply.items() if k != "embeddings"}
            vectors = np.asarray(reply["embeddings"], dtype="<f4")
            if (
                vectors.shape != (len(pending), MODELS[self.model][0])
                or not np.isfinite(vectors).all()
            ):
                raise ValueError(
                    f"Unexpected embedding shape or values: {vectors.shape}"
                )
            with self.cache:
                for (text, key), vector in zip(pending.items(), vectors, strict=True):
                    result[text] = vector
                    if cached:
                        self.cache.execute(
                            "INSERT OR IGNORE INTO vectors VALUES (?, ?)",
                            (key, vector.tobytes()),
                        )
        return np.asarray([result[text] for text in texts], dtype=np.float32)

    def unload(self):
        self.call("/embed", {"model": self.model, "input": [], "keep_alive": 0})
        deadline = monotonic() + 20
        while monotonic() < deadline:
            state = self.call("/ps")
            if not state["models"]:
                return state
            sleep(0.05)
        raise ValueError("Dedicated Ollama server did not unload all models")


def unit(vectors, dimension=None):
    np = importlib.import_module("numpy")
    rows = np.ascontiguousarray(vectors[..., :dimension], dtype=np.float32)
    norms = np.linalg.norm(rows, axis=-1, keepdims=True)
    if np.any(norms == 0) or not np.isfinite(norms).all():
        raise ValueError("Invalid cosine vector")
    return np.ascontiguousarray(rows / norms)


class Exact:
    def __init__(self, vectors, backend="numpy", *, path=":memory:"):
        self.vectors = vectors
        self.backend = backend
        self.index = None
        if backend == "faiss":
            faiss = importlib.import_module("faiss")
            faiss.omp_set_num_threads(1)
            self.index = faiss.IndexFlatIP(vectors.shape[1])
            self.index.add(vectors)
        if backend == "sqlite-vec":
            extension = importlib.import_module("sqlite_vec")
            self.index = sqlite3.connect(path)
            self.index.enable_load_extension(True)
            try:
                extension.load(self.index)
            finally:
                self.index.enable_load_extension(False)
            self.index.execute(
                "CREATE VIRTUAL TABLE points USING vec0("
                f"vector float[{vectors.shape[1]}] distance_metric=cosine)"
            )
            with self.index:
                self.index.executemany(
                    "INSERT INTO points(rowid,vector) VALUES (?,?)",
                    ((i, row.tobytes()) for i, row in enumerate(vectors)),
                )

    def search(self, query, limit):
        np = importlib.import_module("numpy")
        limit = min(limit, len(self.vectors))
        if self.backend == "faiss":
            scores, indices = self.index.search(query.reshape(1, -1), limit)
            return list(zip(indices[0].tolist(), scores[0].tolist(), strict=True))
        if self.backend == "sqlite-vec":
            return [
                (i, 1 - distance)
                for i, distance in self.index.execute(
                    "SELECT rowid,distance FROM points WHERE vector MATCH ?"
                    " AND k=? ORDER BY distance",
                    (query.tobytes(), limit),
                )
            ]
        scores = self.vectors @ query
        if limit < len(scores):
            cutoff = np.partition(scores, len(scores) - limit)[-limit]
            better = np.flatnonzero(scores > cutoff)
            ties = np.flatnonzero(scores == cutoff)[: limit - len(better)]
            candidates = np.concatenate([better, ties])
        else:
            candidates = np.arange(len(scores))
        order = candidates[np.lexsort((candidates, -scores[candidates]))]
        return [(int(i), float(scores[i])) for i in order]

    def close(self):
        if isinstance(self.index, sqlite3.Connection):
            self.index.close()
