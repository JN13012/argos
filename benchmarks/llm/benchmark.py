"""Offline evaluator of extractive analysis. Expected references never enter prompts."""

import argparse
import json
import threading
import time
from pathlib import Path

import httpx
from argos.backend.attack.review.analysis import _request, _selection
from argos.backend.attack.review.ollama import _completion, _require_local_model
from argos.backend.attack.web.receipts import digest

MODELS = ("qwen2.5:0.5b", "qwen3:4b", "gemma3:4b", "qwen3:8b", "deepseek-r1:7b")


def score(selected: list[int], required: list[int]) -> dict:
    """Reference correctness is checked before semantic relevance is scored."""
    hits = len(set(selected) & set(required))
    return {
        "relevance_precision": hits / len(selected) if selected else 0.0,
        "required_recall": hits / len(required) if required else None,
        "required_hits": hits,
    }


def fixtures() -> list[dict]:
    cases = []
    for reverse in (False, True):
        rows = [
            ("fact", "archived_http_response", {"status": 200}),
            (
                "unknown",
                "mapped_elements",
                {"element": "nodes", "category": "authentication", "count": 1},
            ),
            ("contradiction", "contradictory_observation", {}),
            (
                "inference",
                "technology_assessment",
                {"technology": "php", "identification_status": "probable"},
            ),
        ]
        rows.extend(
            (
                "fact",
                "mapped_elements",
                {"element": "nodes", "category": "resource", "count": n},
            )
            for n in range(1, 11)
        )
        if reverse:
            rows.reverse()
        items = [
            dict(
                state=state,
                kind=kind,
                source={"sha256": digest([state, kind, data])},
                **data,
            )
            for state, kind, data in rows
        ]
        context = dict(
            version="mission-review-context-v1",
            items=items,
            coverage={"exhaustive": False},
            omitted_items={},
        )
        _, observations = _request(context)
        required = [
            i + 1
            for i, item in enumerate(observations)
            if item["kind"] != "mapped_elements"
            or item.get("category") == "authentication"
        ]
        cases.append(
            dict(
                name="critical-gaps-reversed" if reverse else "critical-gaps",
                context=context,
                required=required,
            )
        )
    return cases


def sample_memory(stop, peak):
    """Sample all local Ollama processes. Shared RSS can be counted twice."""
    while not stop.is_set():
        total = 0
        for path in Path("/proc").glob("[0-9]*/status"):
            try:
                text = path.read_text()
                if "ollama" in text.splitlines()[0]:
                    total += next(
                        int(line.split()[1])
                        for line in text.splitlines()
                        if line.startswith("VmRSS:")
                    )
            except (OSError, StopIteration, ProcessLookupError):
                continue
        peak[0] = max(peak[0], total)
        stop.wait(0.1)


def run(args) -> None:
    cases = json.loads(Path(args.cases).read_text()) + fixtures()
    with httpx.Client(
        base_url=f"http://127.0.0.1:{args.port}", trust_env=False, timeout=180
    ) as client:
        for model in args.models:
            metadata = client.post("/api/show", json={"model": model}).json()
            _require_local_model(metadata)
            for case in cases:
                request, observations = _request(case["context"])
                client.post(
                    "/api/generate", json={"model": model, "keep_alive": 0}
                ).raise_for_status()
                for temperature in ("cold", "warm", "warm_repeat"):
                    payload = dict(
                        model=model,
                        stream=False,
                        think=False,
                        format=request.response_schema,
                        options=dict(temperature=0, num_ctx=8192, num_predict=384),
                        messages=[
                            dict(role="system", content=request.instructions),
                            dict(role="user", content=request.data_json),
                        ],
                    )
                    stop = threading.Event()
                    peak = [0]
                    sampler = threading.Thread(target=sample_memory, args=(stop, peak))
                    sampler.start()
                    started = time.perf_counter()
                    result = dict(
                        model=model,
                        case=case["name"],
                        phase=temperature,
                        input_sha256=digest(payload),
                        context_sha256=digest(request.data_json),
                        status="failed",
                    )
                    try:
                        response = client.post("/api/chat", json=payload)
                        response.raise_for_status()
                        raw = response.json()
                        result["latency_seconds"] = time.perf_counter() - started
                        result["input_tokens"] = raw.get("prompt_eval_count")
                        result["output_tokens"] = raw.get("eval_count")
                        duration = raw.get("eval_duration", 0)
                        result["tokens_per_second"] = (
                            raw.get("eval_count", 0) * 1e9 / duration
                            if duration
                            else None
                        )
                        completion = _completion(raw)
                        selected = _selection(completion.content, observations)
                        refs = json.loads(completion.content)["refs"]
                        result.update(
                            status="valid",
                            selected_refs=refs,
                            states=sorted({item["state"] for item in selected}),
                        )
                        result.update(
                            score(refs, case["required"])
                            if case.get("required")
                            else {}
                        )
                        result["quality_reference"] = (
                            "independent_fixture"
                            if case.get("required")
                            else "unscored_archive"
                        )
                    except (ValueError, RuntimeError, httpx.HTTPError) as error:
                        result["error"] = type(error).__name__
                        result["latency_seconds"] = time.perf_counter() - started
                    stop.set()
                    sampler.join()
                    result["peak_ollama_rss_kib"] = peak[0]
                    running = client.get("/api/ps").json().get("models", [])
                    result["resident_models"] = [
                        {
                            key: row.get(key)
                            for key in ("name", "size", "size_vram", "digest")
                        }
                        for row in running
                    ]
                    with Path(args.output).open("a") as output:
                        output.write(json.dumps(result, sort_keys=True) + "\n")
                    print(
                        model, case["name"], temperature, result["status"], flush=True
                    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=11534)
    parser.add_argument("--cases", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--models", nargs="+", default=MODELS)
    run(parser.parse_args())
