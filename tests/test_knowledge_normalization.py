import json
import os
from pathlib import Path

import pytest
from argos.backend.knowledge import normalization
from argos.backend.knowledge.chunking import (
    ChunkConfig,
    ChunkStrategy,
    chunk,
    citations,
)
from argos.backend.knowledge.loader import load_file
from argos.backend.knowledge.normalization import normalize


def test_markdown_preserves_source_and_inert_structure():
    raw = (
        "---\ntitle: Fixture\n---\n\n# First\n\nA paragraph.\n\n"
        "- one\n- two\n\n~~~md\n# Literal\n\n~~~\n\nSecond\n------\n"
        "![[private]] [external](https://example.invalid)\n"
    )
    original = b"\xef\xbb\xbf" + raw.replace("\n", "\r\n").encode()
    doc = normalize(original, "text/markdown")
    assert doc.text == raw
    assert [b.kind for b in doc.blocks] == [
        "frontmatter",
        "heading",
        "paragraph",
        "list",
        "code",
        "heading",
        "paragraph",
    ]
    code = doc.blocks[4]
    assert doc.text[code.start : code.end] == "~~~md\n# Literal\n\n~~~"
    assert doc.blocks[-1].headings == ("First", "Second")
    assert citations(doc, code.start + 6, code.end)[0].line_start == 13


def test_plain_text_does_not_parse_markdown():
    doc = normalize(b"# plain\r\nhello\rworld\n\nend", "text/plain")
    assert doc.text == "# plain\nhello\nworld\n\nend"
    assert [(b.kind, b.line) for b in doc.blocks] == [
        ("paragraph", 1),
        ("paragraph", 5),
    ]


def test_json_pointer_and_lossless_numbers():
    raw = b'{"x/y~z":[1e999,{"":true},[]],"z":null,"a":{}}'
    doc = normalize(raw, "application/json")
    assert [b.pointer for b in doc.blocks] == [
        "",
        "/a",
        "/x~1y~0z",
        "/x~1y~0z/0",
        "/x~1y~0z/1",
        "/x~1y~0z/1/",
        "/x~1y~0z/2",
        "/z",
    ]
    assert '"/x~1y~0z/0" = 1e999' in doc.text
    assert normalize(b"42", "application/json").blocks[0].pointer == ""
    assert (
        normalize(
            json.dumps(json.loads(raw.replace(b"1e999", b"1"))).encode(),
            "application/json",
        ).blocks
        == normalize(raw.replace(b"1e999", b"1"), "application/json").blocks
    )


def test_json_keeps_container_types_even_with_identical_leaf_pointers():
    mapping = normalize(b'{"0":"x"}', "application/json")
    array = normalize(b'["x"]', "application/json")
    assert mapping.blocks[0].kind == "object"
    assert array.blocks[0].kind == "array"
    assert mapping.blocks[1].pointer == array.blocks[1].pointer == "/0"
    assert mapping.encode() != array.encode()


@pytest.mark.parametrize(
    ("raw", "media"),
    [
        (b"\xff", "text/plain"),
        (b"\x00", "text/plain"),
        (b" \n", "text/plain"),
        (b"```\nfoo", "text/markdown"),
        (b'{"x":1,"x":2}', "application/json"),
        (b"[NaN]", "application/json"),
        (b'"\\ud800"', "application/json"),
        (b"This is text", "application/json"),
        (b'["unfinished]', "application/json"),
        (b"[" * 49 + b"0" + b"]" * 49, "application/json"),
        (b"1" * 257, "application/json"),
        (b"a" * 65_537, "text/plain"),
    ],
)
def test_bad_documents(raw, media):
    with pytest.raises(ValueError):
        normalize(raw, media)


def test_complexity_bounds(monkeypatch):
    monkeypatch.setattr(normalization, "MAX_BLOCKS", 2)
    with pytest.raises(ValueError, match="block"):
        normalize(b"a\n\nb\n\nc", "text/plain")
    with pytest.raises(ValueError, match="complexity|limits"):
        normalize(b"[1,2,3]", "application/json")
    monkeypatch.setattr(normalization, "MAX_LINES", 2)
    with pytest.raises(ValueError, match="line"):
        normalize(b"a\nb\nc", "text/plain")


def test_loader_explicit_regular_file_only(tmp_path, monkeypatch):
    file = tmp_path / "note.MD"
    file.write_bytes(b"# Note")
    monkeypatch.chdir(tmp_path)
    assert load_file(Path(file.name)) == ("text/markdown", b"# Note")
    link = tmp_path / "link.md"
    link.symlink_to(file)
    with pytest.raises(ValueError, match="regular"):
        load_file(link)
    fifo = tmp_path / "fifo.txt"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="regular"):
        load_file(fifo)
    folder = tmp_path / "dir"
    folder.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(folder, target_is_directory=True)
    (folder / "note.md").touch()
    with pytest.raises(OSError):
        load_file(alias / "note.md")
    with pytest.raises(ValueError, match="path"):
        load_file(folder / ".." / file.name)
    with pytest.raises(ValueError, match="extension"):
        load_file(tmp_path / "note.pdf")
    file.write_bytes(b"")
    with pytest.raises(ValueError, match="bounded"):
        load_file(file)


@pytest.mark.parametrize("strategy", list(ChunkStrategy))
def test_chunks_reproduce_offsets_citations_and_respect_bounds(strategy):
    raw = "# Alpha\n\n" + "une phrase. " * 20 + "\nmore\n\n## Beta\n\nend"
    doc = normalize(raw.encode(), "text/markdown")
    config = ChunkConfig(strategy, 64, 8)
    spans = tuple(chunk(doc, config))
    assert spans == tuple(chunk(doc, config))
    assert spans[0].start == 0
    assert spans[-1].end == len(doc.text)
    for previous, span in zip(spans, spans[1:], strict=False):
        assert previous.end - span.start in (0, 8)
        assert 0 < span.end - span.start <= 64
        for citation in citations(doc, span.start, span.end):
            assert citation.line_start and citation.line_end
            assert citation.line_start <= citation.line_end
    if strategy is not ChunkStrategy.FIXED:
        assert spans[-1].start == doc.blocks[-2].start
        assert citations(doc, spans[-1].start, spans[-1].end)[-1].headings == (
            "Alpha",
            "Beta",
        )
    assert config.identity.startswith("chunk-v1:")


def test_chunk_strategy_boundaries_and_limits(monkeypatch):
    doc = normalize(("a " * 120).encode(), "text/plain")
    assert next(chunk(doc, ChunkConfig(ChunkStrategy.STRUCTURAL, 65))).end == 65
    assert next(chunk(doc, ChunkConfig(ChunkStrategy.RECURSIVE, 65))).end == 64
    for size, overlap in [(63, 0), (64, 17), (64, -1), (16_385, 0)]:
        with pytest.raises(ValueError):
            ChunkConfig(size=size, overlap=overlap)
    monkeypatch.setattr("argos.backend.knowledge.chunking.MAX_FRAGMENTS", 1)
    with pytest.raises(ValueError, match="window"):
        tuple(chunk(doc, ChunkConfig(size=64)))
