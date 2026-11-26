import json
from dataclasses import asdict, replace
from uuid import uuid4

import pytest
from argos.backend.knowledge import (
    ChunkConfig,
    Collection,
    CollectionKind,
    DocumentMetadata,
    DocumentRef,
    Freshness,
    KnowledgeRetriever,
    KnowledgeStore,
    LexicalWeights,
    Passage,
    RetrievalMethod,
    SearchFilters,
    Source,
    SQLiteKnowledgeRetriever,
    Tag,
)


@pytest.fixture
def scope(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGOS_DATA_HOME", str(tmp_path / "data"))
    collection = Collection(CollectionKind.MISSION, uuid4())
    store = KnowledgeStore(collection)
    store.initialize()
    for source in ("a", "b"):
        store.sources.register(Source(source, source.upper(), "notes:local", "Private"))
        store.sources.approve(source)
    return store, SQLiteKnowledgeRetriever(collection, allowed_collections={collection})


def _publish(store, slug, body, *, title="Guide", version=None, tags=(), source="a"):
    doc = DocumentRef(source, slug)
    metadata = DocumentMetadata(
        title, "text/markdown", f"notes:{slug}", declared_version=version, tags=tags
    )
    projection = store.ingest_bytes(doc, metadata, body.encode("utf-8"))
    store.approve_version(doc, projection.version.id)
    return projection


def test_lexical_terms_quotes_accents_and_scores(scope):
    store, search = scope
    v = _publish(store, "guide", "# Guide\n\nContrôle d’accès et X-Frame-Options.")
    _publish(store, "other", "contrôle du réseau et X Other Frame Options")
    engine: KnowledgeRetriever = search
    results = engine.retrieve('"controle d’accès" "X-Frame-Options"', limit=10)
    (result,) = results
    assert result.version_id == v.version.id and result.document.document_id == "guide"
    assert result.reference and search.resolve(result.reference).text == result.text
    assert (
        result.freshness is Freshness.CURRENT
        and result.method is RetrievalMethod.LEXICAL
    )
    assert result.score is not None and result.score > 0
    assert result.provenance and result.provenance.publisher == "A"
    assert result.citations[-1].line_start == 3
    assert result.citations[-1].headings == ("Guide",)
    assert len(engine.retrieve("réseau accès", limit=10)) == 2
    assert engine.retrieve("*)", limit=5) == ()
    assert engine.retrieve("title:guide", limit=5) == ()
    with pytest.raises(ValueError, match="Unclosed"):
        engine.retrieve('"missing', limit=5)


def test_lexical_weights_and_stable_ranking(scope):
    store, search = scope
    _publish(store, "alpha", "place", title="Café")
    _publish(store, "bravo", "café", title="Place")
    _publish(store, "charlie", "place", title="Café")
    assert [p.document.document_id for p in search.retrieve("cafe", limit=3)] == [
        "alpha",
        "charlie",
        "bravo",
    ]
    ref = search.retrieve("cafe", limit=1)[0].reference
    assert ref is not None
    body_first = SQLiteKnowledgeRetriever(
        ref.collection,
        allowed_collections={ref.collection},
        weights=LexicalWeights(1, 20),
    )
    assert body_first.retrieve("cafe", limit=1)[0].document.document_id == "bravo"
    search.rebuild_index()
    assert search.retrieve("cafe", limit=1)[0].reference == ref


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("cve-2024-0123", "references"),
        ("CVE-2024-012", None),
        ("CVE-2024-01234", None),
        ("CWE 79", "references"),
        ("CWE-7", None),
        ("RFC-9110", "references"),
        ("RFC 9110.1", None),
        ("ISO/IEC-27001:2022", "references"),
        ("ISO/IEC 27001", None),
        ("ISO/IEC 27001:2013", None),
        ("IEEE 802.1", None),
        ("IEEE-802.1", None),
        ("NIST SP 800-53 rev 5", "references"),
        ("NIST SP 800-53 Rev. 4", None),
        ("OWASP ASVS 4.0.3", "references"),
        ("OWASP ASVS 4.0", None),
        ("doc:a/references", "references"),
        ("doc:b/references", None),
        ("references", "references"),
        ("References", None),
    ],
)
def test_exact_preserves_identifier_family_version_and_slug_case(
    scope, value, expected
):
    store, search = scope
    _publish(
        store,
        "references",
        "CVE-2024-0123. CWE-79, RFC 9110, ISO/IEC 27001:2022, "
        "NIST SP 800-53 Rev. 5, OWASP ASVS v4.0.3.",
    )
    hits = search.exact(value, limit=10)
    assert [hit.document.document_id for hit in hits] == (
        [expected] if expected else []
    )
    assert all(hit.method is RetrievalMethod.EXACT for hit in hits)


def test_ambiguous_ref_priority_and_pre_limit_filters(scope):
    store, search = scope
    defense = Tag("domain", "defense")
    _publish(store, "rfc-9110", "Rules", source="a", tags=(defense,))
    _publish(
        store,
        "rfc-9110",
        "Different edition",
        source="b",
        version="2025",
        tags=(defense, Tag("topic", "http")),
    )
    _publish(store, "mention", "RFC 9110", source="a")
    assert [h.document for h in search.exact("rfc-9110", limit=10)] == [
        DocumentRef("a", "rfc-9110"),
        DocumentRef("b", "rfc-9110"),
        DocumentRef("a", "mention"),
    ]
    filters = SearchFilters(("b",), ("defense",), (Tag("topic", "http"),), "2025")
    assert (
        search.exact("RFC 9110", limit=1, filters=filters)[0].document.source_id == "b"
    )
    assert (
        search.retrieve("edition", limit=1, filters=filters)[0].document.source_id
        == "b"
    )
    assert not search.exact(
        "RFC 9110", limit=1, filters=replace(filters, declared_version="2024")
    )


def test_scope_budget_deduplication_and_revoked_citations(scope, tmp_path):
    store, search = scope
    v = _publish(
        store, "first", "active " + "a" * 1016 + "\n" + "active " + "a" * 1016 + "\n"
    )
    hits = search.retrieve("active", limit=10)
    (hit,) = hits
    assert len(hit.occurrences) == 1
    assert hit.reference is not None
    reference = hit.reference
    assert search.resolve(hit.occurrences[0]).text == hit.text
    other = Collection(CollectionKind.MISSION, uuid4())
    with pytest.raises(PermissionError):
        SQLiteKnowledgeRetriever(other, allowed_collections={reference.collection})
    assert not any(f"mission-{other.scope_id}" == p.name for p in tmp_path.rglob("*"))
    with pytest.raises(PermissionError):
        search.resolve(replace(reference, collection=other))
    assert search.retrieve("active", limit=1, max_bytes=2) == ()
    budget = len(json.dumps([asdict(replace(hit, occurrences=()))], default=str))
    limited = search.retrieve("active", limit=1, max_bytes=budget)
    assert len(json.dumps([asdict(p) for p in limited], default=str)) <= budget
    new_v = _publish(store, "first", "replacement")
    assert new_v.version.id != v.version.id
    with pytest.raises(KeyError):
        search.resolve(reference)
    assert search.retrieve("active", limit=10) == ()
    store.sources.withdraw("a")
    assert search.retrieve("replacement", limit=10) == ()
    assert search.index_status().indexed_fragments == 0


def test_bounds_and_legacy_passage_constructor(scope):
    _, search = scope
    assert Passage(DocumentRef("a", "b"), "legacy", "x", "text").score is None
    for options in ({"limit": 0}, {"max_bytes": 1}, {"limit": 101}):
        with pytest.raises(ValueError):
            search.retrieve("foo", **({"limit": 1} | options))
    for query in ("word " * 33, "a" * 1025, "word\nword"):
        with pytest.raises(ValueError):
            search.retrieve(query, limit=10)


def test_disallowed_collections_never_contribute_to_scores_or_counts(scope):
    store, search = scope
    _publish(store, "public", "frequent authorized")
    before = search.retrieve("frequent", limit=10)
    stats = search.index_status()
    denied = Collection(CollectionKind.MISSION, uuid4())
    private = KnowledgeStore(denied)
    private.initialize()
    private.sources.register(Source("a", "Private", "notes:private", "Private"))
    private.sources.approve("a")
    _publish(private, "hidden", "frequent hidden CVE-2024-9999")
    assert search.retrieve("frequent", limit=10) == before
    assert search.index_status() == stats
    assert not search.retrieve("hidden", limit=10)
    assert not search.exact("CVE-2024-9999", limit=10)


def test_exact_keeps_standard_parts_and_revision_suffixes(scope):
    store, search = scope
    _publish(store, "standards", "IEEE 802.1X-2020 and NIST SP 800-63B-4")
    assert search.exact("ieee-802.1x-2020", limit=1)
    assert search.exact("NIST SP 800-63B-4", limit=1)
    assert not search.exact("IEEE 802.1X", limit=1)
    assert not search.exact("NIST SP 800-63", limit=1)


def test_revoked_collection_grant_is_checked_before_any_storage_access(scope):
    store, search = scope
    _publish(store, "guide", "approved content")
    ref = search.retrieve("content", limit=1)[0].reference
    assert ref is not None
    allowed = {ref.collection}
    scoped = SQLiteKnowledgeRetriever(ref.collection, allowed_collections=allowed)
    assert scoped.resolve(ref).text == "approved content"
    allowed.clear()
    for action in (
        lambda: scoped.resolve(ref),
        lambda: scoped.retrieve("content", limit=1),
        lambda: scoped.exact("doc:guide", limit=1),
        scoped.index_status,
        scoped.verify_index,
        scoped.rebuild_index,
    ):
        with pytest.raises(PermissionError, match="authorized scope"):
            action()


def test_chunk_boundary_does_not_create_a_false_exact_prefix(scope):
    store, search = scope
    ref = DocumentRef("a", "boundary")
    metadata = DocumentMetadata("References", "text/plain", "fixture:boundary")
    original = b" " * (64 - len(b"CVE-2024-1234")) + b"CVE-2024-12345"
    fixed = store.ingest_bytes(ref, metadata, original, ChunkConfig(size=64))
    store.approve_version(ref, fixed.version.id)
    assert not search.exact("CVE-2024-1234", limit=10)
    assert not search.exact("CVE-2024-12345", limit=10)
    store.ingest_bytes(ref, metadata, original)
    assert search.exact("CVE-2024-12345", limit=10)
    assert not search.exact("CVE-2024-1234", limit=10)
