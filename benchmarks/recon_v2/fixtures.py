"""Bénignes, en lecture seule. Aucune écoute réseau à l'import."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from wsgiref.types import StartResponse, WSGIEnvironment

Response = tuple[str, str, str]
HTML = "text/html; charset=utf-8"
JSON = "application/json"
JS = "application/javascript"

PORTAL = {
    "/": ("200 OK", HTML, '<a href="/guide/">Guide</a>'),
    "/guide/": ("200 OK", HTML, '<a href="intro">Introduction</a>'),
    "/guide/intro": ("200 OK", HTML, "<h1>Introduction</h1>"),
    "/members": ("401 Unauthorized", HTML, "<h1>Connexion requise</h1>"),
}

SHELL = ("200 OK", HTML, '<main id="app"></main><script src="/app.js"></script>')
SPA = {
    "/": SHELL,
    "/app.js": (
        "200 OK",
        JS,
        """fetch('/api/cards').then(r => r.json()).then(cards => {
  const a = document.createElement('a');
  a.textContent = cards[0].title;
  a.href = cards[0].url;
  document.querySelector('#app').append(a);
});""",
    ),
    "/api/cards": (
        "200 OK",
        JSON,
        '[{"title":"Carte","url":"/cards/blue"}]',
    ),
    "/cards/blue": ("200 OK", HTML, "<h1>Carte bleue</h1>"),
}

API = {
    "/": ("200 OK", HTML, '<a href="/openapi.json">Contrat</a>'),
    "/openapi.json": (
        "200 OK",
        JSON,
        '{"openapi":"3.0.3","info":{"title":"Catalogue","version":"1"},'
        '"paths":{"/v1/books":{"get":{"responses":{"200":{"description":"Liste"}}}}}}',
    ),
    "/v1/books": ("200 OK", JSON, '[{"title":"Atlas"}]'),
    "/v1/profile": ("401 Unauthorized", JSON, '{"message":"Connexion requise"}'),
}


def _application(
    routes: dict[str, Response], missing: Response
) -> Callable[[WSGIEnvironment, StartResponse], Iterable[bytes]]:
    def serve(environ: WSGIEnvironment, start: StartResponse) -> Iterable[bytes]:
        method = environ["REQUEST_METHOD"]
        if method in {"GET", "HEAD"}:
            status, content_type, body = routes.get(environ["PATH_INFO"], missing)
        else:
            status, content_type, body = "405 Method Not Allowed", HTML, ""
        headers = [("Content-Type", content_type)]
        if status.startswith("401"):
            headers.append(("WWW-Authenticate", 'Basic realm="fixture"'))
        if status.startswith("405"):
            headers.append(("Allow", "GET, HEAD"))
        start(status, headers)
        return [b"" if method == "HEAD" else body.encode()]

    return serve


NOT_FOUND = ("404 Not Found", HTML, "<h1>Absent</h1>")
portal = _application(PORTAL, NOT_FOUND)
spa = _application(SPA, SHELL)
api = _application(API, ("404 Not Found", JSON, '{"message":"Absent"}'))
