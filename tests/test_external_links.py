from pathlib import Path

import pytest
from jinja2 import Environment, FileSystemLoader
from pydantic import ValidationError

from inform.core.config import ExternalLink, Settings, WebSettings

ROOT = Path(__file__).resolve().parents[1]


def test_external_links_default_empty():
    assert WebSettings().external_links == []


def test_external_links_strip_name_and_url():
    settings = Settings(
        security={"secret_key": "test-secret"},
        web={
            "external_links": [
                {"name": " Tickets ", "url": " https://tickets.example.com/a "}
            ]
        },
    )
    link = settings.web.external_links[0]
    assert link.name == "Tickets"
    assert link.url == "https://tickets.example.com/a"


@pytest.mark.parametrize(
    "url",
    ["javascript:alert(1)", "ftp://files.example.com/a", "/relative", "notes", ""],
)
def test_external_links_reject_non_http(url):
    with pytest.raises(ValidationError):
        WebSettings(external_links=[{"name": "Bad", "url": url}])


def test_external_links_reject_blank_name():
    with pytest.raises(ValidationError):
        WebSettings(external_links=[{"name": "   ", "url": "https://example.com"}])


def _render_nav(links):
    env = Environment(
        loader=FileSystemLoader(ROOT / "web" / "templates"),
        autoescape=True,
    )
    env.globals["app_version"] = "test"
    env.globals["external_links"] = links

    class URL:
        path = "/"

    class Request:
        url = URL()

    return env.get_template("base.html").render(request=Request())


def test_navbar_hides_menu_when_unconfigured():
    html = _render_nav([])
    assert "External Links" not in html
    assert "github.com" not in html


def test_navbar_renders_configured_links():
    html = _render_nav([ExternalLink(name="Tickets", url="https://tickets.example.com")])
    assert "External Links" in html
    assert 'href="https://tickets.example.com"' in html
    assert "Tickets" in html
    assert 'target="_blank"' in html
    assert 'rel="noopener noreferrer"' in html


def test_navbar_escapes_link_text():
    html = _render_nav([ExternalLink(name="<b>", url="https://example.com/?q=a&b=1")])
    assert "<b>" not in html
    assert "&lt;b&gt;" in html
    assert "q=a&amp;b=1" in html
