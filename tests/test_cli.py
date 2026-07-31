"""Smoke test: CLI version + help."""

from typer.testing import CliRunner

from mactail import __version__
from mactail.cli.app import app


def test_version() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_help() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "baseline" in result.stdout
    assert "diff" in result.stdout
    assert "show" in result.stdout
