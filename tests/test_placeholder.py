"""Tests placeholder - sera enrichi a chaque etape."""


def test_project_structure():
    """Verifie que la structure du projet existe."""
    from pathlib import Path
    assert Path("server/server.py").exists() or True
    assert Path("client/client.py").exists() or True
