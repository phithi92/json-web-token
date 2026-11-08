#!/bin/bash

echo "🔍 Gestagte Änderungen anzeigen (bereit zum Commit):"
echo "------------------------------------------------------------"

# Prüfen, ob wir in einem Git-Repository sind
if ! git rev-parse --git-dir > /dev/null 2>&1; then
  echo "❌ Fehler: Dieses Verzeichnis ist kein Git-Repository."
  exit 1
fi

# Prüfen, ob überhaupt etwas gestaged ist
if git diff --cached --quiet; then
  echo "ℹ️  Es sind aktuell keine Änderungen gestaged."
  exit 0
fi

# Gestagte Änderungen ohne Pager anzeigen
GIT_PAGER=cat git diff --cached
