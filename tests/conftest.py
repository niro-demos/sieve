import sys
from pathlib import Path

# app.py lives at the repo root, not inside a package — put the root on
# sys.path so `import app` works regardless of where pytest is invoked from.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
