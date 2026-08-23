import os
import sys

# Make the repository root (where app.py lives) importable regardless of the
# directory pytest is invoked from.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
