"""`python -m awstorage` -- the same CLI, for a box where the console script is not
on PATH (a fresh venv, a scheduler with a bare environment, the self-test)."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
