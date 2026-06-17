"""
sift — entry point for `python sift.py`.

The implementation lives in the sift/ package.  Running this script is
equivalent to `python -m sift` or `python cli.py serve`.
"""
from sift.server import main

if __name__ == "__main__":
    main()
