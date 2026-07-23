from __future__ import annotations

import argparse


def main() -> None:
    parser = argparse.ArgumentParser(prog="tracefence")
    parser.add_argument("command", choices=["api"])
    args = parser.parse_args()
    if args.command == "api":
        import uvicorn

        uvicorn.run("tracefence.api.main:app", host="127.0.0.1", port=9000, reload=False)
