from __future__ import annotations

import argparse

from scentry import __version__


def main() -> None:
    parser = argparse.ArgumentParser(prog="scentry")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("web", help="serve the portal")
    sub.add_parser("worker", help="run queued and scheduled scans")
    sub.add_parser("hass-sync", help="follow what Home Assistant's Marketplace has installed")
    sub.add_parser("notify", help="send notifications about scan results")
    sub.add_parser("ai", help="answer requests for AI explanations (needs a model set up)")
    sub.add_parser("migrate", help="bring the database to the newest schema (every service "
                                   "also does this when it starts)")  # fmt: skip
    new = sub.add_parser("new-migration", help="development: write a migration for model "
                                               "changes")  # fmt: skip
    new.add_argument("message")
    args = parser.parse_args()

    if args.command == "migrate":
        from scentry import db
        from scentry.config import get_settings

        db.configure(get_settings().database_url)
    elif args.command == "new-migration":
        from scentry import db

        for path in db.new_revision(args.message):
            print(path)
    elif args.command == "web":
        import uvicorn

        from scentry.config import get_settings
        from scentry.web.app import create_app

        settings = get_settings()
        uvicorn.run(create_app(settings), host=settings.host, port=settings.port)
    elif args.command == "hass-sync":
        from scentry import hass_sync

        hass_sync.main()
    elif args.command == "notify":
        from scentry import notify

        notify.main()
    elif args.command == "ai":
        from scentry import ai

        ai.main()
    else:
        from scentry import worker

        worker.main()


if __name__ == "__main__":
    main()
