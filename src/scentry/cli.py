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
    reset = sub.add_parser("reset-password", help="set a new admin password when it's "
                                                  "forgotten (run it in the web container)")
    how = reset.add_mutually_exclusive_group()
    how.add_argument("--generate", action="store_true",
                     help="make up a strong one and show it once")  # fmt: skip
    how.add_argument("--use-env", action="store_true",
                     help="forget the one set in the portal: SCENTRY_ADMIN_PASSWORD signs "
                          "in again")  # fmt: skip
    new = sub.add_parser("new-migration", help="development: write a migration for model "
                                               "changes")  # fmt: skip
    new.add_argument("message")
    bench = sub.add_parser("bench", add_help=False,  # its own --help: scentry bench --help
                           help="development: a benchmark of findings labelled by hand")
    bench.add_argument("args", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    if args.command == "bench":
        from scentry import bench as benchmark

        benchmark.main(args.args)
    elif args.command == "reset-password":
        import sys

        from scentry import passwords

        sys.exit(passwords.reset(generate=args.generate, use_env=args.use_env))
    elif args.command == "migrate":
        from scentry import db
        from scentry.config import get_settings

        db.configure(get_settings().database_url)
    elif args.command == "new-migration":
        from scentry import db

        for path in db.new_revision(args.message):
            print(path)
    elif args.command == "web":
        import logging

        import uvicorn

        from scentry import logs
        from scentry.config import get_settings
        from scentry.web.app import create_app

        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
        settings = get_settings()
        app = create_app(settings)
        logs.install("web", settings, prune_old=True)
        # Uvicorn's messages go through the same logging as everything else (log_config
        # None): its errors reach the Log page, and the console looks like the others'.
        uvicorn.run(app, host=settings.host, port=settings.port, log_config=None)
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
