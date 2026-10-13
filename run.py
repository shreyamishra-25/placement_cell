"""Dev server:  python run.py [--https]   |   CLI:  flask --app run <command>

--https serves over an ad-hoc self-signed certificate (encryption in transit for demos).
For production put the app behind a TLS-terminating reverse proxy and a real WSGI server
(e.g. gunicorn -w 1) and set PLACEMENT_HTTPS=1 so cookies are Secure and HSTS is sent.
"""
import argparse
import os

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--https", action="store_true")
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()
    if args.https:
        os.environ["PLACEMENT_HTTPS"] = "1"

from app import create_app  # noqa: E402

app = create_app()

if __name__ == "__main__":
    # threaded=False: the audit hash chain assumes a single writer (see audit.py)
    app.run(host="127.0.0.1", port=args.port, debug=False, threaded=False,
            ssl_context="adhoc" if args.https else None)
