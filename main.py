import json
import logging
import os
import sys
from datetime import timedelta

from gevent.pywsgi import WSGIServer

from src.app import app


def init_logger():
    """
        This method is to initialize the logger.
    """
    logging.basicConfig(
        stream=sys.stdout,
        format="%(asctime)s %(levelname)-8s %(message)s",
        level="INFO",
        datefmt="%Y-%m-%d %H:%M:%S"
    )


def main():
    """
         We load the environment variables into our application context.
         Once loaded, the application is started on port 5000.
    """

    app.config['CORS_HEADERS'] = 'Content-Type'
    app.config['JWT_SECRET_KEY'] = 'dummy_secret'
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
    app.config['MONGO_CREDS'] = json.loads(os.environ['MONGO_CREDS'])

    logging.info("Starting Rest API server")
    http_server = WSGIServer(("0.0.0.0", 5000), app)
    http_server.serve_forever()


if __name__ == '__main__':
    """
         This is the entrypoint for our application.
    """
    init_logger()
    main()
