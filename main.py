import logging
import sys

from src.restapi import app


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

    logging.info("Starting Rest API server")
    app.run(debug=True)


if __name__ == '__main__':
    """
         This is the entrypoint for our application.
    """
    init_logger()
    main()
