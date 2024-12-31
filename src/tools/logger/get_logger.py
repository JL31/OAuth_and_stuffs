"""
    Module to define and configure a logger
"""

# Standard libraries
from logging import Formatter, LogRecord, StreamHandler, Logger, getLogger, DEBUG
from sys import stdout


class CustomFormatter(Formatter):
    """ Class to define a custom formatter """

    def format(self, record: LogRecord):
        """ Override of the format method to customize it """

        format_string = "[%(levelname)s] %(name)s - %(message)s"
        local_formatter = Formatter(format_string)

        return local_formatter.format(record)


# Logger configuration
log_handler = StreamHandler(stdout)
formatter = CustomFormatter()
log_handler.setFormatter(formatter)


def get_logger(logger_name: str) -> Logger:
    """ Function to define and configure a logger """

    defined_logger: Logger = getLogger(logger_name)

    if defined_logger.handlers:
        for handler in defined_logger.handlers:
            defined_logger.removeHandler(handler)

    defined_logger.setLevel(DEBUG)
    defined_logger.addHandler(log_handler)
    defined_logger.propagate = False

    return defined_logger
