import logging
from logging.handlers import TimedRotatingFileHandler


class Logger:
    def getLogger(self):
        # Initialize logger
        logger = logging.getLogger("my_logger")
        logger.setLevel(logging.INFO)  # Set default log level to INFO
 
        # Define log formatter
        logFormatter = logging.Formatter("%(asctime)s,%(levelname)s,%(message)s")
 
        # Configure file handler
        fileHandler = TimedRotatingFileHandler("renote_logins_logs", when='midnight', interval=1, backupCount=90)
        fileHandler.setFormatter(logFormatter)
        fileHandler.setLevel(logging.INFO)  # Set file handler log level to ERROR
 
        # Add file handler to logger
        logger.addHandler(fileHandler)
 
        return logger
 
logger=Logger()
 
logger_instance=logger.getLogger()