import logging

from src.utils.helpers import setup_logger


def test_setup_logger_is_idempotent(tmp_path):
    logger_name = "aegis.test.logger"
    log_file = tmp_path / "test.log"
    logger = logging.getLogger(logger_name)

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    try:
        first = setup_logger(logger_name, log_file=str(log_file))
        second = setup_logger(logger_name, log_file=str(log_file))

        assert first is second
        assert len(second.handlers) == 2
        assert len({id(handler) for handler in second.handlers}) == 2
    finally:
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()
