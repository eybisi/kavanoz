from itertools import cycle
from loguru import logger
import logging
import sys
import re
from typing import cast


def xor(var: bytes, key: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(var, cycle(key)))


dex_headers = [
    b"dex\n035\x00",
    b"dex\n036\x00",
    b"dex\n037\x00",
    b"dex\n038\x00",
    b"dex\n039\x00",
    b"dey\n035\x00",
    b"dey\n036\x00",
    b"dey\n037\x00",
    b"dey\n038\x00",
]

pkzip_headers = [
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
]

zlib_headers = [
    b"\x78\x01",
    b"\x78\x9c",
    b"\x78\x5e",
    b"\x78\xda",
    b"\x78\x20",
    b"\x78\x7d",
    b"\x78\xbb",
    b"\x78\xf9",
]


class MyFilter:
    def __init__(self, level):
        self.level = level

    def __call__(self, record):
        levelno = logger.level(self.level).no
        return record["level"].no >= levelno


def set_log(level):
    """
    Sets the log for loguru based on the level being passed.
    The possible values are TRACE, DEBUG, INFO, SUCCESS, WARNING, ERROR, CRITICAL
    """
    logger.remove(0)
    my_filter = MyFilter(level)
    logger.add(sys.stderr, filter=my_filter, level=0)


def unescape_unicode(str):
    codepoint = re.compile(r"(\\u[0-9a-fA-F]{4})")

    def replace(match):
        return chr(int(match.group(1)[2:], 16))

    return codepoint.sub(replace, str)


class InterceptHandler(logging.Handler):
    # def emit(self, record):
    # # Get corresponding Loguru level if it exists.
    # try:
    # level = logger.level(record.levelname).name
    # except ValueError:
    # level = record.levelno

    # # Find caller from where originated the logged message.
    # frame, depth = sys._getframe(6), 6
    # while frame and frame.f_code.co_filename == logging.__file__:
    # frame = frame.f_back
    # depth += 1

    # logger.opt(depth=depth, exception=record.exc_info).log(
    # level, record.getMessage()
    # )
    def emit(self, record: logging.LogRecord) -> None:
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = str(record.levelno)

        frame, depth = logging.currentframe(), 2
        while frame.f_code.co_filename == logging.__file__:  # noqa: WPS609
            frame = cast(FrameType, frame.f_back)
            depth += 1
        logger_with_opts = logger.opt(depth=depth, exception=record.exc_info)
        try:
            logger_with_opts.log(level, "{}", record.getMessage())
        except Exception as e:
            safe_msg = getattr(record, "msg", None) or str(record)
            logger_with_opts.warning(
                "Exception logging the following native logger message: {}, {!r}",
                safe_msg,
                e,
            )
