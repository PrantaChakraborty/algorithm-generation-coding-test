import logging

from rest_framework.views import exception_handler
from rest_framework.exceptions import APIException


logger = logging.getLogger(__name__)


class BaseCustomException(APIException):
    error = None

    def __init__(self, error_message):
        super().__init__(error_message)
        self.error = error_message


class CustomSerializerValidationError(BaseCustomException):

    def __init__(self, err_msg):
        super().__init__(err_msg)


class CustomAPIError(BaseCustomException):

    def __init__(self, err_msg):
        super().__init__(err_msg)


def custom_exception_handler(exc, context):
    """
    custom exception handler
    """
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)
    logger.info(f"{exc}")
    if response is not None:
        response.data['success'] = False
        response.data["error"] = str(exc.detail)
        del response.data['detail']
    return response

