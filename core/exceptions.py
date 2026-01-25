from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status


def custom_exception_handler(exc, context):
    """
    Custom exception handler for the API
    """
    # Call REST framework's default exception handler first
    response = exception_handler(exc, context)

    # If the exception was handled by the default handler, return it
    if response is not None:
        return response

    # Handle unexpected exceptions
    if isinstance(exc, Exception):
        # Log the exception for debugging
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Unhandled exception: {exc}", exc_info=True)

        # Return a generic error response
        data = {
            'error': 'An unexpected error occurred.',
            'detail': str(exc) if str(exc) else 'Internal server error'
        }
        return Response(data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # If we don't handle the exception, return None to let DRF handle it
    return None