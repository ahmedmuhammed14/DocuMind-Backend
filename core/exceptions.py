from rest_framework.views import exception_handler
from rest_framework.exceptions import APIException
from rest_framework import status


class DocuMindAPIException(APIException):
    """
    Base exception for DocuMind API
    """
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'An error occurred'
    default_code = 'error'
    
    def __init__(self, detail=None, code=None, status_code=None):
        if status_code is not None:
            self.status_code = status_code
        super().__init__(detail=detail, code=code)


class StorageLimitExceeded(DocuMindAPIException):
    """
    Exception raised when user exceeds storage limit
    """
    status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    default_detail = 'Storage limit exceeded'
    default_code = 'storage_limit_exceeded'


class InvalidFileType(DocuMindAPIException):
    """
    Exception raised for invalid file types
    """
    status_code = status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
    default_detail = 'Invalid file type'
    default_code = 'invalid_file_type'


class ResourceNotFound(DocuMindAPIException):
    """
    Exception raised when resource is not found
    """
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = 'Resource not found'
    default_code = 'not_found'


class PermissionDenied(DocuMindAPIException):
    """
    Exception raised when user doesn't have permission
    """
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = 'Permission denied'
    default_code = 'permission_denied'


def custom_exception_handler(exc, context):
    """
    Custom exception handler for API
    """
    # Call REST framework's default exception handler first
    response = exception_handler(exc, context)
    
    if response is not None:
        # Customize the response data
        if isinstance(exc, DocuMindAPIException):
            response.data = {
                'error': {
                    'code': exc.default_code,
                    'message': exc.detail,
                    'status_code': exc.status_code
                }
            }
        else:
            response.data = {
                'error': {
                    'code': 'error',
                    'message': str(exc.detail) if hasattr(exc, 'detail') else str(exc),
                    'status_code': response.status_code
                }
            }
    
    return response