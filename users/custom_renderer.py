from rest_framework.renderers import JSONRenderer
import json


class CustomRenderer(JSONRenderer):
    """
    to render custom formatted response
    for success:
                {
                    success: True,
                    data : “your API result response. It can be any format as per your logic and
                            requirement. ”
                 }
    for error:
            {
                success: False,
                error: “Your API error in an exact single string”
            }

    """
    charset = 'utf-8'

    def render(self, data, accepted_media_type=None, renderer_context=None):
        if 'ErrorDetail' in str(data):
            field_errors = data.get('errors', None)
            non_field_errors = data.get('non_field_errors', None)
            if field_errors:
                # for non field errors
                response = json.dumps({'success': False, 'error': field_errors})
            if non_field_errors:
                response = json.dumps({'success': False, 'error': non_field_errors[0]})
            else:
                response = json.dumps({'success': False, 'error': data['detail']})
        else:
            response = json.dumps({'success': True, 'data': data})
        return response
