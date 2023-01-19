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
            response = json.dumps({'success': False, 'error': data['detail']})
        else:
            response = json.dumps({'success': True, 'data': data})
        return response
