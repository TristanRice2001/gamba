import functools
from flask import jsonify, request
from marshmallow import ValidationError


def marshal_request(request_schema, request_dto):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            try:
                json_data = request.json

                data_dict = request_schema().load(json_data)
            except ValidationError as err:
                return jsonify({"error": err.messages_dict})

            dto = request_dto(**data_dict)
            return fn(dto, *args, **kwargs)
        return wrapped
    return decorator
