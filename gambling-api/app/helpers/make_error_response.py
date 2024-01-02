def make_error_response(value, key="__all__"):
    return {
        "error": {
            key: value
        }
    }
