import json


def handle(request: str) -> str:
    data = json.loads(request)
    return json.dumps({"echo": data})
