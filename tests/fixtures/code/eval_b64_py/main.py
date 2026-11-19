# Inert fixture: the decoded string is print(1).
import base64

exec(base64.b64decode("cHJpbnQoMSk="))
