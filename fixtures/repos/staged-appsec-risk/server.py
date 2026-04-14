import pickle
import requests
import subprocess


def handle_request(request):
    subprocess.run(request.args["cmd"], shell=True)
    requests.get(request.args["url"])
    open(request.args["path"]).read()
    pickle.loads(request.data)
