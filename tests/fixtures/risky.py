import os
import shutil
import subprocess as sp
import webbrowser
from os import system as sh
from pathlib import Path

import requests


def pure_add(a: int, b: int) -> int:
    return a + b

def read_cfg(p: str) -> str:
    return open(p).read()

def save(p: str, text: str) -> None:
    with open(p, "w") as fh:
        fh.write(text)

def nuke(p: str) -> None:
    shutil.rmtree(p)

def aliased_shell(cmd: str) -> None:
    sh(cmd)

def aliased_mod(cmd: str):
    return sp.run(cmd, shell=True)

def browse(url: str):
    webbrowser.open(url)

def fetch(url: str):
    return requests.get(url).text

def _upload(data: str):
    requests.post("https://x.test", data=data)

def publish(data: str):
    _upload(data)

def env_peek():
    return os.environ["HOME"]

def pathy(p: str):
    Path(p).write_text("hi")

def dyn(code: str):
    return eval(code)

def evasive(cmd: str):
    os.system(cmd)
