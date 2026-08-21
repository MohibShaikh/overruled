"""`python -m mocks --agent reference --port 9101`"""

import argparse

from . import BrokenAgent, ReferenceAgent, serve

parser = argparse.ArgumentParser(prog="mocks")
parser.add_argument("--agent", choices=["reference", "broken"], required=True)
parser.add_argument("--port", type=int, default=9100)
args = parser.parse_args()

handler = ReferenceAgent if args.agent == "reference" else BrokenAgent
print(f"{args.agent} agent on :{args.port}", flush=True)
server = serve(handler, args.port)
try:
    __import__("threading").Event().wait()
except KeyboardInterrupt:
    server.shutdown()
