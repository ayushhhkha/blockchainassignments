import asyncio
import logging
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.community import Community
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload import Payload
from ipv8_service import IPv8

EMAIL = "ayushkhadka@student.tudelft.nl"
GITHUB_URL = "https://github.com/ayushhhkha/blockchainassignments"
NONCE = 225133810
SERVER_PUBLIC_KEY = bytes.fromhex("4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb")

class SubmissionPayload(Payload):
    msg_id = 1
    format_list = ["varlenHutf8", "varlenHutf8", "q"]

    def __init__(self, email: str, github_url: str, nonce: int):
        super().__init__()
        self.email = email
        self.github_url = github_url
        self.nonce = nonce

    def to_pack_list(self):
        return [("varlenHutf8", self.email),("varlenHutf8", self.github_url),("q", self.nonce)]

    @classmethod
    def from_unpack_list(cls, email, github_url, nonce):
        return cls(email, github_url, nonce)

class ResponsePayload(Payload):
    msg_id = 2
    format_list = ["?", "varlenHutf8"]

    def __init__(self, success: bool, message: str):
        super().__init__()
        self.success = success
        self.message = message

    def to_pack_list(self):
        return [("?", self.success), ("varlenHutf8", self.message)]

    @classmethod
    def from_unpack_list(cls, success, message):
        return cls(success, message)

class PowCommunity(Community):
    community_id = bytes.fromhex("2c1cc6e35ff484f99ebdfb6108477783c0102881")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_message_handler(ResponsePayload.msg_id, self.on_response)
        self.done = asyncio.Event()

    def find_server(self):
        for peer in self.get_peers():
            if peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
                return peer
        return None

    @lazy_wrapper(ResponsePayload)
    def on_response(self, peer, payload):
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY:
            return
        
        print(f"\n This is the response provided by da server =")
        print(f"Success : {payload.success}")
        print(f"Message : {payload.message}")
        self.done.set()


async def main():
    logging.basicConfig(level=logging.WARNING) 

    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("my peer", "curve25519", "my_peer.key")
    builder.add_overlay( "PowCommunity","my peer", [WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})],default_bootstrap_defs,{},[],)

    ipv8 = IPv8(builder.finalize(), extra_communities={"PowCommunity": PowCommunity})
    await ipv8.start()

    community = ipv8.overlays[0]
    print("IPv8 started.")

    server = None
    for attempt in range(60):
        server = community.find_server()
        if server:
            break
        # total_peers = len(community.get_peers())
        # print(f"{attempt * 2:3d} in secs and {total_peers} ")
        await asyncio.sleep(2)

    if server is None:
        print("i think issue is that server is not running or not reachable so 500.")
        await ipv8.stop()
        return

    print(f" Thse are sent +  email={EMAIL}  nonce={NONCE}")
    community.ez_send(server, SubmissionPayload(EMAIL, GITHUB_URL, NONCE))

    for retry in range(6):          
        try:
            await asyncio.wait_for(community.done.wait(), timeout=5)
            break                 
        except asyncio.TimeoutError:
            if retry < 5:
                community.ez_send(server, SubmissionPayload(EMAIL, GITHUB_URL, NONCE))
    await ipv8.stop()


asyncio.run(main())

