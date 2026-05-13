import asyncio
import logging
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.community import Community
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload import Payload
from ipv8_service import IPv8
from cryptography.exceptions import UnsupportedAlgorithm

EMAIL = "ayushkhadka@student.tudelft.nl"
GITHUB_URL = "https://github.com/ayushhhkha/blockchainassignments"
NONCE = 225133810
SERVER_PUBLIC_KEY = bytes.fromhex("4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96")

MEMBER_KEYS_PUB = [
    "4c69624e61434c504b3a6d5bfd59dca2173b63898fdb38e4cc7cb34332695b419dca3ebc710de1b02e37bc2d2fb858a840cc8b876e33ffbfe6ae27894e928640817e08763906ada69c64",
    "4c69624e61434c504b3a4924a5ac3d83e3128007c5a349dcbda9396f45fc0331f4cd84cf5b7ec3f7b20339cafc465a0f36ddb65c4295953d01327921d7ab4ea5a7e69dcb5e16b96e0ca3",
    "4c69624e61434c504b3a9063db4576026f2d41d5632e1be3d8f3d9acdea4e0f2676ef3bef35d4232d260a9c8cabef50ed898a2d0deb739982255f6c698996112ecef2350f945cae3d60a",
]
MEMBER_KEYS = [bytes.fromhex(h) for h in MEMBER_KEYS_PUB]
GROUP_ID = ""

class IgnoreUnsupportedCurve(logging.Filter):
    def filter(self, record):
        # Only target this logger
        if record.name != "TuDelftBlockchainLab2Community":
            return True

        if not record.exc_info:
            return True

        exc_type, exc, _ = record.exc_info

        # Suppress only this exact exception
        if (
            issubclass(exc_type, UnsupportedAlgorithm)
            # and "Curve 1.3.132.0.1 is not supported" in str(exc)
        ):
            return False

        return True


logger = logging.getLogger("TuDelftBlockchainLab2Community")
logger.addFilter(IgnoreUnsupportedCurve())

class RegisterPayload(Payload):
    msg_id = 1
    format_list = ["varlenH", "varlenH", "varlenH"]

    def __init__(self, member1_key: bytes, member2_key: bytes, member3_key: bytes):
        super().__init__()
        self.member1_key = member1_key
        self.member2_key = member2_key
        self.member3_key = member3_key

    def to_pack_list(self):
        return [("varlenH", self.member1_key), ("varlenH", self.member2_key), ("varlenH", self.member3_key)]

    @classmethod
    def from_unpack_list(cls, m1, m2, m3):
        return cls(m1, m2, m3)


class RegisterResponsePayload(Payload):
    msg_id = 2
    format_list = ["?", "varlenHutf8", "varlenHutf8"]

    def __init__(self, success: bool, group_id: str, message: str):
        super().__init__()
        self.success = success
        self.group_id = group_id
        self.message = message

    def to_pack_list(self):
        return [("?", self.success), ("varlenHutf8", self.group_id), ("varlenHutf8", self.message)]

    @classmethod
    def from_unpack_list(cls, success, group_id, message):
        return cls(success, group_id, message)


class ChallengeRequestPayload(Payload):
    msg_id = 3
    format_list = ["varlenHutf8"]

    def __init__(self, group_id: str):
        super().__init__()
        self.group_id = group_id

    def to_pack_list(self):
        return [("varlenHutf8", self.group_id)]

    @classmethod
    def from_unpack_list(cls, group_id):
        return cls(group_id)


class ChallengeResponsePayload(Payload):
    msg_id = 4
    format_list = ["varlenH", "q", "d"]

    def __init__(self, nonce: bytes, round_number: int, deadline: float):
        super().__init__()
        self.nonce = nonce
        self.round_number = round_number
        self.deadline = deadline

    def to_pack_list(self):
        return [("varlenH", self.nonce), ("q", self.round_number), ("d", self.deadline)]

    @classmethod
    def from_unpack_list(cls, nonce, round_number, deadline):
        return cls(nonce, round_number, deadline)


class SignatureBundlePayload(Payload):
    msg_id = 5
    format_list = ["varlenHutf8", "q", "varlenH", "varlenH", "varlenH"]

    def __init__(self, group_id: str, round_number: int, sig1: bytes, sig2: bytes, sig3: bytes):
        super().__init__()
        self.group_id = group_id
        self.round_number = round_number
        self.sig1 = sig1
        self.sig2 = sig2
        self.sig3 = sig3

    def to_pack_list(self):
        return [("varlenHutf8", self.group_id),("q", self.round_number),("varlenH", self.sig1),("varlenH", self.sig2),("varlenH", self.sig3),]

    @classmethod
    def from_unpack_list(cls, group_id, round_number, sig1, sig2, sig3):
        return cls(group_id, round_number, sig1, sig2, sig3)


class RoundResultPayload(Payload):
    msg_id = 6
    format_list = ["?", "q", "q", "varlenHutf8"]

    def __init__(self, success: bool, round_number: int, rounds_completed: int, message: str):
        super().__init__()
        self.success = success
        self.round_number = round_number
        self.rounds_completed = rounds_completed
        self.message = message

    def to_pack_list(self):
        return [("?", self.success),("q", self.round_number),("q", self.rounds_completed),("varlenHutf8", self.message),]

    @classmethod
    def from_unpack_list(cls, success, round_number, rounds_completed, message):
        return cls(success, round_number, rounds_completed, message)


class AnnounceChallenge(Payload):
    msg_id = 100
    format_list = ["varlenHutf8", "varlenH", "d", "q"]
    names = ["group_id", "nonce", "deadline", "round_number"]

    def __init__(self, group_id: str, nonce: bytes, deadline: float, round_number: int):
        super().__init__()
        self.group_id = group_id
        self.nonce = nonce
        self.deadline = deadline
        self.round_number = round_number

    def to_pack_list(self):
        return [("varlenHutf8", self.group_id),("varlenH", self.nonce),("d", self.deadline),("q", self.round_number),]

    @classmethod
    def from_unpack_list(cls, group_id, nonce, deadline, round_number):
        return cls(group_id, nonce, deadline, round_number)

class BroadcastSignature(Payload):
    msg_id = 102
    format_list = ["varlenH", "varlenH", "q"]
    names = ["nonce", "signature", "round_number"]

    def __init__(self, nonce: bytes, signature: bytes, round_number: int):
        super().__init__()
        self.nonce = nonce
        self.signature = signature
        self.round_number = round_number

    def to_pack_list(self):
        return [("varlenH", self.nonce),("varlenH", self.signature),("q", self.round_number),]

    @classmethod
    def from_unpack_list(cls, nonce, signature, round_number):
        return cls(nonce, signature, round_number)

class AnnounceRoundResultPayload(Payload):
    msg_id = 104
    format_list = ["varlenHutf8", "q", "?"]
    names = ["group_id", "round_number", "success"]

    def __init__(self, group_id: str, round_number: int, success: bool):
        super().__init__()
        self.group_id = group_id
        self.round_number = round_number
        self.success = success
    def to_pack_list(self):
        return [("varlenHutf8", self.group_id), ("q", self.round_number),("?", self.success),]
    
    @classmethod
    def from_unpack_list(cls, group_id, round_number, success):
        return cls(group_id, round_number, success) 


class PowCommunity(Community):
    community_id = bytes.fromhex("4c61623247726f75705369676e696e6732303236")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_message_handler(RegisterResponsePayload.msg_id, self.on_register_response)
        self.add_message_handler(ChallengeResponsePayload.msg_id, self.on_challenge_response)
        self.add_message_handler(RoundResultPayload.msg_id, self.on_round_result)
        self.add_message_handler(AnnounceChallenge.msg_id, self.on_nonce_share)
        self.add_message_handler(BroadcastSignature.msg_id, self.on_signature_share)
        self.add_message_handler(AnnounceRoundResultPayload.msg_id, self.on_round_result_announce)

        self.registered_event = asyncio.Event()
        self.group_id: str = GROUP_ID
        self.current_round = 1

        self.nonce_received:dict = {r: asyncio.Event() for r in (1, 2, 3)}
        self.sigs_collected:dict = {r: asyncio.Event() for r in (1, 2, 3)}
        self.round_result_ev:dict = {r: asyncio.Event() for r in (1, 2, 3)}

        self.nonces:dict = {}
        self.signatures:dict = {r: {} for r in (1, 2, 3)}
        self.round_success: dict = {}
        self.deadlines: dict = {}

    def find_server(self):
        for peer in self.get_peers():
            if peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
                return peer
        return None

    # lab2 helpers =

    def find_teammate(self, key_bytes: bytes):
        for peer in self.get_peers():
            if peer.public_key.key_to_bin() == key_bytes:
                return peer
        return None

    def my_key_bytes(self) -> bytes:
        return self.my_peer.public_key.key_to_bin()

    def my_member_index(self) -> int:
        my_key = self.my_key_bytes()
        for i, k in enumerate(MEMBER_KEYS):
            if k == my_key:
                return i
        raise RuntimeError("My public key is not here recheck.")

    def sign_nonce(self, nonce: bytes) -> bytes:
        return self.crypto.create_signature(self.my_peer.key, nonce)

    @lazy_wrapper(AnnounceChallenge)
    def on_nonce_share(self, peer, payload):
        if peer.public_key.key_to_bin() not in MEMBER_KEYS:
            return
        print(f"Received nonce. Announce challenge = {payload.nonce.hex()[:16]}  deadline = {payload.deadline}  round number = {payload.round_number}")
        sig = self.sign_nonce(payload.nonce)
        sender = self.find_teammate(peer.public_key.key_to_bin())
        if sender:
            self.ez_send(sender, BroadcastSignature(payload.nonce, sig, payload.round_number))

    @lazy_wrapper(RegisterResponsePayload)
    def on_register_response(self, peer, payload):
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY:
            return
        print(f"This is the response for registering = success={payload.success}  group_id={payload.group_id!r}  msg={payload.message!r}")
        if payload.success or "already registered" in payload.message:
            self.group_id = payload.group_id
            self.registered_event.set()

    # server responses with the nonce
    @lazy_wrapper(ChallengeResponsePayload)
    def on_challenge_response(self, peer, payload):
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY:
            return
        r = payload.round_number
        print(f"The challenge response are these =  round={r}  nonce={payload.nonce.hex()[:16]}  deadline={payload.deadline:.2f} ")
        self.nonces[r] = payload.nonce
        self.nonce_received[r].set()
        self.deadlines[r] = payload.deadline

    @lazy_wrapper(RoundResultPayload)
    def on_round_result(self, peer, payload):
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY:
            return
        r = payload.round_number
        print(f"These are the round results = round={r}  success={payload.success}  completed={payload.rounds_completed}  msg={payload.message!r}")
        self.round_success[r] = payload.success
        self.round_result_ev[r].set()

    @lazy_wrapper(AnnounceRoundResultPayload)
    def on_round_result_share(self, peer, payload):
        if peer.public_key.key_to_bin() not in MEMBER_KEYS:
            return
        r = payload.round_number
        print(f"Looking from teammate, round {r} result: success={payload.success}")
        self.round_success[r] = payload.success
        self.round_result_ev[r].set()
    
    @lazy_wrapper(BroadcastSignature)
    def on_signature_share(self, peer, payload):
        sender_key = peer.public_key.key_to_bin()
        if sender_key not in MEMBER_KEYS:
            return
        member_idx = MEMBER_KEYS.index(sender_key)
        r = payload.round_number
        print(f"So just received the signature for the round {r} and this from member{member_idx + 1} and this is the signature : {payload.signature.hex()[:16]}, rounds = {payload.round_number}")
        self.signatures[r][member_idx] = payload.signature
        self.sigs_collected[r].set()

    @lazy_wrapper(AnnounceRoundResultPayload)
    def on_round_result_announce(self, peer, payload):
        if peer.public_key.key_to_bin() not in MEMBER_KEYS:
            return
        r = payload.round_number
        self.round_success[r] = payload.success
        self.round_result_ev[r].set()
        print(f"Looking from teammate, round {r} result: success={payload.success}")

    async def run_lab2(self, server):
        # Wait for teammates first
        for attempt in range(60):
            teammates = [self.find_teammate(k) for k in MEMBER_KEYS if k != self.my_key_bytes()]
            if all(t is not None for t in teammates):
                break
            await asyncio.sleep(1)

        if not self.group_id:
            print("Lets start with registering")
            for _ in range(5):
                self.ez_send(server, RegisterPayload(*MEMBER_KEYS))
                try:
                    await asyncio.wait_for(self.registered_event.wait(), timeout=5.0)
                    break
                except asyncio.TimeoutError:
                    print("No register yet hold")

        if not self.group_id:
            print("issue with registering ppl.")
            return

        print(f"So the group ID is this = {self.group_id}")

        for round_num in (1, 2, 3):
            await self.run_round(round_num, server)

    async def run_round(self, round_num: int, server):
        self.current_round = round_num
        my_idx = self.my_member_index()
        submitter_idx = round_num - 1

        if my_idx != submitter_idx:
            await self.round_result_ev[round_num].wait()
            success = self.round_success.get(round_num, False)
            print(f"{'done' if success else 'not done'} Round {round_num} finished for other ppl, success={success}")
            return

        for attempt in range(5):
            self.ez_send(server, ChallengeRequestPayload(self.group_id))
            try:
                await asyncio.wait_for(self.nonce_received[round_num].wait(), timeout=3.0)
                break
            except asyncio.TimeoutError:
                pass

        nonce = self.nonces.get(round_num)
        if nonce is None:
            print(f"nonce wasnt received ")
            return

        my_sig = self.sign_nonce(nonce)
        self.signatures[round_num][my_idx] = my_sig

        deadline = self.deadlines.get(round_num, 0)
        def broadcast_nonce():
            for key in MEMBER_KEYS:
                if key == self.my_key_bytes():
                    continue
                teammate = self.find_teammate(key)
                if teammate:
                    self.ez_send(teammate, AnnounceChallenge(self.group_id, nonce, deadline, round_num))

        broadcast_nonce()

        for attempt in range(8):
            if len(self.signatures[round_num]) == 3:
                break
            try:
                await asyncio.wait_for(self.sigs_collected[round_num].wait(), timeout=1.5)
                self.sigs_collected[round_num].clear()
            except asyncio.TimeoutError:
                print(f"Still waiting for signatures ")
                broadcast_nonce()

        if len(self.signatures[round_num]) < 3:
            print(f"not all signatures were collected")
            return

        sigs = self.signatures[round_num]
        bundle = SignatureBundlePayload(self.group_id, round_num, sigs[0], sigs[1], sigs[2])

        for attempt in range(5):
            self.ez_send(server, bundle)
            try:
                await asyncio.wait_for(self.round_result_ev[round_num].wait(), timeout=3.0)
                break
            except asyncio.TimeoutError:
                if attempt < 4:
                    print(f" No result yet :(")

        success = self.round_success.get(round_num, False)
        print(f"{'done' if success else 'not done'} Round {round_num} complete — success={success}")

        for key in MEMBER_KEYS:
            if key == self.my_key_bytes():
                continue
            teammate = self.find_teammate(key)
            if teammate:
                self.ez_send(teammate, AnnounceRoundResultPayload(
                    self.group_id, round_num, success))


async def main():
    logging.basicConfig(level=logging.WARNING)

    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("my peer", "curve25519", "my_peer.key")
    builder.add_overlay("PowCommunity", "my peer", [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 10.0})], default_bootstrap_defs, {}, [],)

    # this is for hiding the annoying debug logs
    logging.basicConfig(level=logging.WARNING)
    logging.getLogger("PowCommunity").setLevel(logging.CRITICAL)

    ipv8 = IPv8(builder.finalize(), extra_communities={"PowCommunity": PowCommunity})
    await ipv8.start()

    community = ipv8.overlays[0]
    print("IPv8 started.")
    server = None
    for attempt in range(60):
        server = community.find_server()
        if server:
            print(f"Server found")
            break
        await asyncio.sleep(2)

    if server is None:
        print("i think issue is that server is not running or not reachable so 500.")
        await ipv8.stop()
        return

    lab2_task = asyncio.ensure_future(community.run_lab2(server))

    await lab2_task
    await ipv8.stop()

asyncio.run(main())