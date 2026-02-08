from kemtls.handshake import KEMTLSHandshake
from kemtls.channel import SecureChannel


class KEMTLSServer:
    def __init__(self):
        self.handshake = KEMTLSHandshake()
        self.sessions = {}

    def start_handshake(self):
        """
        Server sends public KEM and signature keys.
        """
        return self.handshake.server_hello()

    def complete_handshake(self, client_ct: bytes):
        """
        Complete KEMTLS handshake and establish secure channel.
        """
        shared_secret = self.handshake.server_decapsulate(client_ct)

        transcript = client_ct
        signature = self.handshake.authenticate_server(transcript)

        channel = SecureChannel(shared_secret)
        session_id = id(channel)

        self.sessions[session_id] = channel

        return session_id, signature

    def send(self, session_id: int, plaintext: bytes) -> bytes:
        return self.sessions[session_id].encrypt(plaintext)

    def receive(self, session_id: int, ciphertext: bytes) -> bytes:
        return self.sessions[session_id].decrypt(ciphertext)
