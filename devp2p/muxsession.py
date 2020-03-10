import gevent
from .multiplexer import Multiplexer, Packet
from .rlpxcipher import RLPxSession
from .crypto import ECCx

# 비동기 i/o를 처리해준다. 즉 read/write 에 대해 각각의 경량 쓰레드를 만든 후에 해당 이벤트가 없는 경우 양보한다. read/write 와 RlpxSession을 관리한다.
# 보내야할 데이터를 조각낸다. 조각내는 이유는 소켓버퍼의 양(window size)에 맞추기 위함인데, 프로토콜 별로 조각, 우선순위별 조각 등이 각각 조합되어 max_window_size 만큼의 패킷을 완성하게 된다. 
# 해당 패킷은 StreamServer를 통해 보내어진다.
class MultiplexedSession(Multiplexer):
    # 내부에 ingress, egress 큐가 존재하여 multiplexing 작업을 할 수 있다/ 
    # RLPxSession 객체를 통해 초기 암호화/프로토콜 공유 핸드웨이킹을 할 수 있다.
    # 멀티프로토콜끼리 공평하게 패킷 공간을 차지하게 하기위한 framing 도 시작된다.
    def __init__(self, privkey, hello_packet, remote_pubkey=None):
        # 내가 시작한 연결인가? 누간가에게 요청되어 온 연결인가?
        # 내가 시작한 연결이라면 노드디스커버리 프로토콜에서 이미 얻어진 상대  public_key 를 가지고 있을 것이다.

        self.is_initiator = bool(remote_pubkey)
        self.hello_packet = hello_packet
        # 나가는 메시지에 대한 큐
        self.message_queue = gevent.queue.Queue()  # wire msg egress queue
        # 들어오는 메시지에 대한 큐
        self.packet_queue = gevent.queue.Queue()  # packet ingress queue
        # 암호화/무결성화 에 사용되는 ECCx 객체 생성
        ecc = ECCx(raw_privkey=privkey)
        # 비밀키/토큰 공유를 위한 RLPxSession 객체 생성
        self.rlpx_session = RLPxSession(
            ecc, is_initiator=bool(remote_pubkey))
        self._remote_pubkey = remote_pubkey
        Multiplexer.__init__(self, frame_cipher=self.rlpx_session)
        # 상대 노드에게 msg를 보낸다(초기 핸드쉐이킹을 위한)
        if self.is_initiator:
            self._send_init_msg()

    @property
    def is_ready(self):
        # only authenticated and ready after successfully authenticated hello packet
        return self.rlpx_session.is_ready

    @property
    def remote_pubkey(self):
        "if responder not be available until first message is received"
        return self._remote_pubkey or self.rlpx_session.remote_pubkey

    @remote_pubkey.setter
    def remote_pubkey(self, value):
        self._remote_pubkey = value

    def _send_init_msg(self):
        # RLPxSession 객체를 통해 인증메시지를 만든다. 이 메시지는 다음과 같은 정보가 포함된다.
        # auth_message = S + sha3(ephemeral_pubkey) + self.ecc.raw_pubkey + self.initiator_nonce + ascii_chr(flag)
        auth_msg = self.rlpx_session.create_auth_message(self._remote_pubkey)
        # 인증 메시지를 암호화한다.
        auth_msg_ct = self.rlpx_session.encrypt_auth_message(auth_msg)
        # 암호화된 메시지를 멀티플렉싱을 위한 egress 큐에 넣는다.
        self.message_queue.put(auth_msg_ct)

    # 노드에서 초기 핸드쉐이크를 할 경우에는 add_message 메소드가 add_message_during_handshake 로직을 따른다.
    # 핸드쉐이크가 끝난 후에는 add_message_post_handshake 로직을 따른다.

    # 핸드쉐이킹 도중에는 받은 메시지를 이렇게 처리한다.
    def _add_message_during_handshake(self, msg):
        assert not self.is_ready
        session = self.rlpx_session
        # 내가 먼저 요청한 연결이라면
        if self.is_initiator:
            # expecting auth ack message
            # auth 요청 보낸것에 대한 답변인 msg를 디코드한다.
            rest = session.decode_auth_ack_message(msg)
            # 리모트에서 넘어온 정보를 토대로 최종적인 상호 암호화 정보를 세팅하게 된다. 앞으로는 구축된 이 정보를 통해 상호간 암호화/무결성화된 통신을 하게 된다.
            session.setup_cipher()
            if len(rest) > 0:  # add remains (hello) to queue
                self._add_message_post_handshake(rest)
        
        # 핸드쉐이킹 요청을 받은 것이라면
        else:
            # expecting auth_init
            # 요청된 auth 정보를 디코딩한다.
            rest = session.decode_authentication(msg)
            # 대답해줄 ack 메시지를 준비한다.
            auth_ack_msg = session.create_auth_ack_message()
            # 대답해줄 ack 메시지를 암호화한다.
            auth_ack_msg_ct = session.encrypt_auth_ack_message(auth_ack_msg)
            # 전송 큐인 message_queue에 넣는다.
            self.message_queue.put(auth_ack_msg_ct)
            # 리모트로부터 받느 auth 정보를 토대로 cipher 를 세팅한다.
            session.setup_cipher()
            if len(rest) > 0:
                self._add_message_post_handshake(rest) 
        # 핸드웨이크 종료 후 add_message 메소드
        self.add_message = self._add_message_post_handshake

        # send hello
        assert session.is_ready
        # 암호화를 위한 핸드쉐이크가 끝나면 이제 프로토콜을 맞춰보는 핸드쉐이크가 시작된다.
        self.add_packet(self.hello_packet)

    # 초기 add_message 메소드
    add_message = _add_message_during_handshake  # on_ready set to _add_message_post_handshake

    # 핸드쉐이킹이 끝난 후에는 아주 단순하게 그냥 전달받은 msg 를 디코드하여 수신큐인 packet_queue에 넣는다.
    def _add_message_post_handshake(self, msg):
        "decodes msg and adds decoded packets to queue"
        for packet in self.decode(msg):
            self.packet_queue.put(packet)

    def add_packet(self, packet):
        "encodes a packet and adds the message(s) to the msg queue"
        assert isinstance(packet, Packet)
        assert self.is_ready  # don't send anything until handshake is finished
        Multiplexer.add_packet(self, packet)
        for f in self.pop_all_frames():
            self.message_queue.put(f.as_bytes())
