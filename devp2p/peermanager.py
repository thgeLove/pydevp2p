import random
import gevent
import socket
import atexit
import time
import re
from gevent.server import StreamServer
from gevent.socket import create_connection, timeout
from .service import WiredService
from .protocol import BaseProtocol
from .p2p_protocol import P2PProtocol
from .upnp import add_portmap, remove_portmap
from devp2p import kademlia
from .peer import Peer
from devp2p import crypto
from devp2p import utils
from rlp.utils import decode_hex

from devp2p import slogging
log = slogging.get_logger('p2p.peermgr')


def on_peer_exit(peer):
    peer.stop()


# StreamServer 를 통해 발생하는 명령들을 최종적으로 TCP를 이용하여 전송하고 받는다.
# peer들과 연결된 후에 각각 peer 객체를 생성해서 개별적으로 통신하게 한다.
class PeerManager(WiredService):

    """
    todo:
        connects new peers if there are too few
        selects peers based on a DHT
        keeps track of peer reputation
        saves/loads peers (rather discovery buckets) to disc

    connection strategy
        for service which requires peers
            while num peers > min_num_peers:
                    gen random id
                    resolve closest node address
                    [ideally know their services]
                    connect closest node
    """
    name = 'peermanager'
    required_services = []
    wire_protocol = P2PProtocol
    nat_upnp = None
    default_config = dict(p2p=dict(bootstrap_nodes=[],
                                   min_peers=5,
                                   max_peers=10,
                                   listen_port=30303,
                                   listen_host='0.0.0.0'),
                          log_disconnects=False,
                          node=dict(privkey_hex=''))

    connect_timeout = 2.
    connect_loop_delay = 0.1
    discovery_delay = 0.5

    def __init__(self, app):
        log.info('PeerManager init')
        WiredService.__init__(self, app)
        self.peers = []
        self.errors = PeerErrors() if self.config['log_disconnects'] else PeerErrorsBase()

        # setup nodeid based on privkey
        if 'id' not in self.config['p2p']:
            self.config['node']['id'] = crypto.privtopub(
                decode_hex(self.config['node']['privkey_hex']))

        self.listen_addr = (self.config['p2p']['listen_host'], self.config['p2p']['listen_port'])
        self.server = StreamServer(self.listen_addr, handle=self._on_new_connection)

    def on_hello_received(self, proto, version, client_version_string, capabilities,
                          listen_port, remote_pubkey):
        log.debug('hello_received', peer=proto.peer, num_peers=len(self.peers))
        if len(self.peers) > self.config['p2p']['max_peers']:
            log.debug('too many peers', max=self.config['p2p']['max_peers'])
            proto.send_disconnect(proto.disconnect.reason.too_many_peers)
            return False
        if remote_pubkey in [p.remote_pubkey for p in self.peers if p != proto.peer]:
            log.debug('connected to that node already')
            proto.send_disconnect(proto.disconnect.reason.useless_peer)
            return False

        return True

    @property
    def wired_services(self):
        return [s for s in self.app.services.values() if isinstance(s, WiredService)]

    def broadcast(self, protocol, command_name, args=[], kargs={},
                  num_peers=None, exclude_peers=[]):
        log.debug('broadcasting', protcol=protocol, command=command_name,
                  num_peers=num_peers, exclude_peers=exclude_peers)
        assert num_peers is None or num_peers > 0
        peers_with_proto = [p for p in self.peers
                            if protocol in p.protocols and p not in exclude_peers]

        if not peers_with_proto:
            log.debug('no peers with proto found', protos=[p.protocols for p in self.peers])
        num_peers = num_peers or len(peers_with_proto)
        for peer in random.sample(peers_with_proto, min(num_peers, len(peers_with_proto))):
            log.debug('broadcasting to', proto=peer.protocols[protocol])
            func = getattr(peer.protocols[protocol], 'send_' + command_name)
            func(*args, **kargs)
            # sequential uploads
            # wait until the message is out, before initiating next
            peer.safe_to_read.wait()
            log.debug('broadcasting done', ts=time.time())

    def _start_peer(self, connection, address, remote_pubkey=None):
        # create peer
        # 해당 노드와 1대1로 통신하기 위한 peer 객체를 생성한다.
        peer = Peer(self, connection, remote_pubkey=remote_pubkey)
        peer.link(on_peer_exit)
        log.debug('created new peer', peer=peer, fno=connection.fileno())
        self.peers.append(peer)

        # loop
        # peer 경량 스레드를 시작한다.
        peer.start()
        log.debug('peer started', peer=peer, fno=connection.fileno())
        assert not connection.closed
        return peer


    def connect(self, address, remote_pubkey):
        log.debug('connecting', address=address)
        """
        gevent.socket.create_connection(address, timeout=Timeout, source_address=None)
        Connect to address (a 2-tuple (host, port)) and return the socket object.
        Passing the optional timeout parameter will set the timeout
        getdefaulttimeout() is default
        """
        try:
            # 먼저 gevent 소켓통신 라이브러리에서 제공하는 create_connection으로 연결정보(소켓디스크립션)을 얻는다.
            connection = create_connection(address, timeout=self.connect_timeout)
        except socket.timeout:
            log.debug('connection timeout', address=address, timeout=self.connect_timeout)
            self.errors.add(address, 'connection timeout')
            return False
        except socket.error as e:
            log.debug('connection error', errno=e.errno, reason=e.strerror)
            self.errors.add(address, 'connection error')
            return False
        log.debug('connecting to', connection=connection)
        # 이제 해당 노드와 1대1로 통신하기 위한 Peer 객체를 생성한다.
        self._start_peer(connection, address, remote_pubkey)
        return True

    def _bootstrap(self, bootstrap_nodes=[]):
        for uri in bootstrap_nodes:
            ip, port, pubkey = utils.host_port_pubkey_from_uri(uri)
            log.info('connecting bootstrap server', uri=uri)
            try:
                self.connect((ip, port), pubkey)
            except socket.error:
                log.warn('connecting bootstrap server failed')

    def start(self):
        log.info('starting peermanager')
        # try upnp nat
        # NAT 문제를 해결하기 위한 upnp 설정
        self.nat_upnp = add_portmap(
            self.config['p2p']['listen_port'],
            'TCP',
            'Ethereum DEVP2P Peermanager'
        )
        # start a listening server
        log.info('starting listener', addr=self.listen_addr)

        # TCP 서버의 listening 핸들러 설정. 새로운 접속이 들어오면 호출된다.
        self.server.set_handle(self._on_new_connection)
        # TCP 서버 시작
        self.server.start()
        super(PeerManager, self).start()

        # gevent는 일종의 경량 쓰레드

        # bootstrap 시작(이미 하드코딩되어 있는 시작 노드에 접속한다.)
        gevent.spawn_later(0.001, self._bootstrap, self.config['p2p']['bootstrap_nodes'])
        # discovery 시작(새로 접속할 노드를 선택하기 위해 kademlia routing table을 참조한다.)
        gevent.spawn_later(1, self._discovery_loop)

    def _on_new_connection(self, connection, address):
        log.debug('incoming connection', connection=connection)
        peer = self._start_peer(connection, address)
        # Explicit join is required in gevent >= 1.1.
        # See: https://github.com/gevent/gevent/issues/594
        # and http://www.gevent.org/whatsnew_1_1.html#compatibility
        peer.join()

    def num_peers(self):
        ps = [p for p in self.peers if p]
        aps = [p for p in ps if not p.is_stopped]
        if len(ps) != len(aps):
            log.warn('stopped peers in peers list', inlist=len(ps), active=len(aps))
        return len(aps)

    def remote_pubkeys(self):
        return [p.remote_pubkey for p in self.peers]


    def _discovery_loop(self):
        log.info('waiting for bootstrap')
        # kademlia node discovery 가 어느정도 완성 될 때까지 대기
        gevent.sleep(self.discovery_delay)
        # 이제부터 계속 접속할 노드를 찾는 과정을 반복한다.
        while not self.is_stopped:
            try:
                num_peers, min_peers = self.num_peers(), self.config['p2p']['min_peers']
                # 접속할 노드를 선택하기 위해 미리 채워두었던 kademlia 프로토콜을 참조한다.
                kademlia_proto = self.app.services.discovery.protocol.kademlia
                # 접속할 최소 피어수보다 많을때까지 추가한다.
                if num_peers < min_peers:
                    log.debug('missing peers', num_peers=num_peers,
                              min_peers=min_peers, known=len(kademlia_proto.routing))
                    #접속할 노드를 선택하기 위해 랜덤으로 node id 하나를 생성한다.
                    nodeid = kademlia.random_nodeid()
                    # kademlia routing table에서 가까운 노드들을 가져온다.
                    kademlia_proto.find_node(nodeid)  # fixme, should be a task
                    gevent.sleep(self.discovery_delay)  # wait for results
                    neighbours = kademlia_proto.routing.neighbours(nodeid, 2)
                    if not neighbours:
                        gevent.sleep(self.connect_loop_delay)
                        continue
                    # 가져온 노드들 중에 노드 하나를 선택한다. 이 무작위로 선택한 노드와 연결될 것이다.
                    node = random.choice(neighbours)
                    if node.pubkey in self.remote_pubkeys():
                        gevent.sleep(self.discovery_delay)
                        continue
                    log.debug('connecting random', node=node)
                    # 내 public key를 구해서
                    local_pubkey = crypto.privtopub(decode_hex(self.config['node']['privkey_hex']))
                    if node.pubkey == local_pubkey:
                        continue
                    if node.pubkey in [p.remote_pubkey for p in self.peers]:
                        continue
                    # 선택된 노드와 연결한다. (그 노드에 내 public key를 보낸다)
                    self.connect((node.address.ip, node.address.tcp_port), node.pubkey)
            except AttributeError:
                # TODO: Is this the correct thing to do here?
                log.error("Discovery service not available.")
                break
            except Exception as e:
                log.error("discovery failed", error=e, num_peers=num_peers, min_peers=min_peers)
            gevent.sleep(self.connect_loop_delay)

        evt = gevent.event.Event()
        evt.wait()

    def stop(self):
        log.info('stopping peermanager')
        remove_portmap(self.nat_upnp, self.config['p2p']['listen_port'], 'TCP')
        self.server.stop()
        for peer in self.peers:
            peer.stop()
        super(PeerManager, self).stop()


class PeerErrorsBase(object):
    def add(self, address, error, client_version=''):
        pass


class PeerErrors(PeerErrorsBase):
    def __init__(self):
        self.errors = dict()  # node: ['error',]
        self.client_versions = dict()  # address: client_version

        def report():
            for k, v in self.errors.items():
                print(k, self.client_versions.get(k, ''))
                for e in v:
                    print('\t', e)

        atexit.register(report)

    def add(self, address, error, client_version=''):
        self.errors.setdefault(address, []).append(error)
        if client_version:
            self.client_versions[address] = client_version
