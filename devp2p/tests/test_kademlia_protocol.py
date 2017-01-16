# -*- coding: utf-8 -*-
import random
from devp2p.utils import int_to_big_endian
from devp2p import kademlia
import pytest
import gevent

random.seed(42)


class WireMock(kademlia.WireInterface):

    messages = []  # global messages

    def __init__(self, sender):
        assert isinstance(sender, kademlia.Node)
        self.sender = sender
        assert not self.messages

    @classmethod
    def empty(cls):
        while cls.messages:
            cls.messages.pop()

    def send_ping(self, node):
        echo = hex(random.randint(0, 2 ** 256))[-32:]
        self.messages.append((node, 'ping', self.sender, echo))
        return echo

    def send_pong(self, node, echo):
        self.messages.append((node, 'pong', self.sender, echo))

    def send_find_node(self,  node, nodeid):
        self.messages.append((node, 'find_node', self.sender, nodeid))

    def send_neighbours(self, node, neighbours):
        self.messages.append((node, 'neighbours', self.sender, neighbours))

    def poll(self, node):
        for i, x in enumerate(self.messages):
            if x[0] == node:
                del self.messages[i]
                return x[1:]

    def process_single(self, node, kademlia_protocols):
        msg = None
        for i, x in enumerate(self.messages):
            if x[0] == node:
                msg = x
                del self.messages[i]
                break
        if msg:
            proto_by_node = dict((p.this_node, p) for p in kademlia_protocols)
            target = proto_by_node[msg[0]]
            cmd = 'recv_' + msg[1]
            getattr(target, cmd)(*msg[2:])
            return msg[1:]

    def process(self, kademlia_protocols, steps=0):
        """
        process messages until none are left
        or if process steps messages if steps >0

        also yields all messages for asserting
        """
        i = 0
        proto_by_node = dict((p.this_node, p) for p in kademlia_protocols)
        while self.messages:
            msg = self.messages.pop(0)
            assert isinstance(msg[2], kademlia.Node)
            target = proto_by_node[msg[0]]
            cmd = 'recv_' + msg[1]
            getattr(target, cmd)(*msg[2:])
            i += 1
            yield msg[1:]
            if steps and i == steps:
                return  # messages may be left
        assert not self.messages


def random_pubkey():
    pk = int_to_big_endian(random.getrandbits(kademlia.k_pubkey_size))
    return '\x00' * (kademlia.k_pubkey_size / 8 - len(pk)) + pk


def random_node():
    return kademlia.Node(random_pubkey())


def routing_table(num_nodes=1000):
    node = random_node()
    routing = kademlia.RoutingTable(node)
    for i in range(num_nodes):
        routing.add_node(random_node())
        assert len(routing.buckets) <= i + 2
    assert len(routing.buckets) <= 512
    assert i == num_nodes - 1
    return routing


@pytest.fixture(scope="function", params=[1])
def num_nodes(request):
    """Fixture for the number of nodes returned by fixture `proto`.
    """
    return request.param


@pytest.fixture(scope="function")
def protos(request, num_nodes):
    """Create `num_nodes` KademliaProtocol instances with `WireMock` attached.
    """
    protocols = []
    for i in range(num_nodes):
        this_node = random_node()
        proto = kademlia.KademliaProtocol(this_node, WireMock(this_node))
        request.addfinalizer(proto.wire.empty)
        protocols.append(proto)
    return protocols


@pytest.fixture(scope="function")
@pytest.mark.parametrize('num_nodes', [1])
def proto(request, protos):
    return protos[0]


@pytest.mark.parametrize('num_nodes', [2])
def test_bootstrap(protos):
    proto = protos[0]
    wire = proto.wire
    other = protos[1]
    # lookup self
    proto.bootstrap(nodes=[other.this_node])
    # bootstrap should initiate bonding
    msg = wire.process_single(other.this_node, protos)
    assert msg[:2] == ('ping', proto.routing.this_node)
    # bonding should be followed up by find_node
    # find_node must be delayed until bonding succeeded!

    msg = wire.process_single(other.this_node, protos)
    assert msg is None

    # let bonding proceed
    messages = list(wire.process(protos, steps=3))
    # ping, pong, ping(consumed), pong
    assert [m[0] for m in messages] == ['ping', 'pong', 'pong']
    assert proto.routing.get_node(other.this_node).bonded

    assert wire.process_single(other.this_node, protos) == ('find_node', proto.routing.this_node, proto.routing.this_node.id)
    assert len(wire.messages)
    # nothing left to be done from other
    assert wire.process_single(other.this_node, protos) is None

    messages = list(wire.process(protos))
    assert wire.messages == []

    assert len(messages)
    assert messages[0] == ('neighbours', other.this_node, [proto.this_node])
    # After bootstrap each node should be in others routing and bonded
    assert other.this_node in proto.routing
    assert proto.routing.get_node(other.this_node).bonded

    assert proto.this_node in other.routing
    assert other.routing.get_node(proto.this_node).bonded


def test_setup(proto):
    """
    nodes connect to any peer and do a lookup for them selfs
    """

    wire = proto.wire
    other = routing_table()

    # lookup self
    proto.bootstrap(nodes=[other.this_node])
    msg = wire.poll(other.this_node)
    assert msg[:2] == ('ping', proto.routing.this_node)
    msg = wire.poll(other.this_node)
    assert msg == ('find_node', proto.routing.this_node, proto.routing.this_node.id)
    assert wire.poll(other.this_node) is None
    assert wire.messages == []

    # respond with neighbours
    closest = other.neighbours(msg[2])
    assert len(closest) == kademlia.k_bucket_size
    proto.recv_neighbours(random_node(), closest)

    # expect 3 lookups
    for i in range(kademlia.k_find_concurrency):
        msg = wire.poll(closest[i])
        assert msg == ('find_node', proto.routing.this_node, proto.routing.this_node.id)

    # and pings for all nodes
    for node in closest:
        msg = wire.poll(node)
        assert msg[0] == 'ping'

    # nothing else
    assert wire.messages == []


@pytest.mark.timeout(5)
@pytest.mark.xfail(reason="unsure")
def test_find_node_timeout(proto):
    other = routing_table()
    wire = proto.wire

    # lookup self
    proto.bootstrap(nodes=[other.this_node])
    msg = wire.poll(other.this_node)
    assert msg == ('find_node', proto.routing.this_node, proto.routing.this_node.id)
    assert wire.poll(other.this_node) is None
    assert wire.messages == []

    # do timeout
    gevent.sleep(kademlia.k_request_timeout)

    # respond with neighbours
    closest = other.neighbours(msg[2])
    assert len(closest) == kademlia.k_bucket_size
    proto.recv_neighbours(random_node(), closest)

    # expect pings, but no other lookup
    msg = wire.poll(closest[0])
    assert msg[0] == 'ping'
    assert wire.poll(closest[0]) is None
    assert wire.messages == []


def test_eviction(proto):
    proto.routing = routing_table(1000)
    wire = proto.wire

    # trigger node ping
    node = proto.routing.neighbours(random_node())[0]
    proto.ping(node)

    # manually set bonding
    node.ping_recv = True

    msg = wire.poll(node)
    assert msg[0] == 'ping'
    assert wire.messages == []
    proto.recv_pong(node, msg[2])
    assert node.pong_recv is True

    assert node.bonded

    # expect no message and that node is still there
    assert wire.messages == []
    assert node in proto.routing

    # expect node to be on the tail
    assert proto.routing.bucket_by_node(node).tail == node


@pytest.mark.timeout(5)
@pytest.mark.xfail
def test_eviction_timeout(proto):
    proto.routing = routing_table(1000)
    wire = proto.wire

    # trigger node ping
    node = proto.routing.neighbours(random_node())[0]
    proto.ping(node)
    msg = wire.poll(node)
    assert msg[0] == 'ping'
    assert wire.messages == []

    gevent.sleep(kademlia.k_request_timeout)
    proto.recv_pong(node, msg[2])
    # expect no message and that is not there anymore
    assert wire.messages == []
    assert node not in proto.routing

    # expect node not to be in the replacement_cache
    assert node not in proto.routing.bucket_by_node(node).replacement_cache


@pytest.mark.timeout(15)
def test_eviction_node_active(proto):
    """
    active nodes (replying in time) should not be evicted
    """
    proto.routing = routing_table(10000)  # set high, so add won't split
    wire = proto.wire

    # get a full bucket
    full_buckets = [b for b in proto.routing.buckets if b.is_full and not b.should_split]
    assert full_buckets
    bucket = full_buckets[0]
    assert not bucket.should_split
    assert len(bucket) == kademlia.k_bucket_size
    bucket_nodes = bucket.nodes[:]
    eviction_candidate = bucket.head

    # manually set bonding successful
    eviction_candidate.ping_recv = eviction_candidate.pong_recv = True
    assert eviction_candidate.bonded

    # create node to insert
    node = random_node()

    #manually set bonding successful
    node.ping_recv = node.pong_recv = True
    assert node.bonded

    node.id = bucket.start + 1  # should not split
    assert bucket.in_range(node)
    assert bucket == proto.routing.bucket_by_node(node)

    # insert node
    proto.update(node)

    # expect bucket was not split
    assert len(bucket) == kademlia.k_bucket_size

    # expect bucket to be unchanged
    assert bucket_nodes == bucket.nodes
    assert eviction_candidate == bucket.head

    # expect node not to be in bucket yet
    assert node not in bucket
    assert node not in proto.routing

    # expect a ping to bucket.head
    assert len(wire.messages)
    msg = wire.poll(eviction_candidate)
    assert msg[0] == 'ping'
    assert msg[1] == proto.this_node
    assert len(proto._expected_pongs) == 1
    expected_pingid = proto._expected_pongs.keys()[0]
    assert len(expected_pingid) == 96
    echo = expected_pingid[:32]
    assert len(echo) == 32

    assert wire.messages == []

    # reply in time
    # can not check w/o mcd
    print 'sending pong'
    proto.recv_pong(eviction_candidate, echo)

    # expect no other messages
    assert wire.messages == []

    # expect node was not added
    assert node not in proto.routing
    # eviction_candidate is around and was promoted to bucket.tail
    assert eviction_candidate in proto.routing
    assert eviction_candidate == bucket.tail
    # expect node to be in the replacement_cache
    assert node in bucket.replacement_cache


@pytest.mark.timeout(5)
@pytest.mark.xfail
def test_eviction_node_inactive(proto):
    """
    active nodes (replying in time) should not be evicted
    """
    proto.routing = routing_table(10000)  # set high, so add won't split
    wire = proto.wire

    # get a full bucket
    full_buckets = [b for b in proto.routing.buckets if b.is_full and not b.should_split]
    assert full_buckets
    bucket = full_buckets[0]
    assert not bucket.should_split
    assert len(bucket) == kademlia.k_bucket_size
    bucket_nodes = bucket.nodes[:]
    eviction_candidate = bucket.head

    # manually set bonding successful
    eviction_candidate.ping_recv = eviction_candidate.pong_recv = True
    assert eviction_candidate.bonded

    # create node to insert
    node = random_node()
    assert not node.bonded

    # manually set bonding successful
    node.ping_recv = node.pong_recv = True
    assert node.bonded

    node.id = bucket.start + 1  # should not split
    assert bucket.in_range(node)
    assert bucket == proto.routing.bucket_by_node(node)

    # insert node
    proto.update(node)

    # expect bucket was not split
    assert len(bucket) == kademlia.k_bucket_size

    # expect bucket to be unchanged
    assert bucket_nodes == bucket.nodes
    assert eviction_candidate == bucket.head

    # expect node not to be in bucket yet
    assert node not in bucket
    assert node not in proto.routing

    # expect a ping to bucket.head
    msg = wire.poll(eviction_candidate)
    assert msg[0] == 'ping'
    assert msg[1] == proto.this_node
    assert len(proto._expected_pongs) == 1
    expected_pingid = proto._expected_pongs.keys()[0]
    assert len(expected_pingid) == 96
    echo = expected_pingid[:32]
    assert len(echo) == 32
    assert wire.messages == []

    # reply late
    gevent.sleep(kademlia.k_request_timeout)
    proto.recv_pong(eviction_candidate, echo)

    # expect no other messages
    assert wire.messages == []

    # expect node was not added
    assert node in proto.routing
    # eviction_candidate is around and was promoted to bucket.tail
    assert eviction_candidate not in proto.routing
    assert node == bucket.tail
    # expect node to be in the replacement_cache
    assert eviction_candidate not in bucket.replacement_cache


def test_eviction_node_split(proto):
    """
    active nodes (replying in time) should not be evicted
    """
    proto.routing = routing_table(1000)  # set lpw, so we'll split
    wire = proto.wire

    # get a full bucket
    full_buckets = [b for b in proto.routing.buckets if b.is_full and b.should_split]
    assert full_buckets
    bucket = full_buckets[0]
    assert bucket.should_split
    assert len(bucket) == kademlia.k_bucket_size
    bucket_nodes = bucket.nodes[:]
    eviction_candidate = bucket.head

    # manually set bonding successful
    eviction_candidate.ping_recv = eviction_candidate.pong_recv = True
    assert eviction_candidate.bonded

    # create node to insert
    node = random_node()
    node.id = bucket.start + 1  # should not split

    # manually set bonding successful
    node.ping_recv = node.pong_recv = True

    assert node.bonded
    assert bucket.in_range(node)
    assert bucket == proto.routing.bucket_by_node(node)

    # insert node
    proto.update(node)

    # expect bucket to be unchanged
    assert bucket_nodes == bucket.nodes
    assert eviction_candidate == bucket.head

    # expect node not to be in bucket yet
    assert node not in bucket
    assert node in proto.routing

    # expect no ping to bucket.head
    assert not wire.poll(eviction_candidate)
    assert wire.messages == []

    # expect node was not added
    assert node in proto.routing

    # eviction_candidate is around and was unchanged
    assert eviction_candidate == bucket.head


def test_ping_not_sufficient_to_add(proto):
    assert len(proto.routing) == 0
    for i in range(10):
        n = random_node()
        proto.recv_ping(n, 'some id %d' % i)
        assert n.ping_recv
        assert len(proto.routing) == 0


def test_ping_pong_adds_sender(proto):
    assert len(proto.routing) == 0
    for i in range(10):
        n = random_node()
        echo = hex(random.randint(0, 2 ** 256))[-32:]
        pingid = proto._mkpingid(echo, n)
        proto.recv_ping(n, pingid)
        proto.ping(n)

        pongid = filter(
            lambda exp: exp[1][1] == n,
            proto._expected_pongs.items()
                )[0][0][:32]

        proto.recv_pong(n, pongid)
        assert n.bonded
        assert len(proto.routing) == i + 1


@pytest.mark.parametrize('num_nodes', [2])
def test_two(protos):
    one, two = protos
    one.routing = routing_table(100)
    wire = one.wire
    assert one.this_node != two.this_node
    two.ping(one.this_node)
    # print 'messages', wire.messages
    wire.process([one, two])
    two.find_node(two.this_node.id)
    # print 'messages', wire.messages
    msg = wire.process([one, two], steps=2)
    # print 'messages', wire.messages
    assert len(wire.messages) >= kademlia.k_bucket_size
    msg = wire.messages.pop(0)
    assert msg[1] == 'find_node'
    for m in wire.messages[kademlia.k_find_concurrency:]:
        assert m[1] == 'ping'


@pytest.mark.parametrize('num_nodes', [17])
def test_many(protos):
    assert num_nodes >= kademlia.k_bucket_size + 1
    bootstrap = protos[0]
    wire = bootstrap.wire

    # bootstrap
    for num, p in enumerate(protos[1:]):
        print("bootstrapping {i} {node}".format(i=num, node=p.this_node))
        p.bootstrap([bootstrap.this_node])
        wire.process(protos)  # successively add nodes

    # now everbody does a find node to fill the buckets
    for p in protos[1:]:
        p.find_node(p.this_node.id)
        wire.process(protos)  # can all send in parallel

    for i, p in enumerate(protos):
        # print i, len(p.routing)
        assert len(p.routing) >= kademlia.k_bucket_size

    return protos


@pytest.mark.skip
@pytest.mark.parametrize('num_nodes', [50])
def test_find_closest(protos):
    """
    assert, that nodes find really the closest of all nodes
    """
    num_tests = 10
    all_nodes = [p.this_node for p in protos]
    for i, p in enumerate(protos[:num_tests]):
        for j, node in enumerate(all_nodes):
            if p.this_node == node:
                continue
            p.find_node(node.id)
            p.wire.process(protos)
            assert p.routing.neighbours(node)[0] == node


if __name__ == '__main__':
    import ethereum.slogging
    ethereum.slogging.configure(config_string=':debug')
    test_many()
