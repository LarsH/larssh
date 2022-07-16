import socket
import hashlib
import random
import struct
from ucryptolib import aes
import uio
import uos
import _thread
import sys

from datatypes import *
import hostkey
from sftp import SFTP

IDSTRING = b'SSH-2.0-pyssh'
ADDR = ('0.0.0.0', 2222)

# This is an ASN.1 header indicating that the 32 bytes following
# it is a sha-256 hash
SHA256_prefix = b'010\r\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x00\x04 '

def diffie_hellman_group_14(e):
	# RFC3526, section 3
	p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
	g = 2

	y = 0
	for _ in range(2048//32):
		y <<= 32
		y += random.getrandbits(32)

	f = pow(g, y, p)
	K = pow(e, y, p)
	return f, K

def hmac(key, data):
	assert len(key) == 32 # RFC6668+2 says keylen for sha256 is 32 bytes
	key = key + b'\x00'*32 # padded key is 64 bytes
	i = bytes(c^0x36 for c in key)
	o = bytes(c^0x5c for c in key)
	tmp = hashlib.sha256(i + data).digest()
	return hashlib.sha256(o + tmp).digest()


class HostKey(object):
	def __init__(this, n,e,d):
		# assert pow(pow(1337,e,n),d,n) == 1337
		assert (1<<2047) < n < (1<<2048)
		this.len = 2048
		this.n = n
		this.e = e
		this.d = d

	def pubkey(this):
		return PubKey(keytype=String(b'ssh-rsa'),
				e = Mpint(this.e),
				n = Mpint(this.n))

	def sign(this, data):
		bytelen = this.len//8
		# rfc2313 Section 8.1
		padlen = bytelen - len(data) - 3
		data = b'\x00\x01' + b'\xff'*padlen + b'\x00' + data


		m = int.from_bytes(data,'big')
		c = pow(m,this.d,this.n)
		return Sig(sigtype=String(b'rsa-sha2-256'), sig=String(c.to_bytes(this.len//8,'big')))

HOST_KEY = HostKey(hostkey.n, hostkey.e, hostkey.d)

class Terminal(uio.IOBase):
	def __init__(this, writeFunc):
		this.inputFromClient = b''
		this.writeFunc = writeFunc

	def write(this, data):
		this.writeFunc(bytes(data).replace(b'\n',b'\r\n'))

	def read(this, l=None):
		if len(this.inputFromClient) == 0:
			return None
		if l is None:
			l = len(this.inputFromClient)
		tmp = this.inputFromClient[:l]
		this.inputFromClient = this.inputFromClient[l:]
		return tmp

	def readinto(this, buf):
		l = len(this.inputFromClient)
		if l == 0:
			return None
		l = min(l, len(buf))

		buf[:l] = this.inputFromClient[:l]
		this.inputFromClient = this.inputFromClient[l:]
		return l


class Shell():
	def __init__(this, terminal):
		this.terminal = terminal

	def interact(this, data):
		this.terminal.inputFromClient += data
		shouldClose = False
		return b'', shouldClose


class Session():
	def __init__(this, sender, window_size, max_size):
		this.sender = sender
		this.window_size = window_size
		this.max_size = max_size
		this.endpoint = None

	def request(this, req, **kwargs):
		t = req.req_type.value
		if t == b'env':
			# ignoring environment variables
			return False
		elif t == b'pty-req':
			# ignoring pseudo terminals
			return False
		elif t == b'shell':
			if this.endpoint == None:
				this.endpoint = Shell(kwargs['terminal'])
				return True
			else:
				# Already allocated an endpoint
				return False
		elif t == b'subsystem':
			if this.endpoint == None:
				this.endpoint = SFTP()
				return True
		else:
			print("Unknown request:", req)

		return False

	def data(this, data):
		if this.endpoint == None:
			print("No endpoint, ignoring data:", data)
			return b'', False
		else:
			return this.endpoint.interact(data)


class Transport(object):
	def __init__(this, conn):
		this.mac_len = 0
		this.conn = conn
		this.sess_id = None

		this.sc_aes = None
		this.cs_aes = None

		this.mac_key_cs = None
		this.mac_key_sc = None

		this.cs_packet_count = 0
		this.sc_packet_count = 0

		this.channels = []


	def run(this):
		# We received a connection, sending our ID string
		# RFC4253 Section 4.2
		this.conn.send(IDSTRING + b'\r\n')
		# receive the client ID string
		client_id = this.recvuntil(b'\n').replace(b'\r\n',b'')

		# Now, recieve the key exchange packet
		data = this.getPacket()
		p = this.parsePacket(data)
		I_C = String(p.pack())

		cookie = bytes(random.getrandbits(8) for _ in range(16))
		serverkex = KexInit(
				cookie=Byte(cookie),
				kex_algorithms=NameList(value=[b'diffie-hellman-group14-sha256']),
				server_host_key_algorithms=NameList(value=[b'rsa-sha2-256']),
				encryption_algorithms_client_to_server=NameList(value=[b'aes128-ctr']),
				encryption_algorithms_server_to_client=NameList(value=[b'aes128-ctr']),
				mac_algorithms_client_to_server=NameList(value=[b'hmac-sha2-256']),
				mac_algorithms_server_to_client=NameList(value=[b'hmac-sha2-256']),
				compression_algorithms_client_to_server=NameList(value=[b'none']),
				compression_algorithms_server_to_client=NameList(value=[b'none']),
				languages_algorithms_client_to_server=NameList(value=[]),
				languages_algorithms_server_to_client=NameList(value=[]),
				first_kex_packets_follows=Bool(False),
				reserved=Uint32(0))
		this.sendPacket(serverkex)

		# RFC4253 Section8. Diffie-Hellman key exchange
		data = this.getPacket()
		clientKex = this.parsePacket(data)
		assert clientKex.__class__ is KexDHInit, clientKex

		f, K = map(Mpint, diffie_hellman_group_14(clientKex.e.value))

		K_S=String(HOST_KEY.pubkey().pack())
		tmp = DataToHash(V_C=String(client_id),
				V_S=String(IDSTRING),
				I_C=I_C,
				I_S=String(serverkex.pack()),
				K_S=K_S,
				e=clientKex.e,
				f=f,
				K=K)
		H = hashlib.sha256(tmp.pack()).digest()

		if this.sess_id is None:
			# RFC4253 7.2: first exchange hash is session id
			this.sess_id = H

		# Must be hashed again before signing, paragraph before RFC4253 8.1
		signature = HOST_KEY.sign(SHA256_prefix + hashlib.sha256(H).digest())
		reply = KexDHReply(
				hostkey=K_S,
				f=f,
				sig=String(signature.pack()))

		this.sendPacket(reply)

		data = this.getPacket()
		nkpacket = this.parsePacket(data)
		assert nkpacket.__class__ is NewKeys, nkpacket

		# Creating the encryption keys as defined in RFC4253 7.2
		def HASH(x, l):
			retval = hashlib.sha256(K.pack() + H + x + this.sess_id).digest()
			while len(retval) < l:
				retval += hashlib.sha256(K.pack() + H + retval).digest()
			return retval[:l]

		this.sendPacket(nkpacket)

		iv_cs = HASH(b'A', 16)
		iv_sc = HASH(b'B', 16)
		key_cs = HASH(b'C', 16)
		key_sc = HASH(b'D', 16)
		this.mac_key_cs = HASH(b'E', 32)
		this.mac_key_sc = HASH(b'F', 32)
		this.mac_len = 32

		# AES CTR mode is somewhat undocumented in micropython
		this.sc_aes = aes(key_sc, 6, iv_sc)
		this.cs_aes = aes(key_cs, 6, iv_cs)

		tmp = this.getPacket()
		serviceReq = this.parsePacket(tmp)

		this.sendPacket(ServiceAccept(ServiceName=serviceReq.ServiceName))
		tmp = this.getPacket()
		packet = this.parsePacket(tmp)
		this.sendPacket(UserauthSuccess()) # Accepting any auth attempt

		while packet._identifier != SSH_MSG_DISCONNECT:
			tmp = this.getPacket()
			packet = this.parsePacket(tmp)

			if packet._identifier == SSH_MSG_CHANNEL_OPEN:
				idx = len(this.channels)
				s = Session(packet.sender.value,
						packet.window_size.value,
						packet.max_size.value)
				this.channels.append(s)
				r = ChannelOpenConfirm(recipient=Uint32(idx),
						sender=packet.sender,
						window_size=Uint32(s.window_size),
						max_size=Uint32(s.max_size))
				this.sendPacket(r)

			elif packet._identifier == SSH_MSG_CHANNEL_REQUEST:
				channel = packet.recipient.value
				term = None
				if packet.req_type.value == b'shell':
					def wfunc(x):
						this.sendPacket(ChannelData(recipient=Uint32(channel),data=String(x)))
					term = Terminal(wfunc)
					uos.dupterm(term)
				wasSuccess = this.channels[channel].request(packet,terminal=term)
				if packet.wantReply.value:
					c = Uint32(channel)
					if wasSuccess:
						pkt = ChannelSuccess(recipient=c)
					else:
						pkt = ChannelFailure(recipient=c)
					this.sendPacket(pkt)

			elif packet._identifier == SSH_MSG_CHANNEL_DATA:
				r = packet.recipient.value
				c = this.channels[r]
				data = packet.data.value

				packet.data.value, shouldClose  = c.data(data)
				if len(packet.data.value) > 0:
					packet.recipient.value = c.sender
					this.sendPacket(packet)
				if shouldClose:
					this.sendPacket(ChannelClose(recipient=Uint32(r)))
			else:
				print(packet._identifier)
				print(packet)


	def sendDebug(this, message):
		if message.__class__ is str:
			message = message.encode()
		d = Debug(
				always_display=Bool(True),
				message=String(message),
				lang=String(b''))
		this.sendPacket(d.pack())

	def recvuntil(this, target):
		retval = b''
		while not target in retval:
			retval += this.conn.recv(1)
		return retval

	def recvExactly(this, target):
		retval = b''
		while len(retval) < target:
			retval += this.conn.recv(target-len(retval))
		return retval

	def getPacket(this):
		lenbuf = this.recvExactly(4)
		if this.cs_aes is not None:
			lenbuf = this.cs_aes.decrypt(lenbuf)
		packet_length, = struct.unpack('>I', lenbuf)

		packet = this.recvExactly(packet_length)
		if this.cs_aes is not None:
			packet = this.cs_aes.decrypt(packet)

		if(this.mac_len > 0):
			mac = this.recvExactly(this.mac_len)
			t = this.cs_packet_count.to_bytes(4,'big')
			cmac = hmac(this.mac_key_cs, t+lenbuf+packet)
			assert mac == cmac

		padding_length = packet[0]
		payload = packet[1:-padding_length]
		this.cs_packet_count += 1

		return payload

	def sendPacket(this, payload):
		payload = payload.pack()
		block_len = 16
		min_padding = 4
		padding_len = min_padding + block_len - (min_padding + 5 + len(payload))%block_len
		padding = b'\x00'*padding_len
		packet_len = 1 + len(payload) + padding_len
		data = struct.pack('>IB', packet_len, padding_len) + payload + padding

		if this.mac_len != 0:
			t = this.sc_packet_count.to_bytes(4,'big')
			mac = hmac(this.mac_key_sc, t + data)
		else:
			mac = b''

		if this.sc_aes is not None:
			data = this.sc_aes.encrypt(data)

		this.conn.send(data + mac)
		this.sc_packet_count += 1

	def __del__(this):
		this.conn.close()

	def parsePacket(this, p):
		packet_type = p[0]
		if packet_type in packet_parsers:
			retval = packet_parsers[packet_type]().parse(p)
			return retval
		else:
			assert False, "Unknown packet type %u for packet: %s"%(p[0] , repr(p))

def server_thread_func(addr, port):
	serv = socket.socket()

	ai = socket.getaddrinfo(addr, port)
	serv.bind(ai[0][-1])

	serv.listen()

	while True:
		clientSock, _ = serv.accept()
		t = Transport(clientSock)
		_thread.start_new_thread(t.run,())

def startServer(addr='0.0.0.0',port=22):
	_thread.start_new_thread(server_thread_func, (addr,port))
