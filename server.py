import socket
import hashlib
import random
import struct

from datatypes import *
import hostkey

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


class HostKey(object):
	def __init__(this, n,e,d):
		assert pow(pow(1337,e,n),d,n) == 1337
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

class Transport(object):
	def __init__(this, addr=ADDR):
		this.mac_len = 0
		this.serv = None # Must be set for destructor to not complain
		this.conn = None
		this.remoteAddr = None

		# Keys as defined in RFC4253 7.2
		this.sess_id = None
		this.iv_cs = None
		this.iv_sc = None
		this.key_cs = None
		this.key_sc = None
		this.mac_key_cs = None
		this.mac_key_sc = None

		this.serv = socket.socket()
		for i in range(10):
			try:
				ai = socket.getaddrinfo(*addr)
				this.serv.bind(ai[0][-1])
				break
			except OSError as e:
				print(e)
				addr = (addr[0], addr[1]+1)
		else:
			assert False, "Could not bind port"
		print("Listening on", addr)
		this.serv.listen()

	def run(this):
		this.conn, this.remoteAddr = this.serv.accept()

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
		serverkex = KexInit(identifier=Byte(b'\x14'),
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
		reply = KexDHReply(identifier=Byte(SSH_MSG_KEXDH_REPLY),
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

		this.sendPacket(nkpacket.pack())

		this.iv_cs = HASH(b'A', 16)
		this.iv_sc = HASH(b'B', 16)
		this.key_cs = HASH(b'C', 16)
		this.key_sc = HASH(b'D', 16)
		this.mac_key_cs = HASH(b'E', 16)
		this.mac_key_sc = HASH(b'F', 16)

	def sendDebug(this, message):
		if message.__class__ is str:
			message = message.encode()
		d = Debug(identifier=Byte(SSH_MSG_DEBUG),
				always_display=Bool(True),
				message=String(message),
				lang=String(b''))
		this.sendPacket(d.pack())

	def recvuntil(this, target):
		retval = b''
		while not target in retval:
			retval += this.conn.recv(1)
		return retval

	def getPacket(this):
		packet_length, = struct.unpack('>I', this.conn.recv(4))
		packet = this.conn.recv(packet_length)
		if(this.mac_len > 0):
			mac = this.conn.recv(this.mac_len)

		padding_length = packet[0]
		payload = packet[1:-padding_length]

		return payload

	def sendPacket(this, payload):
		if payload.__class__ is not bytes:
			payload = payload.pack()
		block_len = 16
		min_padding = 4
		padding_len = min_padding + block_len - (min_padding + 5 + len(payload))%block_len
		padding = b'\x00'*padding_len
		packet_len = 1 + len(payload) + padding_len
		data = struct.pack('>IB', packet_len, padding_len) + payload + padding

		if this.mac_len != 0:
			raise NotImplementedError()

		this.conn.send(data)

	def __del__(this):
		print("Closing...")
		if not (this.conn is None):
			this.conn.close()
		this.serv.close()

	def parsePacket(this, p):
		packet_type = p[0]
		if packet_type in packet_parsers:
			retval = packet_parsers[packet_type]().parse(p)
			return retval
		else:
			assert False, "Unknown packet type for packet: %s"%repr(p)

t = Transport()
t.run()
