import struct
from collections import namedtuple


def createDesc(name, **kwargs):
	keys = []
	values = []
	for k, v in kwargs.items():
		keys.append(k)
		values.append(v())
	return namedtuple(name, keys)(*values)


class Data(object):
	desc = createDesc('DataBaseClass')
	repeats = 1

	def __init__(this, value=None, **kwargs):
		if value is not None:
			setattr(this, 'value', value)
		for k, v in kwargs.items():
			setattr(this, k, v)

	def parse(this, p):
		tmp, r = this._parse(p)
		assert r == b'', "Could not parse all data: %s" % repr((p, r))
		return tmp

	def _parse(this, data):
		klist = []
		vlist = []
		for name, datatype in zip(this.desc._fields, this.desc):
			val, data = datatype._parse(data)
			klist.append(name)
			vlist.append(val)
		obj = this.__class__(**dict(zip(klist, vlist)))
		if hasattr(obj, '_identifier'):
			assert obj.identifier == obj._identifier, \
				repr((obj.identifier, obj._identifier))
		return obj, data

	def pack(this):
		retval = b''
		for name in this.desc._fields:
			retval += getattr(this, name).pack()
		return retval

	def __repr__(this):
		data = [getattr(this, n) for n in this.desc._fields]
		return repr(this.desc.__class__(*data))

	def __call__(this):
		'''For cases when repeated object is already instanciated'''
		return this


class IntData(Data):
	def __eq__(this, other):
		ot = other.__class__
		if this.value is bytes:
			if ot is bytes:
				return this.value == other
			elif len(this.value) == 1:
				return this.value[0] == other
		elif ot in [Data, Uint32, Uint64, Mpint]:
			return this.value == other.value
		elif ot is int:
			return this.value == other
		else:
			raise TypeError(repr((this, other)))


class Byte(IntData):
	desc = createDesc('Byte', value=bytes)
	size = 1
	value = b''

	def __init__(this, value=b''):
		if value.__class__ is int:
			value = bytes([value])
		this.value = value

	def _parse(this, p):
		assert len(p) >= this.size, "Not enough data " + \
			"to parse %u bytes: %s" % (this.size, len(p))

		return Byte(p[:this.size]), p[this.size:]

	def __mul__(this, val):
		this.size *= val
		return this

	def __repr__(this):
		return 'Byte(%s)' % repr(this.value)

	def pack(this):
		return this.value

	def __eq__(this, other):
		ot = other.__class__
		if ot is int and len(this.value) == 1:
			return other == this.value[0]
		elif ot is Byte:
			return this.value == other.value
		elif ot is bytes:
			return this.value == other
		else:
			raise TypeError(repr((this, other)))


class Uint32(IntData):
	desc = createDesc('Uint32', value=Data)

	def _parse(this, data):
		assert len(data) >= 4
		i, = struct.unpack('>I', data[:4])
		return Uint32(i), data[4:]

	def __repr__(this):
		return 'Uint32(%s)' % repr(this.value)

	def pack(this):
		return struct.pack('>I', this.value)


class Uint64(IntData):
	desc = createDesc('Uint64', value=Data)

	def _parse(this, data):
		assert len(data) >= 8
		i, = struct.unpack('>L', data[:8])
		return Uint32(i), data[8:]

	def __repr__(this):
		return 'Uint64(%s)' % repr(this.value)

	def pack(this):
		return struct.pack('>L', this.value)


class Bool(Data):
	desc = createDesc('Bool', value=Data)

	def _parse(this, data):
		tmp, data = Byte()._parse(data)
		return (Bool(tmp.value != b'\x00'), data)

	def __repr__(this):
		return 'Bool(%s)' % repr(this.value)

	def pack(this):
		if this.value:
			return b'\x01'
		else:
			return b'\x00'


class String(Data):
	desc = createDesc('String', value=str)

	def _parse(this, data):
		length, data = Uint32()._parse(data)
		tmp, data = (Byte()*(length.value))._parse(data)
		return String(tmp.value), data

	def __repr__(this):
		return 'String(%s)' % repr(this.value)

	def pack(this):
		return Uint32(len(this.value)).pack() + this.value


class Mpint(IntData):
	desc = createDesc('Mpint', value=Data)

	def pack(this):
		def bit_length(x):
			x = abs(x)
			i = 0
			while (1 << i) <= x:
				i += 1
			return i

		if this.value == 0:
			return b'\x00'*4
		elif this.value > 0:
			bytelen = (bit_length(this.value) // 8) + 1
			val = this.value
		else:
			pval = -this.value-1
			bytelen = (bit_length(pval) // 8) + 1
			val = (1<<(8*bytelen)) - (1+pval)
		return String(val.to_bytes(bytelen, 'big')).pack()

	def _parse(this, data):
		content, data = String()._parse(data)
		content = content.value
		if len(content) == 0:
			return Mpint(0), data

		isPositive = (content[0] & 0x80) == 0

		val = int.from_bytes(content, 'big')
		if not isPositive:
			val -= (1<<(8*len(content)))

		return Mpint(val), data

class NameList(Data):
	desc = createDesc('NameList', value=Data)

	def _parse(this, data):
		s, data = String()._parse(data)
		if len(s.value) == 0:
			return NameList([]), data
		else:
			return NameList(s.value.split(b',')), data

	def pack(this):
		return String(b','.join(this.value)).pack()


SSH_MSG_KEXINIT = 20


class KexInit(Data):
	_identifier = SSH_MSG_KEXINIT
	desc = createDesc('KexInit',
		identifier=Byte,
		cookie=Byte()*16,
		kex_algorithms=NameList,
		server_host_key_algorithms=NameList,
		encryption_algorithms_client_to_server=NameList,
		encryption_algorithms_server_to_client=NameList,
		mac_algorithms_client_to_server=NameList,
		mac_algorithms_server_to_client=NameList,
		compression_algorithms_client_to_server=NameList,
		compression_algorithms_server_to_client=NameList,
		languages_algorithms_client_to_server=NameList,
		languages_algorithms_server_to_client=NameList,
		first_kex_packets_follows=Bool,
		reserved=Uint32)



tmp = [eval(d) for d in dir()]
packet_parsers = {e._identifier:e for e in tmp if hasattr(e,'_identifier')}
del tmp

