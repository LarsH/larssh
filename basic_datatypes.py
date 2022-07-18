import struct
from collections import OrderedDict


class Data(object):
	repeats = 1
	_fields = {"value": None}

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
		if hasattr(this, '_identifier'):
			identifier, data = Byte()._parse(data)
			assert identifier == this._identifier
		for name, datatype in this._fields.items():
			val, data = datatype._parse(data)
			klist.append(name)
			vlist.append(val)
		obj = this.__class__(**dict(zip(klist, vlist)))
		return obj, data

	def pack(this):
		retval = b''
		if hasattr(this, '_identifier'):
			retval += Byte(this._identifier).pack()
		for name in this._fields:
			retval += getattr(this, name).pack()
		return retval

	def __repr__(this):
		data = [n+'='+repr(getattr(this, n)) for n in this._fields if hasattr(this, n)]
		return this.__class__.__name__ + '(' + ', '.join(data) + ')'


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
	_fields = OrderedDict(value=bytes)
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
	_fields=OrderedDict(value=Data())

	def _parse(this, data):
		assert len(data) >= 4
		i, = struct.unpack('>I', data[:4])
		return Uint32(i), data[4:]

	def __repr__(this):
		return 'Uint32(%s)' % repr(this.value)

	def pack(this):
		return struct.pack('>I', this.value)


class Uint64(IntData):

	def _parse(this, data):
		assert len(data) >= 8
		i, = struct.unpack('>L', data[:8])
		return Uint32(i), data[8:]

	def __repr__(this):
		return 'Uint64(%s)' % repr(this.value)

	def pack(this):
		return struct.pack('>Q', this.value)


class Bool(Data):
	def _parse(this, data):
		tmp, data = Byte()._parse(data)
		return (Bool(tmp.value != b'\x00'), data)

	def pack(this):
		if this.value:
			return b'\x01'
		else:
			return b'\x00'


class String(Data):

	def _parse(this, data):
		length, data = Uint32()._parse(data)
		tmp, data = (Byte()*(length.value))._parse(data)
		return String(tmp.value), data

	def pack(this):
		return Uint32(len(this.value)).pack() + this.value


class Mpint(IntData):
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

	def _parse(this, data):
		s, data = String()._parse(data)
		if len(s.value) == 0:
			return NameList([]), data
		else:
			return NameList(s.value.split(b',')), data

	def pack(this):
		return String(b','.join(this.value)).pack()
