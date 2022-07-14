from basic_datatypes import *

# RF4250,4.1.2
SSH_MSG_DISCONNECT = 1
SSH_MSG_DEBUG = 4
SSH_MSG_SERVICE_REQUEST = 5
SSH_MSG_SERVICE_ACCEPT = 6
SSH_MSG_KEXINIT = 20
SSH_MSG_NEWKEYS = 21
SSH_MSG_KEXDH_INIT = 30
SSH_MSG_KEXDH_REPLY = 31
SSH_MSG_USERAUTH_REQUEST = 50
SSH_MSG_USERAUTH_SUCCESS = 52
SSH_MSG_CHANNEL_OPEN = 90
SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91


class KexInit(Data):
    _identifier = SSH_MSG_KEXINIT
    _fields = OrderedDict(
                      cookie=Byte()*16,
                      kex_algorithms=NameList(),
                      server_host_key_algorithms=NameList(),
                      encryption_algorithms_client_to_server=NameList(),
                      encryption_algorithms_server_to_client=NameList(),
                      mac_algorithms_client_to_server=NameList(),
                      mac_algorithms_server_to_client=NameList(),
                      compression_algorithms_client_to_server=NameList(),
                      compression_algorithms_server_to_client=NameList(),
                      languages_algorithms_client_to_server=NameList(),
                      languages_algorithms_server_to_client=NameList(),
                      first_kex_packets_follows=Bool(),
                      reserved=Uint32())


class KexDHInit(Data):
    _identifier = SSH_MSG_KEXDH_INIT
    _fields = OrderedDict(
                      e=Mpint())


class KexDHReply(Data):
    _identifier = SSH_MSG_KEXDH_REPLY
    _fields = OrderedDict(
                      hostkey=String(),
                      f=Mpint(),
                      sig=String())

class PubKey(Data):
    _fields = OrderedDict(
                      keytype = String(),
                      e = Mpint(),
                      n = Mpint())


class Sig(Data):
    _fields = OrderedDict(sigtype=String(), sig=String())

class DataToHash(Data):
    _fields = OrderedDict(
                      V_C=String(),
                      V_S=String(),
                      I_C=String(),
                      I_S=String(),
                      K_S=String(),
                      e=Mpint(),
                      f=Mpint(),
                      K=Mpint())

class Debug(Data):
    _identifier = SSH_MSG_DEBUG
    _fields = OrderedDict(
                      always_display=Bool(),
                      message=String(),
                      lang=String())


class NewKeys(Data):
    _identifier = SSH_MSG_NEWKEYS
    _fields = {}


class ServiceRequest(Data):
    _identifier = SSH_MSG_SERVICE_REQUEST
    _fields = {'ServiceName':String()}


class ServiceAccept(Data):
    _identifier = SSH_MSG_SERVICE_ACCEPT
    _fields = {'ServiceName':String()}

class UserauthRequest(Data):
    _identifier = SSH_MSG_USERAUTH_REQUEST
    _fields = OrderedDict(
                      user=String(),
                      service=String(),
                      method=String())
    def _parse(this, p):
        t, p = super()._parse(p)
        if t.method.value == b'none':
            # Nothing more to parse
            pass
        else:
            assert False, "Unknown auth method: %s"%repr(t)
        return(t,p)

class UserauthSuccess(Data):
    _identifier = SSH_MSG_USERAUTH_SUCCESS
    _fields = {}

class ChannelOpen(Data):
    # RFC4254,5.1
    _identifier = SSH_MSG_CHANNEL_OPEN
    _fields = OrderedDict(
                      chann_type=String(),
                      sender=Uint32(),
                      window_size=Uint32(),
                      max_size=Uint32())
    def _parse(this, p):
        t, p = super()._parse(p)
        if t.chann_type.value == b'session':
            # Nothing more to parse
            pass
        else:
            assert False, "Unknown channel type: %s"%repr(t)
        return(t,p)

class ChannelOpenConfirm(Data):
    # RFC4254,5.1
    _identifier = SSH_MSG_CHANNEL_OPEN_CONFIRMATION
    _fields = OrderedDict(
                      recipient=Uint32(),
                      sender=Uint32(),
                      window_size=Uint32(),
                      max_size=Uint32())
    def _parse(this, p):
        t, p = super()._parse(p)
        if t.chann_type.value == b'session':
            # Nothing more to parse
            pass
        else:
            assert False, "Unknown channel type: %s"%repr(t)
        return(t,p)

class Disconnect(Data):
    # RFC4243,11.1
    _identifier = SSH_MSG_DISCONNECT
    _fields = OrderedDict(
                      reason_code = Uint32(),
                      description = String(),
                      lang = String())


tmp = [eval(d) for d in dir()]
packet_parsers = {e._identifier: e for e in tmp if hasattr(e, '_identifier')}
del tmp
