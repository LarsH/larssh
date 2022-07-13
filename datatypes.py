from basic_datatypes import *

SSH_MSG_DEBUG = 4
SSH_MSG_SERVICE_REQUEST = 5
SSH_MSG_KEXINIT = 20
SSH_MSG_NEWKEYS = 21
SSH_MSG_KEXDH_INIT = 30
SSH_MSG_KEXDH_REPLY = 31

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


tmp = [eval(d) for d in dir()]
packet_parsers = {e._identifier: e for e in tmp if hasattr(e, '_identifier')}
del tmp
