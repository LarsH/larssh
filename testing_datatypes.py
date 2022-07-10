from datatypes import *

assert String().parse(b'\x00\x00\x00\x07testing').value == b'testing'
assert String().parse(b'\x00\x00\x00\x00').value == b''
assert Uint32().parse(b'ABCD').value == 0x41424344
assert (Byte()*4).parse(b'asdf').value == b'asdf'
assert Byte(0x41) == b'A'

assert Mpint(0).pack() == b'\x00\x00\x00\x00'
assert Mpint(0x9a378f9b2e332a7).pack() == b'\x00\x00\x00\x08\t\xa3x\xf9\xb2\xe32\xa7'
assert Mpint(0x80).pack() == b'\x00\x00\x00\x02\x00\x80'
assert Mpint().parse(b'\x00\x00\x00\x02\x00\x80') == 0x80
assert Mpint(0x7f).pack() == b'\x00\x00\x00\x01\x7f'
assert Mpint(-0x80).pack() == b'\x00\x00\x00\x01\x80'
assert Mpint(-0x81).pack() == b'\x00\x00\x00\x02\xff\x7f'
assert Mpint(-0x1234).pack() == b'\x00\x00\x00\x02\xed\xcc'
assert Mpint(-0xdeadbeef).pack() == b'\x00\x00\x00\x05\xff!RA\x11'

test = b'\x14\xf1+\xc9\x8f\xc4\xcc?7\x9b\xeb\\\xd2\xdcR\xcd\xe9\x00\x00\x00\xf1curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-c\x00\x00\x01\xf4ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ecdsa-sha2-nistp256@openssh.com,ssh-ed25519,sk-ssh-ed25519@openssh.com,rsa-sha2-512,rsa-sha2-256,ssh-rsa\x00\x00\x00lchacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\x00\x00\x00lchacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\x00\x00\x00\xd5umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\x00\x00\x00\xd5umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\x00\x00\x00\x1anone,zlib@openssh.com,zlib\x00\x00\x00\x1anone,zlib@openssh.com,zlib\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
# test2 = KexInit(identifier=Byte(b'\x14'), cookie=Byte(b'\xf1+\xc9\x8f\xc4\xcc?7\x9b\xeb\\\xd2\xdcR\xcd\xe9'), kex_algorithms=NameList(value=[b'curve25519-sha256', b'curve25519-sha256@libssh.org', b'ecdh-sha2-nistp256', b'ecdh-sha2-nistp384', b'ecdh-sha2-nistp521', b'diffie-hellman-group-exchange-sha256', b'diffie-hellman-group16-sha512', b'diffie-hellman-group18-sha512', b'diffie-hellman-group14-sha256', b'ext-info-c']), server_host_key_algorithms=NameList(value=[b'ecdsa-sha2-nistp256-cert-v01@openssh.com', b'ecdsa-sha2-nistp384-cert-v01@openssh.com', b'ecdsa-sha2-nistp521-cert-v01@openssh.com', b'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com', b'ssh-ed25519-cert-v01@openssh.com', b'sk-ssh-ed25519-cert-v01@openssh.com', b'rsa-sha2-512-cert-v01@openssh.com', b'rsa-sha2-256-cert-v01@openssh.com', b'ssh-rsa-cert-v01@openssh.com', b'ecdsa-sha2-nistp256', b'ecdsa-sha2-nistp384', b'ecdsa-sha2-nistp521', b'sk-ecdsa-sha2-nistp256@openssh.com', b'ssh-ed25519', b'sk-ssh-ed25519@openssh.com', b'rsa-sha2-512', b'rsa-sha2-256', b'ssh-rsa']), encryption_algorithms_client_to_server=NameList(value=[b'chacha20-poly1305@openssh.com', b'aes128-ctr', b'aes192-ctr', b'aes256-ctr', b'aes128-gcm@openssh.com', b'aes256-gcm@openssh.com']), encryption_algorithms_server_to_client=NameList(value=[b'chacha20-poly1305@openssh.com', b'aes128-ctr', b'aes192-ctr', b'aes256-ctr', b'aes128-gcm@openssh.com', b'aes256-gcm@openssh.com']), mac_algorithms_client_to_server=NameList(value=[b'umac-64-etm@openssh.com', b'umac-128-etm@openssh.com', b'hmac-sha2-256-etm@openssh.com', b'hmac-sha2-512-etm@openssh.com', b'hmac-sha1-etm@openssh.com', b'umac-64@openssh.com', b'umac-128@openssh.com', b'hmac-sha2-256', b'hmac-sha2-512', b'hmac-sha1']), mac_algorithms_server_to_client=NameList(value=[b'umac-64-etm@openssh.com', b'umac-128-etm@openssh.com', b'hmac-sha2-256-etm@openssh.com', b'hmac-sha2-512-etm@openssh.com', b'hmac-sha1-etm@openssh.com', b'umac-64@openssh.com', b'umac-128@openssh.com', b'hmac-sha2-256', b'hmac-sha2-512', b'hmac-sha1']), compression_algorithms_client_to_server=NameList(value=[b'none', b'zlib@openssh.com', b'zlib']), compression_algorithms_server_to_client=NameList(value=[b'none', b'zlib@openssh.com', b'zlib']), languages_algorithms_client_to_server=NameList(value=[]), languages_algorithms_server_to_client=NameList(value=[]), first_kex_packets_follows=Bool(False), reserved=Uint32(0))
k = KexInit().parse(test)

assert test == k.pack()


s = '''
0000   1f 00 00 01 17 00 00 00 07 73 73 68 2d 72 73 61
0010   00 00 00 03 01 00 01 00 00 01 01 00 dc 87 59 85
0020   57 3d 2d cb 3e 15 19 46 6d 07 4e aa 36 79 b4 9d
0030   b3 36 2e 50 d1 f9 64 e1 95 e4 a7 0d d1 32 61 e8
0040   00 ad 66 a3 22 bd b9 08 a6 71 09 ab d3 50 59 71
0050   c3 e7 39 e3 0e 5a 52 59 44 cb 00 81 d6 cd f6 c3
0060   eb a4 3d 7c 86 34 08 20 15 ac af 5e 5d c0 b0 f5
0070   a8 33 16 fb db e7 d1 25 9a 07 55 e3 ae ab 32 81
0080   73 bf 77 d8 1e cd 0d 16 e2 58 4b 21 38 df 3d 96
0090   47 6d c2 03 54 b5 2c b6 8f 84 4c a0 0b 27 d4 5c
00a0   c6 79 59 f9 51 b5 42 18 b9 af 1b 13 11 87 48 dc
00b0   00 dc e1 fe a3 6d 9c d4 da 7a b4 b0 bb dd 0b 11
00c0   6e 8d 12 3d 33 76 da a8 38 f1 9e c5 52 9a c4 c2
00d0   74 d2 80 45 b3 a3 af 84 75 1c 0f db 6c 65 cc 89
00e0   5e f4 71 62 ea c4 cc 22 a7 72 2f 1b 87 1b 19 11
00f0   cc 2d 7d e0 30 ea 7d 4a 0e b2 50 41 11 bb 87 a1
0100   73 40 a3 d5 38 6c 96 a2 b4 a1 ec e7 bd fc 76 10
0110   09 f8 39 e7 7d 9a 72 63 02 e3 96 6f 00 00 01 01
0120   00 91 79 e1 04 a1 64 70 b6 8c 6a 02 69 b8 68 75
0130   77 3a 6a 7c f0 4d 0c 57 a6 66 7e b8 44 bf d9 d5
0140   4b 2e 60 a9 78 87 3b 8d 0c a2 51 8a 3d 63 de 9c
0150   be d9 21 ad 93 d7 14 ef e9 5b a1 b2 36 19 cf 29
0160   2b b3 ec ae 74 3e 22 65 1b fd 8d 15 b6 74 dc d9
0170   1b ad c2 5a 1d ce da 8c e8 0b 38 65 6e c3 13 75
0180   f5 aa bb d6 93 16 eb e0 d0 f2 75 27 24 90 b4 f6
0190   a9 a2 50 33 70 a9 f4 52 0a 5d 46 26 2a 27 95 d0
01a0   57 ca ba 93 a2 e1 c2 c1 39 6f c4 09 3b 5e 67 d0
01b0   b1 5c 47 e3 b2 03 ee 45 67 cf fa 82 d7 f9 f8 f1
01c0   89 79 58 f7 73 87 d2 47 d7 da 2d b6 df f0 a3 6b
01d0   e8 3c 7f 32 b3 27 be 11 1b 59 0e 23 8f f4 c8 82
01e0   2b 0d 6f 6b 55 32 29 e8 fc d9 4b d3 c0 7d 2b e4
01f0   d1 f2 94 2b 3d 20 92 cf 22 24 f5 c0 01 bf 0c e8
0200   ee 09 62 e7 c6 90 56 fb 38 d7 52 67 e2 c4 83 c5
0210   d1 cd 05 45 8b cd 28 05 c6 de d1 0b ab de 34 e4
0220   c9 00 00 01 14 00 00 00 0c 72 73 61 2d 73 68 61
0230   32 2d 32 35 36 00 00 01 00 a7 e3 6f 0e 1f 62 14
0240   6a 5d 44 db 3f 44 c1 ff a2 55 e0 92 ee c0 be e9
0250   26 a5 0d 3b 32 7c 0b 6f 3b 3d a2 ef 34 3d 57 c2
0260   d8 86 3a 18 9b c4 cd e4 b9 2e bc dd 7f 43 3f 69
0270   30 3b 6b cb a1 9b 72 e9 e6 f3 6a 21 79 00 29 0b
0280   bb f7 f2 13 c0 1f c4 ba d1 76 9e 97 ba 77 1e a4
0290   46 54 a1 94 67 f4 c6 27 2f a4 4e ed e7 af 99 01
02a0   ce 5d 97 0d d9 e9 e5 a9 57 d9 9f 7d b3 1e d0 de
02b0   d6 8c c5 ef b6 ee 4a c8 8a bf 05 ff 27 93 1d 7c
02c0   d5 ad 28 8a a0 6c 61 f0 bd 84 08 c9 3d 24 7e 14
02d0   53 86 2b 44 0a c2 a1 24 a0 c8 8b f0 2b b9 de ea
02e0   ec 44 74 ad c4 93 ba 29 a4 d2 01 e2 8c 8e 84 52
02f0   af 6c c4 1e c4 2d ea 2e 91 a5 6e ea a2 ad dc 4a
0300   d9 f1 7b 84 dc 69 84 71 c2 3f ce 19 9c 1a 9e df
0310   7f e5 bc a0 26 bf d3 ca 58 3f ca 02 50 23 4f 9b
0320   60 b9 9c a5 7b e5 07 51 82 fd 3c 54 2c e1 bb 77
0330   68 28 74 c3 3b 52 04 f4 58
'''
msg = bytes.fromhex(''.join(''.join(l.split()[1:]) for l in s.split('\n')))
dhreply = KexDHReply().parse(msg)
pk = PubKey().parse(dhreply.hostkey.value)
sig = Sig().parse(dhreply.sig.value)
val = int.from_bytes(sig.sig.value,'big')
x = pow(val, pk.e.value, pk.n.value)
print(hex(x))

print(pk)
print(sig)
