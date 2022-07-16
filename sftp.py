import struct

class SFTP():
	def __init__(this):
		this.buf = b''

	def interact(this, data):
		shouldClose = False
		reply = b''

		this.buf += data

		# https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02
		while True:
			if len(this.buf) < 5:
				break

			l = int.from_bytes(data[:4],'big')
			if len(this.buf) < (4+l):
				break

			t = this.buf[4]
			content = this.buf[5:4+l]
			this.buf = this.buf[4+l:]
			print("SFTP:", t, content)
			if t == 1:
				# SSH_FXP_INIT
				reply += struct.pack(">IBI", 5, 2, 3)
			else:
				print("Unhandled packet")
				shouldClose = True

		return reply, shouldClose
