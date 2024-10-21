import re
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# from log
# moonlight-common-c AudioStream.c, RtspConnection.c
# session->audio.avRiKeyId = util::endian::big(*(std::uint32_t *) launch_session.iv.data());
# uint32_t ivSeq = BE32(avRiKeyId + rtp->sequenceNumber);
rikey = bytes.fromhex('F3CB8CFA676D563BBEBFC80D3943F10A')
rikeyid = 1485042510
assert len(rikey) == 16

opus_bin = b''
opus_paks = []
with open('audio.out', 'r') as fp:
    while l := fp.readline().strip():
        fec_head = ''
        raw_pack = bytes.fromhex(l)
        # extract rtp head
        rtp_head, raw_pack = raw_pack[:12], raw_pack[12:]
        # rtp seq:
        rtp_seq:int = u16(rtp_head[2:4], endianness='big')
        
        if len(raw_pack) == 128 + 12:
            # FEC pack with 12B head
            fec_head, raw_pack = raw_pack[:12], raw_pack[12:]

        # try that key
        IV = (rikeyid + rtp_seq).to_bytes(4, 'big') + b'\x00' * 12
        KEY = rikey

        ciph = AES.new(key=rikey, mode=AES.MODE_CBC, iv=IV)
        try_dec = ciph.decrypt(raw_pack)

        if not fec_head:
            # assert opus_bin.endswith(b'')
            opus_bin += unpad(try_dec, 16)
            opus_paks += [unpad(try_dec, 16)]
            assert try_dec.endswith(b'\x08' * 8)

            # if rtp_seq < 20:
            #     print(f"{rtp_seq = } {IV.hex() = } {KEY = } {try_dec[-16:] = }")

print(opus_paks[0])
with open('audio.opus', 'wb') as fp:
    fp.write(opus_bin)

with open('audio.opus.b64', 'wb') as fp:
    for pak in opus_paks:
        fp.write(base64.b64encode(pak) + b'\n')
# https://github.com/zkry/opus-packet-decoder
os.system('./opus-packet-decoder -f ./audio.opus.b64 -o audio.pcm')

os.system('ffmpeg -y -f s16le -ar 16k -i audio.pcm -ss 00:00:12 audio.wav')

# 2825628257282931