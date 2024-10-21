import re
from pwn import *

with open('sunshine.log', 'r') as fp:
    RAW_LOG = fp.read()

# https://games-on-whales.github.io/wolf/dev-fake-uinput/protocols/index.html

# UDP
# 68:59765 RAISE VIDEO RTP+H264/HEVC, unencrypt
# 68:65516 :: AUDIO RTP+OPUS AES-CBC128 encrypt

'''
  struct video_packet_raw_t {
    uint8_t *
    payload() {
      return (uint8_t *) (this + 1);
    }

    RTP_PACKET rtp;
    char reserved[4];

    NV_VIDEO_PACKET packet;
  };

  typedef struct _NV_VIDEO_PACKET {
    uint32_t streamPacketIndex;
    uint32_t frameIndex;
    uint8_t flags;
    uint8_t reserved;
    uint8_t multiFecFlags;
    uint8_t multiFecBlocks;
    uint32_t fecInfo;
} NV_VIDEO_PACKET, *PNV_VIDEO_PACKET;

struct video_short_frame_header_t {
    uint8_t *
    payload() {
      return (uint8_t *) (this + 1);
    }

    std::uint8_t headerType;  // Always 0x01 for short headers

    // Sunshine extension
    // Frame processing latency, in 1/10 ms units
    //     zero when the frame is repeated or there is no backend implementation
    boost::endian::little_uint16_at frame_processing_latency;

    // Currently known values:
    // 1 = Normal P-frame
    // 2 = IDR-frame
    // 4 = P-frame with intra-refresh blocks
    // 5 = P-frame after reference frame invalidation
    std::uint8_t frameType;

    // Length of the final packet payload for codecs that cannot handle
    // zero padding, such as AV1 (Sunshine extension).
    boost::endian::little_uint16_at lastPayloadLen;

    std::uint8_t unknown[2];
  };

afterwards are raw H264
'''

rtp_bin = b''
frames = []
with open('rtp.out', 'r') as fp:
    while l := fp.readline().strip():

        raw_pack = bytes.fromhex(l)

        stream_pak_ind = u32(raw_pack[0:4])
        frame_ind = u32(raw_pack[4:8])
        flag4 = u32(raw_pack[8:12])
        fecinfo = u32(raw_pack[12:16])

        other_payload = raw_pack[16:]
        if len(frames) < frame_ind:
            frames.append(b'')

        frames[frame_ind - 1] += other_payload
        if other_payload.startswith(b'\x01'):
            rtp_bin += other_payload[8:]
        else:
            rtp_bin += other_payload[0:]
            
        

# for iframe, frame in enumerate(frames):
#     '''frame: video short frame header
#     '''
#     assert frame[0] == 1, iframe
#     frame_type = frame[3]
#     lastpayload_len = u16(frame[4:6])

#     raw_payload = frame[8:]



# print(rtp_bin.__len__())

with open('rtp.h264', 'wb') as fp:
    fp.write(rtp_bin)

# flag{BigBrotherIsWatchingYou!!}

