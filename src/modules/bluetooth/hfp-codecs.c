/***
  This file is part of PulseAudio.


  Copyright (C) 2019 Sathish Narasimman <sathish.narasimman@intel.com>
  Copyright (C) 2020 DSP Group

  PulseAudio is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.

  PulseAudio is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with PulseAudio; if not, see <http://www.gnu.org/licenses/>.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>
#include <errno.h>
#include <string.h>

#include "pulsecore/core-error.h"
#include "pulsecore/core-util.h"
#include "hfp-codecs.h"



/*
 * MSBC codec
 */

struct msbc_parser {
    size_t len;
    size_t frame_size;
    uint8_t *buffer;
};

struct msbc_info {
    sbc_t sbcenc;              /* Encoder data */
    sbc_t sbcdec;              /* Decoder data */
    struct {
        uint8_t *buf;
        size_t head;
        size_t tail;
        size_t head_chunk;
        size_t tail_chunk;
        size_t size;
    } ebuffer;
    size_t mtu;

    struct msbc_parser parser; /* mSBC parser for concatenating frames */

    size_t encoded_frame_size;
    size_t decoded_frame_size;

    struct {
        int enc, dec;
    } frame_count;

};

static const char sntable[4] = { 0x08, 0x38, 0xC8, 0xF8 };
/* Run from IO thread */
static void msbc_parser_reset(struct msbc_parser *p) {
    p->len = 0;
}

/* Run from IO thread */
static int msbc_state_machine(struct msbc_parser *p, uint8_t byte) {
    pa_assert(p->len < p->frame_size);

    switch (p->len) {
    case 0:
        if (byte == 0x01)
            goto copy;
        return 0;
    case 1:
        if (byte == 0x08 || byte == 0x38 || byte == 0xC8 || byte == 0xF8)
            goto copy;
        break;
    case 2:
        if (byte == 0xAD)
            goto copy;
        break;
    case 3:
        if (byte == 0x00)
            goto copy;
        break;
    case 4:
        if (byte == 0x00)
            goto copy;
        break;
    default:
        goto copy;
    }

    p->len = 0;
    return 0;
copy:
    p->buffer[p->len] = byte;
    p->len++;

    return p->len;
}


static bool msbc_can_accept_capabilities(const uint8_t *capabilities_buffer, uint8_t capabilities_size, bool for_encoding) {
    return false;
}

static const char *msbc_choose_remote_endpoint(const pa_hashmap *capabilities_hashmap, const pa_sample_spec *default_sample_spec, bool for_encoding) {
    return NULL;
}

static uint8_t msbc_fill_capabilities(uint8_t capabilities_buffer[MAX_A2DP_CAPS_SIZE]) {
    return 0;
}

static bool msbc_is_configuration_valid(const uint8_t *config_buffer, uint8_t config_size) {
    return false;
}

static uint8_t msbc_fill_preferred_configuration(const pa_sample_spec *default_sample_spec, const uint8_t *capabilities_buffer, uint8_t capabilities_size, uint8_t config_buffer[MAX_A2DP_CAPS_SIZE]) {
    return 0;
}

/* greater common divider */
static int gcd(int a, int b) {
    while(b) {
        int c = b;
        b = a % b;
        a = c;
    }
    return a;
}
/* least common multiple */
static int lcm(int a, int b) {
    return (a*b)/gcd(a,b);
}

#define MAX_MSBC_BUFSZ (2048)

static int msbc_init_ebuffer(struct msbc_info *msbc_info) {
    msbc_info->ebuffer.size = lcm(msbc_info->parser.frame_size, msbc_info->mtu);
    pa_assert(msbc_info->ebuffer.size > 0);
    pa_assert(msbc_info->ebuffer.size <= MAX_MSBC_BUFSZ);

    msbc_info->ebuffer.buf = pa_xmalloc(msbc_info->ebuffer.size);

    if (!msbc_info->ebuffer.buf) {
        pa_log_error("Failed to initialize mSBC encoder.");
        return -1;
    }

    msbc_info->ebuffer.head = 0;
    msbc_info->ebuffer.tail = 0;
    msbc_info->ebuffer.head_chunk = msbc_info->parser.frame_size;
    msbc_info->ebuffer.tail_chunk = msbc_info->mtu;
    return 0;
}

static void *msbc_init(bool for_encoding, bool for_backchannel, const uint8_t *config_buffer, uint8_t config_size, pa_sample_spec *sample_spec) {

    int ret;
    struct msbc_info *msbc_info;
    struct hf_config *hf_config = (struct hf_config*)config_buffer;

    sample_spec->format = PA_SAMPLE_S16LE;
    sample_spec->channels = 1;
    sample_spec->rate = 16000;

    pa_assert(config_size == sizeof(*hf_config));
    pa_assert(for_encoding);
    pa_assert(for_backchannel);

    msbc_info = pa_xnew0(struct msbc_info, 1);

    ret = sbc_init_msbc(&msbc_info->sbcenc, 0);
    if (ret != 0) {
        pa_xfree(msbc_info);
        pa_log_error("mSBC initialization failed: %d", ret);
        return NULL;
    }

    ret = sbc_init_msbc(&msbc_info->sbcdec, 0);
    if (ret != 0) {
        pa_xfree(msbc_info);
        pa_log_error("mSBC initialization failed: %d", ret);
        return NULL;
    }
    msbc_info->encoded_frame_size = sbc_get_frame_length(&msbc_info->sbcenc);
    msbc_info->decoded_frame_size = sbc_get_codesize(&msbc_info->sbcenc);
    msbc_parser_reset(&msbc_info->parser);

    /* header + payload + zero byte */
    msbc_info->parser.frame_size = 2 + msbc_info->encoded_frame_size + 1;
    msbc_info->parser.buffer = pa_xmalloc(msbc_info->parser.frame_size);
    pa_assert(msbc_info->parser.buffer);
    msbc_info->parser.len = 0;
    msbc_info->mtu = hf_config->mtu;

    if (msbc_init_ebuffer(msbc_info) == -1) {
        pa_xfree(msbc_info);
        pa_log_error("mSBC initialization failed.");
        return NULL;
    }
    return msbc_info;
}

static void msbc_deinit(void *codec_info) {

    struct msbc_info *msbc_info = (struct msbc_info*)codec_info;

    pa_assert(msbc_info);

    if (msbc_info->parser.buffer) {
        pa_xfree(msbc_info->parser.buffer);
        msbc_info->parser.buffer = NULL;
    }
    if (msbc_info->ebuffer.buf) {
        pa_xfree(msbc_info->ebuffer.buf);
        msbc_info->ebuffer.buf = NULL;
    }
    pa_xfree(msbc_info);
}

static int msbc_reset(void *codec_info) {

    struct msbc_info *msbc_info = (struct msbc_info*)codec_info;

    msbc_parser_reset(&msbc_info->parser);
    msbc_info->ebuffer.head = msbc_info->ebuffer.tail = 0;
    return 0;
}

static size_t msbc_get_block_size(void *codec_info, size_t link_mtu) {

    struct msbc_info *msbc_info = (struct msbc_info*)codec_info;
    return msbc_info->decoded_frame_size;
}

/*
 * mSBC encoded frame size is 60, typical mtu is 48.
 * Double buffer might be required to push out 2 * 48 data
 * to avoid conjestion.
 */
static size_t msbc_get_max_output_buffer_size(void *codec_info, size_t write_link_mtu) {
    return 2 * write_link_mtu;
}

static size_t msbc_reduce_encoder_bitrate(void *codec_info, size_t write_link_mtu) {

    return msbc_get_block_size(codec_info, write_link_mtu);
}

/* amount of data in buffer */
static size_t msbc_eb_size(struct msbc_info *msbc_info) {
    ssize_t s = (ssize_t)msbc_info->ebuffer.head - (ssize_t)msbc_info->ebuffer.tail;
    return (size_t)(s >= 0 ? s : (ssize_t)msbc_info->ebuffer.size - s);
}
/* amount of free space in buffer */
static size_t msbc_eb_space(struct msbc_info *msbc_info) {
    return msbc_info->ebuffer.size - msbc_eb_size(msbc_info);
}
/* free <tail chunk> amount of space in buffer */
static void msbc_eb_size_inc(struct msbc_info *msbc_info) {
    pa_assert(msbc_info->ebuffer.head_chunk <= msbc_eb_space(msbc_info));
    msbc_info->ebuffer.head =
        (msbc_info->ebuffer.head + msbc_info->ebuffer.head_chunk)
            % msbc_info->ebuffer.size;
}
/* claim <head chunk> amount of space in buffer */
static void msbc_eb_space_inc(struct msbc_info *msbc_info) {
    pa_assert(msbc_info->ebuffer.tail_chunk <= msbc_eb_size(msbc_info));
    msbc_info->ebuffer.tail =
        (msbc_info->ebuffer.tail + msbc_info->ebuffer.tail_chunk)
            % msbc_info->ebuffer.size;
}
/* return ptr to data */
static uint8_t *msbc_eb_head(struct msbc_info *msbc_info) {
    pa_assert(msbc_info->ebuffer.head < msbc_info->ebuffer.size);
    return &msbc_info->ebuffer.buf[msbc_info->ebuffer.head];
}
/* return ptr to free space */
static uint8_t *msbc_eb_tail(struct msbc_info *msbc_info) {
    pa_assert(msbc_info->ebuffer.tail < msbc_info->ebuffer.size);
    return &msbc_info->ebuffer.buf[msbc_info->ebuffer.tail];
}

static size_t _msbc_encode_buffer(void *codec_info, uint32_t timestamp, const uint8_t *input_buffer, size_t input_size, uint8_t *output_buffer, size_t output_size, size_t *processed) {

    static int sn = 0;
    ssize_t encoded, written = 0;
    uint8_t *out_ptr, *out_end;
    struct msbc_info *msbc_info = (struct msbc_info*)codec_info;

    pa_assert(input_buffer);
    pa_assert(output_buffer);
    pa_assert(output_size >= msbc_info->encoded_frame_size);

    out_ptr = output_buffer;
    out_end = output_buffer + output_size;
    *out_ptr++ = 0x01;
    *out_ptr++ = sntable[sn];
    sn = (sn + 1) % 4;

    encoded = sbc_encode(&msbc_info->sbcenc, input_buffer, input_size,
            out_ptr, (out_end - out_ptr), &written);

    if (PA_UNLIKELY(written <= 0)) {
        pa_log_error("Filed to encode SBC buffer: %ld", written);
        return -1;
    }
    out_ptr += written;
    *out_ptr++ = 0x0;
    written += 3;
    *processed = (size_t)encoded;
    msbc_info->frame_count.enc++;
    return out_ptr - output_buffer;
}

static size_t msbc_encode_buffer(void *codec_info, uint32_t timestamp, const uint8_t *input_buffer, size_t input_size, uint8_t *output_buffer, size_t output_size, size_t *processed) {

    uint8_t *eb;
    uint8_t *in_ptr, *in_end, *out_ptr, *out_end;
    size_t eb_size, copied_to_output, encoded;
    ssize_t written;
    struct msbc_info *msbc_info;

    msbc_info = (struct msbc_info*)codec_info;
    encoded = copied_to_output = *processed = 0;

    out_ptr = output_buffer;
    out_end = output_buffer + output_size;
    in_ptr = (uint8_t*)input_buffer;
    in_end = (uint8_t*)input_buffer + input_size;
    *processed = 0;

    while ((in_ptr < in_end) || encoded) {
        encoded = 0;
        /* step 1: write data from internal encoder buffer into output buffer
         * in mtu chunks */
        while ((msbc_eb_size(msbc_info) >= msbc_info->mtu)
                && ((size_t)(out_end - out_ptr) >= msbc_info->mtu)) {

            memcpy(out_ptr, msbc_eb_tail(msbc_info), msbc_info->mtu);
            msbc_eb_space_inc(msbc_info);
            out_ptr += msbc_info->mtu;
            copied_to_output += msbc_info->mtu;
        }
        /* step 2: encode audio into internal encoder buffer */
        if (in_ptr < in_end) {
            /* size may be 0 if there's no free space in the buffer */
            eb_size = msbc_eb_space(msbc_info);
            if (eb_size < msbc_info->parser.frame_size) {
                pa_log_debug("Not enough space in encoding buffer: %ld/%ld",
                        eb_size, msbc_info->parser.frame_size);
                break;
            }

            eb = msbc_eb_head(msbc_info);
            written = _msbc_encode_buffer(codec_info, 0, in_ptr, (in_end - in_ptr),
                    eb, eb_size, &encoded);

            if (written < 0)
                return -1;

            in_ptr += encoded;
            pa_assert(in_ptr <= in_end);
            msbc_eb_size_inc(msbc_info);
            *processed += encoded;
        }
        /* step 3: if encoded something, while loop will make one more iteration
         * and will attempt to write encoded data into output buffer
         */
    }
    return copied_to_output;
}

static size_t msbc_decode_buffer(void *codec_info, const uint8_t *input_buffer, size_t input_size, uint8_t *output_buffer, size_t output_size, size_t *processed) {

    ssize_t decoded;
    size_t written;
    uint8_t *input_ptr, *input_end, *output_ptr, *output_end;
    struct msbc_info *msbc_info = (struct msbc_info*)codec_info;

    input_ptr = (uint8_t*)input_buffer;
    input_end = (uint8_t*)input_buffer + input_size;
    output_ptr = (uint8_t*)output_buffer;
    output_end = (uint8_t*)output_buffer + output_size;
    *processed = 0;

    for (; input_ptr < input_end; input_ptr++) {
        if (msbc_state_machine(&msbc_info->parser, *input_ptr) !=
                (int)msbc_info->parser.frame_size) {
            continue;
        }
        pa_assert(output_ptr < output_end);

        written = 0;
        decoded = sbc_decode(&msbc_info->sbcdec,
                        msbc_info->parser.buffer + 2,
                        msbc_info->parser.len - 2 - 1,
                        output_ptr,
                        output_end - output_ptr,
                        &written);

        msbc_parser_reset(&msbc_info->parser);

        if (PA_UNLIKELY(decoded <= 0)) {
            pa_log_debug("Error while decoding: %ld\n", decoded);
            msbc_parser_reset(&msbc_info->parser);
            return -1;
        }
        /*count header and zero byte back. Encoder counts only sbc payoad.*/
        pa_assert(written == msbc_info->decoded_frame_size);
        output_ptr += written;
        pa_assert(output_ptr <= output_end);
        msbc_info->frame_count.dec++;
    }
    *processed = input_ptr - input_buffer;
    return output_ptr - output_buffer;
}

/*
 * CVSD "codec"
 */

static bool cvsd_can_accept_capabilities(const uint8_t *capabilities_buffer, uint8_t capabilities_size, bool for_encoding) {
    return false;
}

static const char *cvsd_choose_remote_endpoint(const pa_hashmap *capabilities_hashmap, const pa_sample_spec *default_sample_spec, bool for_encoding) {
    return NULL;
}

static uint8_t cvsd_fill_capabilities(uint8_t capabilities_buffer[MAX_A2DP_CAPS_SIZE]) {
    return 0;
}

static bool cvsd_is_configuration_valid(const uint8_t *config_buffer, uint8_t config_size) {
    return false;
}

static uint8_t cvsd_fill_preferred_configuration(const pa_sample_spec *default_sample_spec, const uint8_t *capabilities_buffer, uint8_t capabilities_size, uint8_t config_buffer[MAX_A2DP_CAPS_SIZE]) {
    return 0;
}

static void *cvsd_init(bool for_encoding, bool for_backchannel, const uint8_t *config_buffer, uint8_t config_size, pa_sample_spec *sample_spec) {

    sample_spec->format = PA_SAMPLE_S16LE;
    sample_spec->channels = 1;
    sample_spec->rate = 8000;

    return (void*)0x0c0dec;
 }

static void cvsd_deinit(void *codec_info) {
}

static int cvsd_reset(void *codec_info) {
    return 0;
}

static size_t cvsd_get_block_size(void *codec_info, size_t link_mtu) {
    return link_mtu;
}

static size_t cvsd_get_max_output_buffer_size(void *codec_info, size_t write_link_mtu) {
    return write_link_mtu;
}

static size_t cvsd_reduce_encoder_bitrate(void *codec_info, size_t write_link_mtu) {
    return write_link_mtu;
}

static size_t cvsd_encode_buffer(void *codec_info, uint32_t timestamp, const uint8_t *input_buffer, size_t input_size, uint8_t *output_buffer, size_t output_size, size_t *processed) {

    int to_copy = MIN(input_size, output_size);
    memcpy(output_buffer, input_buffer, to_copy);
    *processed = to_copy;
    return to_copy;
}

static size_t cvsd_decode_buffer(void *codec_info, const uint8_t *input_buffer, size_t input_size, uint8_t *output_buffer, size_t output_size, size_t *processed) {

    int to_copy = MIN(input_size, output_size);
    memcpy(output_buffer, input_buffer, to_copy);
    *processed = to_copy;
    return to_copy;
}



/*
 *
 */
const pa_bt_codec pa_hf_codec_msbc = {
    .name = "msbc",
    .description = "mSBC",
    .id = { HFP_AUDIO_CODEC_MSBC, 0, 0 },
    .support_backchannel = true,
    .can_accept_capabilities = msbc_can_accept_capabilities,
    .choose_remote_endpoint = msbc_choose_remote_endpoint,
    .fill_capabilities = msbc_fill_capabilities,
    .is_configuration_valid = msbc_is_configuration_valid,
    .fill_preferred_configuration = msbc_fill_preferred_configuration,
    .init = msbc_init,
    .deinit = msbc_deinit,
    .reset = msbc_reset,
    .get_read_block_size = msbc_get_block_size,
    .get_write_block_size = msbc_get_block_size,
    .get_max_output_buffer_size = msbc_get_max_output_buffer_size,
    .reduce_encoder_bitrate = msbc_reduce_encoder_bitrate,
    .encode_buffer = msbc_encode_buffer,
    .decode_buffer = msbc_decode_buffer,
};

const pa_bt_codec pa_hf_codec_cvsd = {
    .name = "cvsd",
    .description = "CVSD",
    .id = { HFP_AUDIO_CODEC_CVSD, 0, 0 },
    .support_backchannel = true,
    .can_accept_capabilities = cvsd_can_accept_capabilities,
    .choose_remote_endpoint = cvsd_choose_remote_endpoint,
    .fill_capabilities = cvsd_fill_capabilities,
    .is_configuration_valid = cvsd_is_configuration_valid,
    .fill_preferred_configuration = cvsd_fill_preferred_configuration,
    .init = cvsd_init,
    .deinit = cvsd_deinit,
    .reset = cvsd_reset,
    .get_read_block_size = cvsd_get_block_size,
    .get_write_block_size = cvsd_get_block_size,
    .get_max_output_buffer_size = cvsd_get_max_output_buffer_size,
    .reduce_encoder_bitrate = cvsd_reduce_encoder_bitrate,
    .encode_buffer = cvsd_encode_buffer,
    .decode_buffer = cvsd_decode_buffer,
};

const pa_bt_codec *hf_codec_from_id(int codec_id)
{
    const pa_bt_codec *codec = NULL;
    switch (codec_id) {
        case HFP_AUDIO_CODEC_CVSD:
            pa_log_debug("HFP codec: CVSD (%d)", codec_id);
            codec = &pa_hf_codec_cvsd;
            break;
        case HFP_AUDIO_CODEC_MSBC:
            pa_log_debug("HFP codec: MSBC (%d)", codec_id);
            codec = &pa_hf_codec_msbc;
            break;
        default:
            pa_log_error("Bad HFP codec: %d", codec_id);
            break;
    }

    return codec;
}
