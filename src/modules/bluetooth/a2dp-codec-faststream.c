/***
  This file is part of PulseAudio.

  Copyright 2018-2019 Pali Rohár <pali.rohar@gmail.com>

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

#include <pulsecore/core-util.h>
#include <pulsecore/log.h>
#include <pulsecore/macro.h>
#include <pulsecore/once.h>
#include <pulse/sample.h>
#include <pulse/xmalloc.h>

#include <sbc/sbc.h>

#include "a2dp-codecs.h"
#include "a2dp-codec-api.h"

struct faststream_info {
    sbc_t sbc;                           /* Codec data */
    size_t codesize, frame_length;       /* SBC Codesize, frame_length. We simply cache those values here */
    bool is_microphone;
    uint8_t frequency;
};

static bool can_accept_capabilities(const uint8_t *capabilities_buffer, uint8_t capabilities_size, bool for_encoding) {
    const a2dp_faststream_t *capabilities = (const a2dp_faststream_t *) capabilities_buffer;

    if (capabilities_size != sizeof(*capabilities))
        return false;

    if (A2DP_GET_VENDOR_ID(capabilities->info) != FASTSTREAM_VENDOR_ID || A2DP_GET_CODEC_ID(capabilities->info) != FASTSTREAM_CODEC_ID)
        return false;

    if (!(capabilities->direction & FASTSTREAM_DIRECTION_SINK))
        return false;

    if (!(capabilities->sink_frequency & (FASTSTREAM_SINK_SAMPLING_FREQ_44100 | FASTSTREAM_SINK_SAMPLING_FREQ_48000)))
        return false;

    return true;
}

static bool can_accept_capabilities_mic(const uint8_t *capabilities_buffer, uint8_t capabilities_size, bool for_encoding) {
    const a2dp_faststream_t *capabilities = (const a2dp_faststream_t *) capabilities_buffer;

    if (!can_accept_capabilities(capabilities_buffer, capabilities_size, for_encoding))
        return false;

    if (!(capabilities->direction & FASTSTREAM_DIRECTION_SOURCE))
        return false;

    if (!(capabilities->source_frequency & FASTSTREAM_SOURCE_SAMPLING_FREQ_16000))
        return false;

    return true;
}

static int cmp_endpoints_common(const uint8_t *capabilities1_buffer, uint8_t capabilities1_size, const uint8_t *capabilities2_buffer, uint8_t capabilities2_size, const pa_sample_spec *default_sample_spec, bool for_encoding, bool with_mic) {
    const a2dp_faststream_t *capabilities1 = (const a2dp_faststream_t *) capabilities1_buffer;
    const a2dp_faststream_t *capabilities2 = (const a2dp_faststream_t *) capabilities2_buffer;
    bool cap1_has_mic = (capabilities1->direction & FASTSTREAM_DIRECTION_SOURCE);
    bool cap2_has_mic = (capabilities2->direction & FASTSTREAM_DIRECTION_SOURCE);
    bool cap1_has_freq_44100 = (capabilities1->sink_frequency & FASTSTREAM_SINK_SAMPLING_FREQ_44100);
    bool cap2_has_freq_44100 = (capabilities2->sink_frequency & FASTSTREAM_SINK_SAMPLING_FREQ_44100);
    bool cap1_has_freq_48000 = (capabilities1->sink_frequency & FASTSTREAM_SINK_SAMPLING_FREQ_48000);
    bool cap2_has_freq_48000 = (capabilities2->sink_frequency & FASTSTREAM_SINK_SAMPLING_FREQ_48000);

    pa_assert(capabilities1_size == sizeof(a2dp_faststream_t));
    pa_assert(capabilities2_size == sizeof(a2dp_faststream_t));

    /* Prefer endpoint which frequency is near to default sample rate */
    if (default_sample_spec->rate <= 44100) {
        if (cap1_has_freq_44100 && !cap2_has_freq_44100)
            return -1;
        if (!cap1_has_freq_44100 && cap2_has_freq_44100)
            return 1;
    } else {
        if (cap1_has_freq_48000 && !cap2_has_freq_48000)
            return -1;
        if (!cap1_has_freq_48000 && cap2_has_freq_48000)
            return 1;
    }

    /* Prefer endpoint without microphone when microphone is not used */
    if (!with_mic) {
        if (cap1_has_mic && !cap2_has_mic)
            return 1;
        if (!cap1_has_mic && cap2_has_mic)
            return -1;
    }

    return 0;
}

static int cmp_endpoints(const uint8_t *capabilities1_buffer, uint8_t capabilities1_size, const uint8_t *capabilities2_buffer, uint8_t capabilities2_size, const pa_sample_spec *default_sample_spec, bool for_encoding) {
    return cmp_endpoints_common(capabilities1_buffer, capabilities1_size, capabilities2_buffer, capabilities2_size, default_sample_spec, for_encoding, false);
}

static int cmp_endpoints_mic(const uint8_t *capabilities1_buffer, uint8_t capabilities1_size, const uint8_t *capabilities2_buffer, uint8_t capabilities2_size, const pa_sample_spec *default_sample_spec, bool for_encoding) {
    return cmp_endpoints_common(capabilities1_buffer, capabilities1_size, capabilities2_buffer, capabilities2_size, default_sample_spec, for_encoding, true);
}

static uint8_t fill_capabilities(uint8_t capabilities_buffer[MAX_A2DP_CAPS_SIZE]) {
    a2dp_faststream_t *capabilities = (a2dp_faststream_t *) capabilities_buffer;

    pa_zero(*capabilities);

    capabilities->info = A2DP_SET_VENDOR_ID_CODEC_ID(FASTSTREAM_VENDOR_ID, FASTSTREAM_CODEC_ID);
    capabilities->direction = FASTSTREAM_DIRECTION_SINK;
    capabilities->sink_frequency = FASTSTREAM_SINK_SAMPLING_FREQ_44100 | FASTSTREAM_SINK_SAMPLING_FREQ_48000;

    return sizeof(*capabilities);
}

static uint8_t fill_capabilities_mic(uint8_t capabilities_buffer[MAX_A2DP_CAPS_SIZE]) {
    a2dp_faststream_t *capabilities = (a2dp_faststream_t *) capabilities_buffer;

    pa_zero(*capabilities);

    fill_capabilities(capabilities_buffer);

    capabilities->direction |= FASTSTREAM_DIRECTION_SOURCE;
    capabilities->source_frequency = FASTSTREAM_SOURCE_SAMPLING_FREQ_16000;

    return sizeof(*capabilities);
}

static bool is_configuration_valid_common(const a2dp_faststream_t *config, uint8_t config_size) {
    uint8_t sink_frequency;

    if (config_size != sizeof(*config)) {
        pa_log_error("Invalid size of config buffer");
        return false;
    }

    if (A2DP_GET_VENDOR_ID(config->info) != FASTSTREAM_VENDOR_ID || A2DP_GET_CODEC_ID(config->info) != FASTSTREAM_CODEC_ID) {
        pa_log_error("Invalid vendor codec information in configuration");
        return false;
    }

    if (!(config->direction & FASTSTREAM_DIRECTION_SINK)) {
        pa_log_error("Invalid direction in configuration");
        return false;
    }

    sink_frequency = config->sink_frequency;

    /* Some headsets are buggy and set both 48 kHz and 44.1 kHz in
     * the config. In such situation trying to send audio at 44.1 kHz
     * results in choppy audio, so we have to assume that the headset
     * actually wants 48 kHz audio. */
    if (sink_frequency == (FASTSTREAM_SINK_SAMPLING_FREQ_44100 | FASTSTREAM_SINK_SAMPLING_FREQ_48000))
        sink_frequency = FASTSTREAM_SINK_SAMPLING_FREQ_48000;

    if (sink_frequency != FASTSTREAM_SINK_SAMPLING_FREQ_44100 && sink_frequency != FASTSTREAM_SINK_SAMPLING_FREQ_48000) {
        pa_log_error("Invalid sink sampling frequency in configuration");
        return false;
    }

    return true;
}

static bool is_configuration_valid(const uint8_t *config_buffer, uint8_t config_size) {
    const a2dp_faststream_t *config = (const a2dp_faststream_t *) config_buffer;

    if (!is_configuration_valid_common(config, config_size))
        return false;

    if (config->direction & FASTSTREAM_DIRECTION_SOURCE) {
        pa_log_error("Invalid direction in configuration");
        return false;
    }

    return true;
}

static bool is_configuration_valid_mic(const uint8_t *config_buffer, uint8_t config_size) {
    const a2dp_faststream_t *config = (const a2dp_faststream_t *) config_buffer;

    if (!is_configuration_valid_common(config, config_size))
        return false;

    if (!(config->direction & FASTSTREAM_DIRECTION_SOURCE)) {
        pa_log_error("Invalid direction in configuration");
        return false;
    }

    if (config->source_frequency != FASTSTREAM_SOURCE_SAMPLING_FREQ_16000) {
        pa_log_error("Invalid source sampling frequency in configuration");
        return false;
    }

    return true;
}

static uint8_t fill_preferred_configuration(const pa_sample_spec *default_sample_spec, const uint8_t *capabilities_buffer, uint8_t capabilities_size, uint8_t config_buffer[MAX_A2DP_CAPS_SIZE]) {
    a2dp_faststream_t *config = (a2dp_faststream_t *) config_buffer;
    const a2dp_faststream_t *capabilities = (const a2dp_faststream_t *) capabilities_buffer;
    int i;

    static const struct {
        uint32_t rate;
        uint8_t cap;
    } freq_table[] = {
        { 44100U, FASTSTREAM_SINK_SAMPLING_FREQ_44100 },
        { 48000U, FASTSTREAM_SINK_SAMPLING_FREQ_48000 }
    };

    if (capabilities_size != sizeof(*capabilities)) {
        pa_log_error("Invalid size of capabilities buffer");
        return 0;
    }

    pa_zero(*config);

    if (A2DP_GET_VENDOR_ID(capabilities->info) != FASTSTREAM_VENDOR_ID || A2DP_GET_CODEC_ID(capabilities->info) != FASTSTREAM_CODEC_ID) {
        pa_log_error("No supported vendor codec information");
        return 0;
    }

    config->info = A2DP_SET_VENDOR_ID_CODEC_ID(FASTSTREAM_VENDOR_ID, FASTSTREAM_CODEC_ID);

    /* Find the lowest freq that is at least as high as the requested sampling rate */
    for (i = 0; (unsigned) i < PA_ELEMENTSOF(freq_table); i++) {
        if (freq_table[i].rate >= default_sample_spec->rate && (capabilities->sink_frequency & freq_table[i].cap)) {
            config->sink_frequency = freq_table[i].cap;
            break;
        }
    }

    if ((unsigned) i == PA_ELEMENTSOF(freq_table)) {
        for (--i; i >= 0; i--) {
            if (capabilities->sink_frequency & freq_table[i].cap) {
                config->sink_frequency = freq_table[i].cap;
                break;
            }
        }

        if (i < 0) {
            pa_log_error("Not suitable sample rate");
            return 0;
        }
    }

    pa_assert((unsigned) i < PA_ELEMENTSOF(freq_table));

    if (!(capabilities->direction & FASTSTREAM_DIRECTION_SINK)) {
        pa_log_error("No sink support");
        return 0;
    }

    config->direction = FASTSTREAM_DIRECTION_SINK;

    return sizeof(*config);
}

static uint8_t fill_preferred_configuration_mic(const pa_sample_spec *default_sample_spec, const uint8_t *capabilities_buffer, uint8_t capabilities_size, uint8_t config_buffer[MAX_A2DP_CAPS_SIZE]) {
    a2dp_faststream_t *config = (a2dp_faststream_t *) config_buffer;
    const a2dp_faststream_t *capabilities = (const a2dp_faststream_t *) capabilities_buffer;

    if (fill_preferred_configuration(default_sample_spec, capabilities_buffer, capabilities_size, config_buffer) == 0)
        return 0;

    if (!(capabilities->direction & FASTSTREAM_DIRECTION_SOURCE)) {
        pa_log_error("No source support");
        return 0;
    }

    if (!(capabilities->source_frequency & FASTSTREAM_SOURCE_SAMPLING_FREQ_16000)) {
        pa_log_error("No suitable source sample rate");
        return 0;
    }

    config->direction |= FASTSTREAM_DIRECTION_SOURCE;
    config->source_frequency = FASTSTREAM_SOURCE_SAMPLING_FREQ_16000;

    return sizeof(*config);
}

static void set_params(struct faststream_info *faststream_info) {
    /* FastStream uses SBC codec with these fixed parameters */
    if (faststream_info->is_microphone) {
        faststream_info->sbc.mode = SBC_MODE_MONO;
        faststream_info->sbc.bitpool = 32;
    } else {
        faststream_info->sbc.mode = SBC_MODE_JOINT_STEREO;
        faststream_info->sbc.bitpool = 29;
    }

    faststream_info->sbc.frequency = faststream_info->frequency;
    faststream_info->sbc.blocks = SBC_BLK_16;
    faststream_info->sbc.subbands = SBC_SB_8;
    faststream_info->sbc.allocation = SBC_AM_LOUDNESS;
    faststream_info->sbc.endian = SBC_LE;

    faststream_info->codesize = sbc_get_codesize(&faststream_info->sbc);
    faststream_info->frame_length = sbc_get_frame_length(&faststream_info->sbc);

    /* Frame length for FastStream is zero-padded to even byte length
     * libsbc just pad frame length to an integral number of bytes */
    if (faststream_info->frame_length & 1)
        faststream_info->frame_length++;

    /* Frame length for FastStream is 72 always bytes */
    pa_assert(faststream_info->frame_length == 72);
}

static void *init(bool for_encoding, bool for_backchannel, const uint8_t *config_buffer, uint8_t config_size, pa_sample_spec *sample_spec) {
    struct faststream_info *faststream_info;
    const a2dp_faststream_t *config = (const a2dp_faststream_t *) config_buffer;
    int ret;

    pa_assert(config_size == sizeof(*config));

    faststream_info = pa_xnew0(struct faststream_info, 1);
    faststream_info->is_microphone = for_backchannel;

    ret = sbc_init(&faststream_info->sbc, 0);
    if (ret != 0) {
        pa_xfree(faststream_info);
        pa_log_error("SBC initialization failed: %d", ret);
        return NULL;
    }

    sample_spec->format = PA_SAMPLE_S16LE;

    if (faststream_info->is_microphone) {
        if (config->source_frequency == FASTSTREAM_SOURCE_SAMPLING_FREQ_16000) {
            faststream_info->frequency = SBC_FREQ_16000;
            sample_spec->rate = 16000U;
        } else {
            pa_assert_not_reached();
        }

        sample_spec->channels = 1;
    } else {
        uint8_t sink_frequency = config->sink_frequency;

        /* Some headsets are buggy and set both 48 kHz and 44.1 kHz in
         * the config. In such situation trying to send audio at 44.1 kHz
         * results in choppy audio, so we have to assume that the headset
         * actually wants 48 kHz audio. */
        if (sink_frequency == (FASTSTREAM_SINK_SAMPLING_FREQ_44100 | FASTSTREAM_SINK_SAMPLING_FREQ_48000))
            sink_frequency = FASTSTREAM_SINK_SAMPLING_FREQ_48000;

        if (sink_frequency == FASTSTREAM_SINK_SAMPLING_FREQ_48000) {
            faststream_info->frequency = SBC_FREQ_48000;
            sample_spec->rate = 48000U;
        } else if (config->sink_frequency == FASTSTREAM_SINK_SAMPLING_FREQ_44100) {
            faststream_info->frequency = SBC_FREQ_44100;
            sample_spec->rate = 44100U;
        } else {
            pa_assert_not_reached();
        }

        sample_spec->channels = 2;
    }

    set_params(faststream_info);

    pa_log_info("SBC parameters: allocation=%s, subbands=%u, blocks=%u, mode=%s bitpool=%u codesize=%u frame_length=%u",
                faststream_info->sbc.allocation ? "SNR" : "Loudness", faststream_info->sbc.subbands ? 8 : 4,
                (faststream_info->sbc.blocks+1)*4, faststream_info->sbc.mode == SBC_MODE_MONO ? "Mono" :
                faststream_info->sbc.mode == SBC_MODE_DUAL_CHANNEL ? "DualChannel" :
                faststream_info->sbc.mode == SBC_MODE_STEREO ? "Stereo" : "JointStereo",
                faststream_info->sbc.bitpool, (unsigned)faststream_info->codesize, (unsigned)faststream_info->frame_length);

    return faststream_info;
}

static void deinit(void *codec_info) {
    struct faststream_info *faststream_info = (struct faststream_info *) codec_info;

    sbc_finish(&faststream_info->sbc);
    pa_xfree(faststream_info);
}

static int reset(void *codec_info) {
    struct faststream_info *faststream_info = (struct faststream_info *) codec_info;
    int ret;

    ret = sbc_reinit(&faststream_info->sbc, 0);
    if (ret != 0) {
        pa_log_error("SBC reinitialization failed: %d", ret);
        return -1;
    }

    /* sbc_reinit() sets also default parameters, so reset them back */
    set_params(faststream_info);
    return 0;
}

static size_t get_read_block_size(void *codec_info, size_t read_link_mtu) {
    struct faststream_info *faststream_info = (struct faststream_info *) codec_info;
    size_t frame_count;

    if (read_link_mtu < 220)
        pa_log_error("Link MTU for FastStream codec is %u too small (need at least 220)", (unsigned)read_link_mtu);

    frame_count = read_link_mtu / faststream_info->frame_length;
    return frame_count * faststream_info->codesize;
}

static size_t get_write_block_size(void *codec_info, size_t write_link_mtu) {
    /* FastStream must fit into DM5 packet (220 bytes) so ensure that we never generate larger packet */
    return get_read_block_size(codec_info, (write_link_mtu > 220 ? 220 : write_link_mtu));
}

static size_t reduce_encoder_bitrate(void *codec_info, size_t write_link_mtu) {
    return 0;
}

static size_t encode_buffer(void *codec_info, uint32_t timestamp, const uint8_t *input_buffer, size_t input_size, uint8_t *output_buffer, size_t output_size, size_t *processed) {
    struct faststream_info *faststream_info = (struct faststream_info *) codec_info;
    uint8_t *d;
    const uint8_t *p;
    size_t to_write, to_encode;

    p = input_buffer;
    to_encode = input_size;

    d = output_buffer;
    to_write = output_size;

    while (PA_LIKELY(to_encode > 0 && to_write > 0)) {
        ssize_t written;
        ssize_t encoded;

        encoded = sbc_encode(&faststream_info->sbc, p, to_encode, d, (to_write & ~0x1), &written);

        if (PA_UNLIKELY(encoded <= 0)) {
            pa_log_error("SBC encoding error (%li)", (long) encoded);
            break;
        }

        if (PA_UNLIKELY(written < 0)) {
            pa_log_error("SBC encoding error (%li)", (long) written);
            break;
        }

        /* If necessary add zero padding to have frame size of even length */
        if (written & 1)
            d[written++] = 0;

        pa_assert_fp((size_t) encoded <= to_encode);
        pa_assert_fp((size_t) encoded == faststream_info->codesize);

        pa_assert_fp((size_t) written <= to_write);
        pa_assert_fp((size_t) written == faststream_info->frame_length);

        p += encoded;
        to_encode -= encoded;

        d += written;
        to_write -= written;
    }

    PA_ONCE_BEGIN {
        pa_log_debug("Using FastStream codec with SBC codec implementation: %s", pa_strnull(sbc_get_implementation_info(&faststream_info->sbc)));
    } PA_ONCE_END;

    *processed = p - input_buffer;
    return d - output_buffer;
}

static size_t decode_buffer(void *codec_info, const uint8_t *input_buffer, size_t input_size, uint8_t *output_buffer, size_t output_size, size_t *processed) {
    struct faststream_info *faststream_info = (struct faststream_info *) codec_info;
    const uint8_t *p;
    uint8_t *d;
    size_t to_write, to_decode;

    p = input_buffer;
    to_decode = input_size;

    d = output_buffer;
    to_write = output_size;

    while (PA_LIKELY(to_decode > 0 && to_write > 0)) {
        size_t written;
        ssize_t decoded;

        decoded = sbc_decode(&faststream_info->sbc, p, to_decode, d, to_write, &written);

        if (PA_UNLIKELY(decoded <= 0)) {
            pa_log_error("SBC decoding error (%li)", (long) decoded);
            break;
        }

        /* Frame size is of even length so process zero padding */
        if ((size_t)decoded < to_decode && (decoded & 1))
            decoded++;

        pa_assert_fp((size_t) decoded <= to_decode);
        pa_assert_fp((size_t) decoded == faststream_info->frame_length);

        pa_assert_fp((size_t) written <= to_write);
        pa_assert_fp((size_t) written == faststream_info->codesize);

        p += decoded;
        to_decode -= decoded;

        d += written;
        to_write -= written;
    }

    *processed = p - input_buffer;
    return d - output_buffer;
}

const pa_a2dp_codec pa_a2dp_codec_faststream = {
    .name = "faststream",
    .description = "FastStream (without microphone)",
    .id = { A2DP_CODEC_VENDOR, FASTSTREAM_VENDOR_ID, FASTSTREAM_CODEC_ID },
    .support_backchannel = false,
    .can_accept_capabilities = can_accept_capabilities,
    .cmp_endpoints = cmp_endpoints,
    .fill_capabilities = fill_capabilities,
    .is_configuration_valid = is_configuration_valid,
    .fill_preferred_configuration = fill_preferred_configuration,
    .init = init,
    .deinit = deinit,
    .reset = reset,
    .get_read_block_size = get_read_block_size,
    .get_write_block_size = get_write_block_size,
    .reduce_encoder_bitrate = reduce_encoder_bitrate,
    .encode_buffer = encode_buffer,
    .decode_buffer = decode_buffer,
};

const pa_a2dp_codec pa_a2dp_codec_faststream_mic = {
    .name = "faststream_mic",
    .description = "FastStream (with microphone)",
    .id = { A2DP_CODEC_VENDOR, FASTSTREAM_VENDOR_ID, FASTSTREAM_CODEC_ID },
    .support_backchannel = true,
    .can_accept_capabilities = can_accept_capabilities_mic,
    .cmp_endpoints = cmp_endpoints_mic,
    .fill_capabilities = fill_capabilities_mic,
    .is_configuration_valid = is_configuration_valid_mic,
    .fill_preferred_configuration = fill_preferred_configuration_mic,
    .init = init,
    .deinit = deinit,
    .reset = reset,
    .get_read_block_size = get_read_block_size,
    .get_write_block_size = get_write_block_size,
    .reduce_encoder_bitrate = reduce_encoder_bitrate,
    .encode_buffer = encode_buffer,
    .decode_buffer = decode_buffer,
};
