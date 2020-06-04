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

#include <pulsecore/log.h>
#include <pulsecore/macro.h>
#include <pulsecore/once.h>
#include <pulse/sample.h>

#include <arpa/inet.h>

#include <openaptx.h>

#include "a2dp-codecs.h"
#include "a2dp-codec-api.h"
#include "rtp.h"

struct aptx_hd_info {
    struct aptx_context *aptx_c;
    uint16_t seq_num;
};

static bool can_accept_capabilities_common(const a2dp_aptx_t *capabilities, uint32_t vendor_id, uint16_t codec_id) {
    if (A2DP_GET_VENDOR_ID(capabilities->info) != vendor_id || A2DP_GET_CODEC_ID(capabilities->info) != codec_id)
        return false;

    if (!(capabilities->frequency & (APTX_SAMPLING_FREQ_16000 | APTX_SAMPLING_FREQ_32000 |
                                     APTX_SAMPLING_FREQ_44100 | APTX_SAMPLING_FREQ_48000)))
        return false;

    if (!(capabilities->channel_mode & APTX_CHANNEL_MODE_STEREO))
        return false;

    return true;
}

static bool can_accept_capabilities(const uint8_t *capabilities_buffer, uint8_t capabilities_size, bool for_encoding) {
    const a2dp_aptx_t *capabilities = (const a2dp_aptx_t *) capabilities_buffer;

    if (capabilities_size != sizeof(*capabilities))
        return false;

    return can_accept_capabilities_common(capabilities, APTX_VENDOR_ID, APTX_CODEC_ID);
}

static bool can_accept_capabilities_hd(const uint8_t *capabilities_buffer, uint8_t capabilities_size, bool for_encoding) {
    const a2dp_aptx_hd_t *capabilities = (const a2dp_aptx_hd_t *) capabilities_buffer;

    if (capabilities_size != sizeof(*capabilities))
        return false;

    return can_accept_capabilities_common(&capabilities->aptx, APTX_HD_VENDOR_ID, APTX_HD_CODEC_ID);
}

static int cmp_endpoints_common(const a2dp_aptx_t *capabilities1, const a2dp_aptx_t *capabilities2, const pa_sample_spec *default_sample_spec, bool for_encoding) {
    uint32_t freq1 = 0;
    uint32_t freq2 = 0;
    int i;

    static const struct {
        uint32_t rate;
        uint8_t cap;
    } freq_table[] = {
        { 16000U, APTX_SAMPLING_FREQ_16000 },
        { 32000U, APTX_SAMPLING_FREQ_32000 },
        { 44100U, APTX_SAMPLING_FREQ_44100 },
        { 48000U, APTX_SAMPLING_FREQ_48000 }
    };

    /* Find the lowest freq that is at least as high as the requested sampling rate */
    for (i = 0; (unsigned)i < PA_ELEMENTSOF(freq_table); i++) {
        if (!freq1 && freq_table[i].rate >= default_sample_spec->rate && (capabilities1->frequency & freq_table[i].cap))
            freq1 = freq_table[i].rate;
        if (!freq2 && freq_table[i].rate >= default_sample_spec->rate && (capabilities2->frequency & freq_table[i].cap))
            freq2 = freq_table[i].rate;
        if (freq1 && freq2)
            break;
    }

    /* Prefer endpoint which frequency is near to default sample rate */
    if (freq1 && freq2) {
        if (freq1 < freq2)
            return -1;
        if (freq1 > freq2)
            return 1;
    } else if (freq1) {
        return freq1;
    } else if (freq2) {
        return freq2;
    } else {
        for (i = PA_ELEMENTSOF(freq_table)-1; i >= 0; i--) {
            if (capabilities1->frequency & freq_table[i].cap)
                freq1 = freq_table[i].rate;
            if (capabilities2->frequency & freq_table[i].cap)
                freq2 = freq_table[i].rate;
            if (freq1 && freq2)
                break;
        }
        pa_assert(i >= 0);

        if (freq1 > freq2)
            return -1;
        if (freq2 < freq1)
            return 1;
    }

    return 0;
}

static int cmp_endpoints(const uint8_t *capabilities1_buffer, uint8_t capabilities1_size, const uint8_t *capabilities2_buffer, uint8_t capabilities2_size, const pa_sample_spec *default_sample_spec, bool for_encoding) {
    pa_assert(capabilities1_size == sizeof(a2dp_aptx_t));
    pa_assert(capabilities2_size == sizeof(a2dp_aptx_t));
    return cmp_endpoints_common((const a2dp_aptx_t *)capabilities1_buffer, (const a2dp_aptx_t *)capabilities2_buffer, default_sample_spec, for_encoding);
}

static int cmp_endpoints_hd(const uint8_t *capabilities1_buffer, uint8_t capabilities1_size, const uint8_t *capabilities2_buffer, uint8_t capabilities2_size, const pa_sample_spec *default_sample_spec, bool for_encoding) {
    pa_assert(capabilities1_size == sizeof(a2dp_aptx_hd_t));
    pa_assert(capabilities2_size == sizeof(a2dp_aptx_hd_t));
    return cmp_endpoints_common(&((const a2dp_aptx_hd_t *)capabilities1_buffer)->aptx, &((const a2dp_aptx_hd_t *)capabilities2_buffer)->aptx, default_sample_spec, for_encoding);
}

static void fill_capabilities_common(a2dp_aptx_t *capabilities, uint32_t vendor_id, uint16_t codec_id) {
    capabilities->info = A2DP_SET_VENDOR_ID_CODEC_ID(vendor_id, codec_id);
    capabilities->channel_mode = APTX_CHANNEL_MODE_STEREO;
    capabilities->frequency = APTX_SAMPLING_FREQ_16000 | APTX_SAMPLING_FREQ_32000 |
                              APTX_SAMPLING_FREQ_44100 | APTX_SAMPLING_FREQ_48000;
}

static uint8_t fill_capabilities(uint8_t capabilities_buffer[MAX_A2DP_CAPS_SIZE]) {
    a2dp_aptx_t *capabilities = (a2dp_aptx_t *) capabilities_buffer;

    pa_zero(*capabilities);
    fill_capabilities_common(capabilities, APTX_VENDOR_ID, APTX_CODEC_ID);
    return sizeof(*capabilities);
}

static uint8_t fill_capabilities_hd(uint8_t capabilities_buffer[MAX_A2DP_CAPS_SIZE]) {
    a2dp_aptx_hd_t *capabilities = (a2dp_aptx_hd_t *) capabilities_buffer;

    pa_zero(*capabilities);
    fill_capabilities_common(&capabilities->aptx, APTX_HD_VENDOR_ID, APTX_HD_CODEC_ID);
    return sizeof(*capabilities);
}

static bool is_configuration_valid_common(const a2dp_aptx_t *config, uint32_t vendor_id, uint16_t codec_id) {
    if (A2DP_GET_VENDOR_ID(config->info) != vendor_id || A2DP_GET_CODEC_ID(config->info) != codec_id) {
        pa_log_error("Invalid vendor codec information in configuration");
        return false;
    }

    if (config->frequency != APTX_SAMPLING_FREQ_16000 && config->frequency != APTX_SAMPLING_FREQ_32000 &&
        config->frequency != APTX_SAMPLING_FREQ_44100 && config->frequency != APTX_SAMPLING_FREQ_48000) {
        pa_log_error("Invalid sampling frequency in configuration");
        return false;
    }

    if (config->channel_mode != APTX_CHANNEL_MODE_STEREO) {
        pa_log_error("Invalid channel mode in configuration");
        return false;
    }

    return true;
}

static bool is_configuration_valid(const uint8_t *config_buffer, uint8_t config_size) {
    const a2dp_aptx_t *config = (const a2dp_aptx_t *) config_buffer;

    if (config_size != sizeof(*config)) {
        pa_log_error("Invalid size of config buffer");
        return false;
    }

    return is_configuration_valid_common(config, APTX_VENDOR_ID, APTX_CODEC_ID);
}

static bool is_configuration_valid_hd(const uint8_t *config_buffer, uint8_t config_size) {
    const a2dp_aptx_hd_t *config = (const a2dp_aptx_hd_t *) config_buffer;

    if (config_size != sizeof(*config)) {
        pa_log_error("Invalid size of config buffer");
        return false;
    }

    return is_configuration_valid_common(&config->aptx, APTX_HD_VENDOR_ID, APTX_HD_CODEC_ID);
}

static bool fill_preferred_configuration_common(const pa_sample_spec *default_sample_spec, const a2dp_aptx_t *capabilities, a2dp_aptx_t *config, uint32_t vendor_id, uint16_t codec_id) {
    int i;

    static const struct {
        uint32_t rate;
        uint8_t cap;
    } freq_table[] = {
        { 16000U, APTX_SAMPLING_FREQ_16000 },
        { 32000U, APTX_SAMPLING_FREQ_32000 },
        { 44100U, APTX_SAMPLING_FREQ_44100 },
        { 48000U, APTX_SAMPLING_FREQ_48000 }
    };

    if (A2DP_GET_VENDOR_ID(capabilities->info) != vendor_id || A2DP_GET_CODEC_ID(capabilities->info) != codec_id) {
        pa_log_error("No supported vendor codec information");
        return false;
    }

    config->info = A2DP_SET_VENDOR_ID_CODEC_ID(vendor_id, codec_id);

    if (!(capabilities->channel_mode & APTX_CHANNEL_MODE_STEREO)) {
        pa_log_error("No supported channel modes");
        return false;
    }

    config->channel_mode = APTX_CHANNEL_MODE_STEREO;

    /* Find the lowest freq that is at least as high as the requested sampling rate */
    for (i = 0; (unsigned) i < PA_ELEMENTSOF(freq_table); i++) {
        if (freq_table[i].rate >= default_sample_spec->rate && (capabilities->frequency & freq_table[i].cap)) {
            config->frequency = freq_table[i].cap;
            break;
        }
    }

    if ((unsigned) i == PA_ELEMENTSOF(freq_table)) {
        for (--i; i >= 0; i--) {
            if (capabilities->frequency & freq_table[i].cap) {
                config->frequency = freq_table[i].cap;
                break;
            }
        }

        if (i < 0) {
            pa_log_error("Not suitable sample rate");
            return false;
        }
    }

    return true;
}

static uint8_t fill_preferred_configuration(const pa_sample_spec *default_sample_spec, const uint8_t *capabilities_buffer, uint8_t capabilities_size, uint8_t config_buffer[MAX_A2DP_CAPS_SIZE]) {
    a2dp_aptx_t *config = (a2dp_aptx_t *) config_buffer;
    const a2dp_aptx_t *capabilities = (const a2dp_aptx_t *) capabilities_buffer;

    if (capabilities_size != sizeof(*capabilities)) {
        pa_log_error("Invalid size of capabilities buffer");
        return 0;
    }

    pa_zero(*config);

    if (!fill_preferred_configuration_common(default_sample_spec, capabilities, config, APTX_VENDOR_ID, APTX_CODEC_ID))
        return 0;

    return sizeof(*config);
}

static uint8_t fill_preferred_configuration_hd(const pa_sample_spec *default_sample_spec, const uint8_t *capabilities_buffer, uint8_t capabilities_size, uint8_t config_buffer[MAX_A2DP_CAPS_SIZE]) {
    a2dp_aptx_hd_t *config = (a2dp_aptx_hd_t *) config_buffer;
    const a2dp_aptx_hd_t *capabilities = (const a2dp_aptx_hd_t *) capabilities_buffer;

    if (capabilities_size != sizeof(*capabilities)) {
        pa_log_error("Invalid size of capabilities buffer");
        return 0;
    }

    pa_zero(*config);

    if (!fill_preferred_configuration_common(default_sample_spec, &capabilities->aptx, &config->aptx, APTX_HD_VENDOR_ID, APTX_HD_CODEC_ID))
        return 0;

    return sizeof(*config);
}

static void *init_common(const a2dp_aptx_t *config, pa_sample_spec *sample_spec, int hd) {
    struct aptx_context *aptx_c;

    aptx_c = aptx_init(hd);
    if (!aptx_c) {
        pa_log_error("libopenaptx initialization failed");
        return NULL;
    }

    sample_spec->format = PA_SAMPLE_S24LE;

    switch (config->frequency) {
        case APTX_SAMPLING_FREQ_16000:
            sample_spec->rate = 16000U;
            break;
        case APTX_SAMPLING_FREQ_32000:
            sample_spec->rate = 32000U;
            break;
        case APTX_SAMPLING_FREQ_44100:
            sample_spec->rate = 44100U;
            break;
        case APTX_SAMPLING_FREQ_48000:
            sample_spec->rate = 48000U;
            break;
        default:
            pa_assert_not_reached();
    }

    switch (config->channel_mode) {
        case APTX_CHANNEL_MODE_STEREO:
            sample_spec->channels = 2;
            break;
        default:
            pa_assert_not_reached();
    }

    PA_ONCE_BEGIN {
#if OPENAPTX_MAJOR == 0 && OPENAPTX_MINOR == 0 && OPENAPTX_PATCH == 0
        /* libopenaptx version 0.0.0 does not export version global variables */
        pa_log_debug("Using aptX codec implementation: libopenaptx from https://github.com/pali/libopenaptx");
#else
        pa_log_debug("Using aptX codec implementation: libopenaptx %d.%d.%d from https://github.com/pali/libopenaptx", aptx_major, aptx_minor, aptx_patch);
#endif
    } PA_ONCE_END;

    return aptx_c;
}

static void *init(bool for_encoding, bool for_backchannel, const uint8_t *config_buffer, uint8_t config_size, pa_sample_spec *sample_spec) {
    const a2dp_aptx_t *config = (const a2dp_aptx_t *) config_buffer;

    pa_assert(config_size == sizeof(*config));
    pa_assert(!for_backchannel);

    return init_common(config, sample_spec, 0);
}

static void *init_hd(bool for_encoding, bool for_backchannel, const uint8_t *config_buffer, uint8_t config_size, pa_sample_spec *sample_spec) {
    struct aptx_hd_info *aptx_hd_info;
    const a2dp_aptx_hd_t *config = (const a2dp_aptx_hd_t *) config_buffer;

    pa_assert(config_size == sizeof(*config));
    pa_assert(!for_backchannel);

    aptx_hd_info = pa_xnew0(struct aptx_hd_info, 1);

    aptx_hd_info->aptx_c = init_common(&config->aptx, sample_spec, 1);
    if (!aptx_hd_info->aptx_c) {
        pa_xfree(aptx_hd_info);
        return NULL;
    }

    return aptx_hd_info;
}

static void deinit(void *codec_info) {
    struct aptx_context *aptx_c = (struct aptx_context *) codec_info;

    aptx_finish(aptx_c);
}

static void deinit_hd(void *codec_info) {
    struct aptx_hd_info *aptx_hd_info = (struct aptx_hd_info *) codec_info;

    deinit(aptx_hd_info->aptx_c);
    pa_xfree(aptx_hd_info);
}

static int reset(void *codec_info) {
    struct aptx_context *aptx_c = (struct aptx_context *) codec_info;

    aptx_reset(aptx_c);

#if OPENAPTX_MAJOR == 0 && OPENAPTX_MINOR >= 2
    aptx_decode_sync_finish(aptx_c);
#endif

    return 0;
}

static int reset_hd(void *codec_info) {
    struct aptx_hd_info *aptx_hd_info = (struct aptx_hd_info *) codec_info;

    reset(aptx_hd_info->aptx_c);
    aptx_hd_info->seq_num = 0;
    return 0;
}

static size_t get_read_block_size(void *codec_info, size_t link_mtu) {
    /* one aptX sample is 4 bytes long and decompress to four stereo 24 bit samples */
    size_t frame_count = (link_mtu / 4);

    /* due to synchronization support, libopenaptx may decode one additional frame */
    return (frame_count + 1) * 3 * 2 * 4;
}

static size_t get_write_block_size(void *codec_info, size_t link_mtu) {
    /* one aptX sample is 4 bytes long and decompress to four stereo 24 bit samples */
    size_t frame_count = (link_mtu / 4);

    return frame_count * 3 * 2 * 4;
}

static size_t get_read_block_size_hd(void *codec_info, size_t link_mtu) {
    /* one aptX HD sample is 6 bytes long and decompress to four stereo 24 bit samples */
    size_t rtp_size = sizeof(struct rtp_header);
    size_t frame_count = (link_mtu - rtp_size) / 6;

    /* due to synchronization support, libopenaptx may decode one additional frame */
    return (frame_count + 1) * 3 * 2 * 4;
}

static size_t get_write_block_size_hd(void *codec_info, size_t link_mtu) {
    /* one aptX HD sample is 6 bytes long and decompress to four stereo 24 bit samples */
    size_t rtp_size = sizeof(struct rtp_header);
    size_t frame_count = (link_mtu - rtp_size) / 6;

    return frame_count * 3 * 2 * 4;
}

static size_t reduce_encoder_bitrate(void *codec_info, size_t write_link_mtu) {
    return 0;
}

static size_t encode_buffer(void *codec_info, uint32_t timestamp, const uint8_t *input_buffer, size_t input_size, uint8_t *output_buffer, size_t output_size, size_t *processed) {
    struct aptx_context *aptx_c = (struct aptx_context *) codec_info;
    size_t written;

    *processed = aptx_encode(aptx_c, input_buffer, input_size, output_buffer, output_size, &written);
    if (PA_UNLIKELY(*processed == 0 || *processed != input_size))
        pa_log_error("aptX encoding error");

    return written;
}

static size_t encode_buffer_hd(void *codec_info, uint32_t timestamp, const uint8_t *input_buffer, size_t input_size, uint8_t *output_buffer, size_t output_size, size_t *processed) {
    struct aptx_hd_info *aptx_hd_info = (struct aptx_hd_info *) codec_info;
    struct rtp_header *header;
    size_t written;

    if (PA_UNLIKELY(output_size < sizeof(*header))) {
        *processed = 0;
        return 0;
    }

    written = encode_buffer(aptx_hd_info->aptx_c, timestamp, input_buffer, input_size, output_buffer + sizeof(*header), output_size - sizeof(*header), processed);

    if (PA_LIKELY(written > 0)) {
        header = (struct rtp_header *) output_buffer;
        pa_zero(*header);
        header->v = 2;
        header->pt = 96;
        header->sequence_number = htons(aptx_hd_info->seq_num++);
        header->timestamp = htonl(timestamp);
        header->ssrc = htonl(1);
        written += sizeof(*header);
    }

    return written;
}

static size_t decode_buffer(void *codec_info, const uint8_t *input_buffer, size_t input_size, uint8_t *output_buffer, size_t output_size, size_t *processed) {
    struct aptx_context *aptx_c = (struct aptx_context *) codec_info;
    size_t written;

#if OPENAPTX_MAJOR == 0 && OPENAPTX_MINOR >= 2
    int synced;
    size_t dropped;

    *processed = aptx_decode_sync(aptx_c, input_buffer, input_size, output_buffer, output_size, &written, &synced, &dropped);
    if (!synced)
        pa_log_warn("aptX decoding is failing");
    if (dropped)
        pa_log_warn("aptX decoder dropped %lu bytes", dropped);
#else
    *processed = aptx_decode(aptx_c, input_buffer, input_size, output_buffer, output_size, &written);
#endif

    /* Due to aptX latency, aptx_decode starts filling output buffer after 90 input samples.
     * If input buffer contains less than 90 samples, aptx_decode returns zero (=no output)
     * but set *processed to non zero as input samples were processed. So do not check for
     * return value of aptx_decode, zero is valid. Decoding error is indicating by fact that
     * not all input samples were processed. */
    if (PA_UNLIKELY(*processed != input_size))
        pa_log_error("aptX decoding error");

    return written;
}

static size_t decode_buffer_hd(void *codec_info, const uint8_t *input_buffer, size_t input_size, uint8_t *output_buffer, size_t output_size, size_t *processed) {
    struct aptx_hd_info *aptx_hd_info = (struct aptx_hd_info *) codec_info;
    struct rtp_header *header;
    size_t written;

    if (PA_UNLIKELY(input_size < sizeof(*header))) {
        *processed = 0;
        return 0;
    }

    header = (struct rtp_header *) input_buffer;
    written = decode_buffer(aptx_hd_info->aptx_c, input_buffer + sizeof(*header), input_size - sizeof(*header), output_buffer, output_size, processed);
    *processed += sizeof(*header);
    return written;
}

const pa_a2dp_codec pa_a2dp_codec_aptx = {
    .name = "aptx",
    .description = "aptX",
    .id = { A2DP_CODEC_VENDOR, APTX_VENDOR_ID, APTX_CODEC_ID },
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

const pa_a2dp_codec pa_a2dp_codec_aptx_hd = {
    .name = "aptx_hd",
    .description = "aptX HD",
    .id = { A2DP_CODEC_VENDOR, APTX_HD_VENDOR_ID, APTX_HD_CODEC_ID },
    .support_backchannel = false,
    .can_accept_capabilities = can_accept_capabilities_hd,
    .cmp_endpoints = cmp_endpoints_hd,
    .fill_capabilities = fill_capabilities_hd,
    .is_configuration_valid = is_configuration_valid_hd,
    .fill_preferred_configuration = fill_preferred_configuration_hd,
    .init = init_hd,
    .deinit = deinit_hd,
    .reset = reset_hd,
    .get_read_block_size = get_read_block_size_hd,
    .get_write_block_size = get_write_block_size_hd,
    .reduce_encoder_bitrate = reduce_encoder_bitrate,
    .encode_buffer = encode_buffer_hd,
    .decode_buffer = decode_buffer_hd,
};
