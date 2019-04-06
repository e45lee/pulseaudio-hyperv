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

#include <arpa/inet.h>

#include <sbc/sbc.h>

#include "a2dp-codecs.h"
#include "a2dp-codec-api.h"
#include "rtp.h"

/* Below are capabilities tables for different qualities. Order of capabilities in tables are from the most preferred to the least preferred. */

#define FIXED_SBC_CAPS(mode, freq, bitpool) { .channel_mode = (mode), .frequency = (freq), .min_bitpool = (bitpool), .max_bitpool = (bitpool), .allocation_method = SBC_ALLOCATION_LOUDNESS, .subbands = SBC_SUBBANDS_8, .block_length = SBC_BLOCK_LENGTH_16 }

/* SBC Low Quality, Joint Stereo is same as FastStream's SBC codec configuration, Mono was calculated to match Joint Stereo */
static const a2dp_sbc_t sbc_lq_caps_table[] = {
    FIXED_SBC_CAPS(SBC_CHANNEL_MODE_JOINT_STEREO, SBC_SAMPLING_FREQ_44100, 29), /* 195.7 kbps */
    FIXED_SBC_CAPS(SBC_CHANNEL_MODE_JOINT_STEREO, SBC_SAMPLING_FREQ_48000, 29), /* 213   kbps */
    FIXED_SBC_CAPS(SBC_CHANNEL_MODE_MONO,         SBC_SAMPLING_FREQ_44100, 15), /* 104.7 kbps */
    FIXED_SBC_CAPS(SBC_CHANNEL_MODE_MONO,         SBC_SAMPLING_FREQ_48000, 15), /* 114   kbps */
};

/* SBC Middle Quality, based on A2DP spec: Recommended sets of SBC parameters */
static const a2dp_sbc_t sbc_mq_caps_table[] = {
    FIXED_SBC_CAPS(SBC_CHANNEL_MODE_JOINT_STEREO, SBC_SAMPLING_FREQ_44100, SBC_BITPOOL_MQ_JOINT_STEREO_44100), /* bitpool = 35, 228.8 kbps */
    FIXED_SBC_CAPS(SBC_CHANNEL_MODE_JOINT_STEREO, SBC_SAMPLING_FREQ_48000, SBC_BITPOOL_MQ_JOINT_STEREO_48000), /* bitpool = 33, 237   kbps */
    FIXED_SBC_CAPS(SBC_CHANNEL_MODE_MONO,         SBC_SAMPLING_FREQ_44100, SBC_BITPOOL_MQ_MONO_44100),         /* bitpool = 19, 126.8 kbps */
    FIXED_SBC_CAPS(SBC_CHANNEL_MODE_MONO,         SBC_SAMPLING_FREQ_48000, SBC_BITPOOL_MQ_MONO_48000),         /* bitpool = 18, 132   kbps */
};

/* SBC High Quality, based on A2DP spec: Recommended sets of SBC parameters */
static const a2dp_sbc_t sbc_hq_caps_table[] = {
    FIXED_SBC_CAPS(SBC_CHANNEL_MODE_JOINT_STEREO, SBC_SAMPLING_FREQ_44100, SBC_BITPOOL_HQ_JOINT_STEREO_44100), /* bitpool = 53, 328   kbps */
    FIXED_SBC_CAPS(SBC_CHANNEL_MODE_JOINT_STEREO, SBC_SAMPLING_FREQ_48000, SBC_BITPOOL_HQ_JOINT_STEREO_48000), /* bitpool = 51, 345   kbps */
    FIXED_SBC_CAPS(SBC_CHANNEL_MODE_MONO,         SBC_SAMPLING_FREQ_44100, SBC_BITPOOL_HQ_MONO_44100),         /* bitpool = 31, 192.9 kbps */
    FIXED_SBC_CAPS(SBC_CHANNEL_MODE_MONO,         SBC_SAMPLING_FREQ_48000, SBC_BITPOOL_HQ_MONO_48000),         /* bitpool = 29, 210   kbps */
};

/* SBC eXtreme Quality, calculated to minimize wasted bytes and to be below max possible 512 kbps */
static const a2dp_sbc_t sbc_xq1_caps_table[] = {
    FIXED_SBC_CAPS(SBC_CHANNEL_MODE_JOINT_STEREO, SBC_SAMPLING_FREQ_44100, 76), /* 454.8 kbps */
    FIXED_SBC_CAPS(SBC_CHANNEL_MODE_JOINT_STEREO, SBC_SAMPLING_FREQ_48000, 76), /* 495   kbps */
    FIXED_SBC_CAPS(SBC_CHANNEL_MODE_STEREO,       SBC_SAMPLING_FREQ_44100, 76), /* 452   kbps */
    FIXED_SBC_CAPS(SBC_CHANNEL_MODE_STEREO,       SBC_SAMPLING_FREQ_48000, 76), /* 492   kbps */
};
static const a2dp_sbc_t sbc_xq2_caps_table[] = {
    FIXED_SBC_CAPS(SBC_CHANNEL_MODE_DUAL_CHANNEL, SBC_SAMPLING_FREQ_44100, 38), /* 452   kbps */
    FIXED_SBC_CAPS(SBC_CHANNEL_MODE_DUAL_CHANNEL, SBC_SAMPLING_FREQ_48000, 38), /* 492   kbps */
    FIXED_SBC_CAPS(SBC_CHANNEL_MODE_MONO,         SBC_SAMPLING_FREQ_44100, 37), /* 226   kbps */
    FIXED_SBC_CAPS(SBC_CHANNEL_MODE_MONO,         SBC_SAMPLING_FREQ_48000, 37), /* 246   kbps */
};
/* In most cases bluetooth headsets would support only sbc dual channel mode
 * for 2 channels as they have limited maximal bitpool value to 53.
 * We need to define it in two tables to disallow invalid combination of
 * joint stereo with bitpool 38 which is not XQ. */

#undef FIXED_SBC_CAPS

/* SBC Auto Quality, only one row which allow any possible configuration up to common High Quality */
/* We need to ensure that bitrate is below max possible 512 kbps, therefore limit configuration to High Quality */
static const a2dp_sbc_t sbc_auto_caps_table[] = { {
    .channel_mode = SBC_CHANNEL_MODE_MONO | SBC_CHANNEL_MODE_DUAL_CHANNEL | SBC_CHANNEL_MODE_STEREO | SBC_CHANNEL_MODE_JOINT_STEREO,
    .frequency = SBC_SAMPLING_FREQ_16000 | SBC_SAMPLING_FREQ_32000 | SBC_SAMPLING_FREQ_44100 | SBC_SAMPLING_FREQ_48000,
    .allocation_method = SBC_ALLOCATION_SNR | SBC_ALLOCATION_LOUDNESS,
    .subbands = SBC_SUBBANDS_4 | SBC_SUBBANDS_8,
    .block_length = SBC_BLOCK_LENGTH_4 | SBC_BLOCK_LENGTH_8 | SBC_BLOCK_LENGTH_12 | SBC_BLOCK_LENGTH_16,
    .min_bitpool = SBC_MIN_BITPOOL,
    .max_bitpool = SBC_BITPOOL_HQ_JOINT_STEREO_44100,
} };

/* Bitpool limits and steps for reducing bitrate in Auto Quality mode */
#define SBC_SEPARATE_BITPOOL_DEC_LIMIT 10
#define SBC_COMBINED_BITPOOL_DEC_LIMIT 25
#define SBC_SEPARATE_BITPOOL_DEC_STEP   2
#define SBC_COMBINED_BITPOOL_DEC_STEP   4

struct sbc_info {
    sbc_t sbc;                           /* Codec data */
    size_t codesize, frame_length;       /* SBC Codesize, frame_length. We simply cache those values here */
    uint16_t seq_num;                    /* Cumulative packet sequence */
    uint8_t frequency;
    uint8_t blocks;
    uint8_t subbands;
    uint8_t mode;
    uint8_t allocation;
    uint8_t initial_bitpool;
    uint8_t min_bitpool;
    uint8_t max_bitpool;
};

static bool are_capabilities_compatible(const a2dp_sbc_t *capabilities1, const a2dp_sbc_t *capabilities2) {
    if (!(capabilities1->channel_mode & capabilities2->channel_mode))
        return false;

    if (!(capabilities1->frequency & capabilities2->frequency))
        return false;

    if (!(capabilities1->allocation_method & capabilities2->allocation_method))
        return false;

    if (!(capabilities1->subbands & capabilities2->subbands))
        return false;

    if (!(capabilities1->block_length & capabilities2->block_length))
        return false;

    if (capabilities1->min_bitpool > capabilities2->max_bitpool || capabilities2->min_bitpool > capabilities1->max_bitpool)
        return false;

    if (capabilities1->min_bitpool > capabilities1->max_bitpool || capabilities2->min_bitpool > capabilities2->max_bitpool)
        return false;

    return true;
}

static bool can_accept_capabilities(const uint8_t *capabilities_buffer, uint8_t capabilities_size, bool for_encoding) {
    const a2dp_sbc_t *capabilities = (const a2dp_sbc_t *) capabilities_buffer;

    if (capabilities_size != sizeof(*capabilities))
        return false;

    return are_capabilities_compatible(capabilities, &sbc_auto_caps_table[0]);
}

static bool can_accept_capabilities_table(const uint8_t *capabilities_buffer, uint8_t capabilities_size, const a2dp_sbc_t capabilities_table[], unsigned capabilities_table_elements) {
    const a2dp_sbc_t *capabilities = (const a2dp_sbc_t *) capabilities_buffer;
    unsigned i;

    if (!can_accept_capabilities(capabilities_buffer, capabilities_size, false))
        return false;

    for (i = 0; i < capabilities_table_elements; i++) {
        if (!are_capabilities_compatible(capabilities, &capabilities_table[i]))
            continue;
        return true;
    }

    return false;
}

static bool can_accept_capabilities_lq(const uint8_t *capabilities_buffer, uint8_t capabilities_size, bool for_encoding) {
    return can_accept_capabilities_table(capabilities_buffer, capabilities_size, sbc_lq_caps_table, PA_ELEMENTSOF(sbc_lq_caps_table));
}

static bool can_accept_capabilities_mq(const uint8_t *capabilities_buffer, uint8_t capabilities_size, bool for_encoding) {
    return can_accept_capabilities_table(capabilities_buffer, capabilities_size, sbc_mq_caps_table, PA_ELEMENTSOF(sbc_mq_caps_table));
}

static bool can_accept_capabilities_hq(const uint8_t *capabilities_buffer, uint8_t capabilities_size, bool for_encoding) {
    return can_accept_capabilities_table(capabilities_buffer, capabilities_size, sbc_hq_caps_table, PA_ELEMENTSOF(sbc_hq_caps_table));
}

static bool can_accept_capabilities_xq1(const uint8_t *capabilities_buffer, uint8_t capabilities_size, bool for_encoding) {
    return can_accept_capabilities_table(capabilities_buffer, capabilities_size, sbc_xq1_caps_table, PA_ELEMENTSOF(sbc_xq1_caps_table));
}

static bool can_accept_capabilities_xq2(const uint8_t *capabilities_buffer, uint8_t capabilities_size, bool for_encoding) {
    return can_accept_capabilities_table(capabilities_buffer, capabilities_size, sbc_xq2_caps_table, PA_ELEMENTSOF(sbc_xq2_caps_table));
}

static const char *choose_remote_endpoint_table(const pa_hashmap *capabilities_hashmap, const pa_sample_spec *default_sample_spec, const a2dp_sbc_t capabilities_table[], unsigned capabilities_table_elements) {
    const pa_a2dp_codec_capabilities *a2dp_capabilities;
    const a2dp_sbc_t *capabilities;
    const char *key;
    void *state;
    unsigned i;
    uint8_t table_range;
    uint8_t current_range;
    const char *best_key = NULL;
    uint8_t best_range = 0;
    uint8_t frequency = 0;
    bool is_mono = (default_sample_spec->channels <= 1);

    static const struct {
        uint32_t rate;
        uint8_t cap;
    } freq_table[] = {
        { 16000U, SBC_SAMPLING_FREQ_16000 },
        { 32000U, SBC_SAMPLING_FREQ_32000 },
        { 44100U, SBC_SAMPLING_FREQ_44100 },
        { 48000U, SBC_SAMPLING_FREQ_48000 }
    };

    for (i = 0; i < PA_ELEMENTSOF(freq_table); i++) {
        if (freq_table[i].rate == default_sample_spec->rate) {
            frequency = freq_table[i].cap;
            break;
        }
    }

    if (!frequency)
        return NULL;

    /* choose remote capabilities which are compatible and its bitpool range is nearest to one from capabilities table */
    PA_HASHMAP_FOREACH_KV(key, a2dp_capabilities, capabilities_hashmap, state) {
        /* skip remote capabilities which are not compatible */
        if (!can_accept_capabilities(a2dp_capabilities->buffer, a2dp_capabilities->size, false))
            continue;

        capabilities = (const a2dp_sbc_t *) a2dp_capabilities->buffer;

        /* choose capabilities from our table which is compatible with sample spec and remote capabilities */
        for (i = 0; i < capabilities_table_elements; i++) {
            if (!are_capabilities_compatible(capabilities, &capabilities_table[i]))
                continue;
            /* For mono mode both capabilities must support mono */
            if (is_mono && !((capabilities->channel_mode & SBC_CHANNEL_MODE_MONO) & (capabilities_table[i].channel_mode & SBC_CHANNEL_MODE_MONO)))
                continue;
            /* For non-mono mode both capabilities must support at least one common non-mode mode */
            if (!is_mono && !((capabilities->channel_mode & (SBC_CHANNEL_MODE_JOINT_STEREO | SBC_CHANNEL_MODE_STEREO | SBC_CHANNEL_MODE_DUAL_CHANNEL)) & (capabilities_table[i].channel_mode & (SBC_CHANNEL_MODE_JOINT_STEREO | SBC_CHANNEL_MODE_STEREO | SBC_CHANNEL_MODE_DUAL_CHANNEL))))
                continue;
            /* And both capabilites must be compatible with chosen frequency */
            if (!(capabilities->frequency & frequency) || !(capabilities_table[i].frequency & frequency))
                continue;
            break;
        }

        /* skip if nothing is compatible */
        if (i == capabilities_table_elements)
            continue;

        /* calculate current bitpool range compatible with both remote capabilities and capabilities from our table */
        if (capabilities->min_bitpool > capabilities_table[i].min_bitpool) {
            if (capabilities->max_bitpool > capabilities_table[i].max_bitpool)
                current_range = capabilities_table[i].max_bitpool - capabilities->min_bitpool;
            else
                current_range = capabilities->max_bitpool - capabilities->min_bitpool;
        } else {
            if (capabilities->max_bitpool > capabilities_table[i].max_bitpool)
                current_range = capabilities_table[i].max_bitpool - capabilities_table[i].min_bitpool;
            else
                current_range = capabilities->max_bitpool - capabilities_table[i].min_bitpool;
        }

        table_range = capabilities_table[i].max_bitpool - capabilities_table[i].min_bitpool;

        /* use current remote capabilities if its bitpool range is closer to bitpool range in table */
        if (!best_key || abs((int)current_range - (int)(table_range)) < abs((int)best_range - (int)(table_range))) {
            best_range = current_range;
            best_key = key;
        }
    }

    return best_key;
}

static const char *choose_remote_endpoint_lq(const pa_hashmap *capabilities_hashmap, const pa_sample_spec *default_sample_spec, bool for_encoding) {
    return choose_remote_endpoint_table(capabilities_hashmap, default_sample_spec, sbc_lq_caps_table, PA_ELEMENTSOF(sbc_lq_caps_table));
}

static const char *choose_remote_endpoint_mq(const pa_hashmap *capabilities_hashmap, const pa_sample_spec *default_sample_spec, bool for_encoding) {
    return choose_remote_endpoint_table(capabilities_hashmap, default_sample_spec, sbc_mq_caps_table, PA_ELEMENTSOF(sbc_mq_caps_table));
}

static const char *choose_remote_endpoint_hq(const pa_hashmap *capabilities_hashmap, const pa_sample_spec *default_sample_spec, bool for_encoding) {
    return choose_remote_endpoint_table(capabilities_hashmap, default_sample_spec, sbc_hq_caps_table, PA_ELEMENTSOF(sbc_hq_caps_table));
}

static const char *choose_remote_endpoint_xq1(const pa_hashmap *capabilities_hashmap, const pa_sample_spec *default_sample_spec, bool for_encoding) {
    return choose_remote_endpoint_table(capabilities_hashmap, default_sample_spec, sbc_xq1_caps_table, PA_ELEMENTSOF(sbc_xq1_caps_table));
}

static const char *choose_remote_endpoint_xq2(const pa_hashmap *capabilities_hashmap, const pa_sample_spec *default_sample_spec, bool for_encoding) {
    return choose_remote_endpoint_table(capabilities_hashmap, default_sample_spec, sbc_xq2_caps_table, PA_ELEMENTSOF(sbc_xq2_caps_table));
}

static const char *choose_remote_endpoint(const pa_hashmap *capabilities_hashmap, const pa_sample_spec *default_sample_spec, bool for_encoding) {
    return choose_remote_endpoint_table(capabilities_hashmap, default_sample_spec, sbc_auto_caps_table, PA_ELEMENTSOF(sbc_auto_caps_table));
}

static uint8_t fill_capabilities_table(uint8_t capabilities_buffer[MAX_A2DP_CAPS_SIZE], const a2dp_sbc_t capabilities_table[], unsigned capabilities_table_elements) {
    a2dp_sbc_t *capabilities = (a2dp_sbc_t *) capabilities_buffer;
    unsigned i;

    pa_zero(*capabilities);

    capabilities->min_bitpool = 0xFF;
    capabilities->max_bitpool = 0x00;

    for (i = 0; i < capabilities_table_elements; i++) {
        capabilities->channel_mode |= capabilities_table[i].channel_mode;
        capabilities->frequency |= capabilities_table[i].frequency;
        capabilities->allocation_method |= capabilities_table[i].allocation_method;
        capabilities->subbands |= capabilities_table[i].subbands;
        capabilities->block_length |= capabilities_table[i].block_length;
        if (capabilities->min_bitpool > capabilities_table[i].min_bitpool)
            capabilities->min_bitpool = capabilities_table[i].min_bitpool;
        if (capabilities->max_bitpool < capabilities_table[i].max_bitpool)
            capabilities->max_bitpool = capabilities_table[i].max_bitpool;
    }

    pa_assert(capabilities->min_bitpool != 0xFF);
    pa_assert(capabilities->max_bitpool != 0x00);

    return sizeof(*capabilities);
}

static uint8_t fill_capabilities_lq(uint8_t capabilities_buffer[MAX_A2DP_CAPS_SIZE]) {
    return fill_capabilities_table(capabilities_buffer, sbc_lq_caps_table, PA_ELEMENTSOF(sbc_lq_caps_table));
}

static uint8_t fill_capabilities_mq(uint8_t capabilities_buffer[MAX_A2DP_CAPS_SIZE]) {
    return fill_capabilities_table(capabilities_buffer, sbc_mq_caps_table, PA_ELEMENTSOF(sbc_mq_caps_table));
}

static uint8_t fill_capabilities_hq(uint8_t capabilities_buffer[MAX_A2DP_CAPS_SIZE]) {
    return fill_capabilities_table(capabilities_buffer, sbc_hq_caps_table, PA_ELEMENTSOF(sbc_hq_caps_table));
}

static uint8_t fill_capabilities_xq1(uint8_t capabilities_buffer[MAX_A2DP_CAPS_SIZE]) {
    return fill_capabilities_table(capabilities_buffer, sbc_xq1_caps_table, PA_ELEMENTSOF(sbc_xq1_caps_table));
}

static uint8_t fill_capabilities_xq2(uint8_t capabilities_buffer[MAX_A2DP_CAPS_SIZE]) {
    return fill_capabilities_table(capabilities_buffer, sbc_xq2_caps_table, PA_ELEMENTSOF(sbc_xq2_caps_table));
}

static uint8_t fill_capabilities(uint8_t capabilities_buffer[MAX_A2DP_CAPS_SIZE]) {
    return fill_capabilities_table(capabilities_buffer, sbc_auto_caps_table, PA_ELEMENTSOF(sbc_auto_caps_table));
}

static bool is_configuration_valid(const uint8_t *config_buffer, uint8_t config_size) {
    const a2dp_sbc_t *config = (const a2dp_sbc_t *) config_buffer;

    if (config_size != sizeof(*config)) {
        pa_log_error("Invalid size of config buffer");
        return false;
    }

    if (config->frequency != SBC_SAMPLING_FREQ_16000 && config->frequency != SBC_SAMPLING_FREQ_32000 &&
        config->frequency != SBC_SAMPLING_FREQ_44100 && config->frequency != SBC_SAMPLING_FREQ_48000) {
        pa_log_error("Invalid sampling frequency in configuration");
        return false;
    }

    if (config->channel_mode != SBC_CHANNEL_MODE_MONO && config->channel_mode != SBC_CHANNEL_MODE_DUAL_CHANNEL &&
        config->channel_mode != SBC_CHANNEL_MODE_STEREO && config->channel_mode != SBC_CHANNEL_MODE_JOINT_STEREO) {
        pa_log_error("Invalid channel mode in configuration");
        return false;
    }

    if (config->allocation_method != SBC_ALLOCATION_SNR && config->allocation_method != SBC_ALLOCATION_LOUDNESS) {
        pa_log_error("Invalid allocation method in configuration");
        return false;
    }

    if (config->subbands != SBC_SUBBANDS_4 && config->subbands != SBC_SUBBANDS_8) {
        pa_log_error("Invalid SBC subbands in configuration");
        return false;
    }

    if (config->block_length != SBC_BLOCK_LENGTH_4 && config->block_length != SBC_BLOCK_LENGTH_8 &&
        config->block_length != SBC_BLOCK_LENGTH_12 && config->block_length != SBC_BLOCK_LENGTH_16) {
        pa_log_error("Invalid block length in configuration");
        return false;
    }

    if (config->min_bitpool > config->max_bitpool) {
        pa_log_error("Invalid bitpool in configuration");
        return false;
    }

    return true;
}

static bool are_configs_compatible(const a2dp_sbc_t *config1, const a2dp_sbc_t *config2) {
    if (config1->frequency != config2->frequency)
        return false;

    if (config1->channel_mode != config2->channel_mode)
        return false;

    if (config1->allocation_method != config2->allocation_method)
        return false;

    if (config1->subbands != config2->subbands)
        return false;

    if (config1->block_length != config2->block_length)
        return false;

    /* second config must have constant bitpool */
    pa_assert(config2->min_bitpool == config2->max_bitpool);

    if (config1->min_bitpool > config2->min_bitpool || config1->max_bitpool < config2->min_bitpool)
        return false;

    return true;
}

static bool is_configuration_valid_table(const uint8_t *config_buffer, uint8_t config_size, const a2dp_sbc_t capabilities_table[], unsigned capabilities_table_elements) {
    const a2dp_sbc_t *config;
    unsigned i;

    if (!is_configuration_valid(config_buffer, config_size))
        return false;

    config = (const a2dp_sbc_t *) config_buffer;

    for (i = 0; i < capabilities_table_elements; i++) {
        if (!are_configs_compatible(config, &capabilities_table[i]))
            continue;
        return true;
    }

    pa_log_error("Some configuration settings are invalid for current quality");
    return false;
}

static bool is_configuration_valid_lq(const uint8_t *config_buffer, uint8_t config_size) {
    return is_configuration_valid_table(config_buffer, config_size, sbc_lq_caps_table, PA_ELEMENTSOF(sbc_lq_caps_table));
}

static bool is_configuration_valid_mq(const uint8_t *config_buffer, uint8_t config_size) {
    return is_configuration_valid_table(config_buffer, config_size, sbc_mq_caps_table, PA_ELEMENTSOF(sbc_mq_caps_table));
}

static bool is_configuration_valid_hq(const uint8_t *config_buffer, uint8_t config_size) {
    return is_configuration_valid_table(config_buffer, config_size, sbc_hq_caps_table, PA_ELEMENTSOF(sbc_hq_caps_table));
}

static bool is_configuration_valid_xq1(const uint8_t *config_buffer, uint8_t config_size) {
    return is_configuration_valid_table(config_buffer, config_size, sbc_xq1_caps_table, PA_ELEMENTSOF(sbc_xq1_caps_table));
}

static bool is_configuration_valid_xq2(const uint8_t *config_buffer, uint8_t config_size) {
    return is_configuration_valid_table(config_buffer, config_size, sbc_xq2_caps_table, PA_ELEMENTSOF(sbc_xq2_caps_table));
}

static uint8_t fill_preferred_configuration_table(const pa_sample_spec *default_sample_spec, const uint8_t *capabilities_buffer, uint8_t capabilities_size, uint8_t config_buffer[MAX_A2DP_CAPS_SIZE], const a2dp_sbc_t capabilities_table[], unsigned capabilities_table_elements) {
    a2dp_sbc_t *config = (a2dp_sbc_t *) config_buffer;
    const a2dp_sbc_t *capabilities = (const a2dp_sbc_t *) capabilities_buffer;
    bool is_mono = (default_sample_spec->channels <= 1);
    unsigned i;
    int j;

    static const struct {
        uint32_t rate;
        uint8_t cap;
    } freq_table[] = {
        { 16000U, SBC_SAMPLING_FREQ_16000 },
        { 32000U, SBC_SAMPLING_FREQ_32000 },
        { 44100U, SBC_SAMPLING_FREQ_44100 },
        { 48000U, SBC_SAMPLING_FREQ_48000 }
    };

    if (capabilities_size != sizeof(*capabilities)) {
        pa_log_error("Invalid size of capabilities buffer");
        return 0;
    }

    pa_zero(*config);

    /* Find the lowest freq that is at least as high as the requested sampling rate */
    for (j = 0; (unsigned) j < PA_ELEMENTSOF(freq_table); j++) {
        if (freq_table[j].rate >= default_sample_spec->rate && (capabilities->frequency & freq_table[j].cap)) {
            for (i = 0; i < capabilities_table_elements; i++) {
                if (capabilities_table[i].frequency & freq_table[j].cap) {
                    config->frequency = freq_table[j].cap;
                    break;
                }
            }
            if (i != capabilities_table_elements)
                break;
        }
    }

    if ((unsigned) j == PA_ELEMENTSOF(freq_table)) {
        for (--j; j >= 0; j--) {
            if (capabilities->frequency & freq_table[j].cap) {
                for (i = 0; i < capabilities_table_elements; i++) {
                    if (capabilities_table[i].frequency & freq_table[j].cap) {
                        config->frequency = freq_table[j].cap;
                        break;
                    }
                }
                if (i != capabilities_table_elements)
                    break;
            }
        }

        if (j < 0) {
            pa_log_error("No suitable sample rate");
            return 0;
        }
    }

    pa_assert((unsigned) j < PA_ELEMENTSOF(freq_table));

    for (i = 0; i < capabilities_table_elements; i++) {
        if ((capabilities->block_length & SBC_BLOCK_LENGTH_16) && (capabilities_table[i].block_length & SBC_BLOCK_LENGTH_16))
            config->block_length = SBC_BLOCK_LENGTH_16;
        else if ((capabilities->block_length & SBC_BLOCK_LENGTH_12) && (capabilities_table[i].block_length & SBC_BLOCK_LENGTH_12))
            config->block_length = SBC_BLOCK_LENGTH_12;
        else if ((capabilities->block_length & SBC_BLOCK_LENGTH_8) && (capabilities_table[i].block_length & SBC_BLOCK_LENGTH_8))
            config->block_length = SBC_BLOCK_LENGTH_8;
        else if ((capabilities->block_length & SBC_BLOCK_LENGTH_4) && (capabilities_table[i].block_length & SBC_BLOCK_LENGTH_4))
            config->block_length = SBC_BLOCK_LENGTH_4;
        else {
            pa_log_debug("No supported block lengths in table %u", i);
            continue;
        }

        if ((capabilities->subbands & SBC_SUBBANDS_8) && (capabilities_table[i].subbands & SBC_SUBBANDS_8))
            config->subbands = SBC_SUBBANDS_8;
        else if ((capabilities->subbands & SBC_SUBBANDS_4) && (capabilities_table[i].subbands & SBC_SUBBANDS_4))
            config->subbands = SBC_SUBBANDS_4;
        else {
            pa_log_debug("No supported subbands in table %u", i);
            continue;
        }

        if ((capabilities->allocation_method & SBC_ALLOCATION_LOUDNESS) && (capabilities_table[i].allocation_method & SBC_ALLOCATION_LOUDNESS))
            config->allocation_method = SBC_ALLOCATION_LOUDNESS;
        else if ((capabilities->allocation_method & SBC_ALLOCATION_SNR) && (capabilities_table[i].allocation_method & SBC_ALLOCATION_SNR))
            config->allocation_method = SBC_ALLOCATION_SNR;
        else {
            pa_log_debug("No supported allocation method in table %u", i);
            continue;
        }

        if (is_mono) {
            if ((capabilities->channel_mode & SBC_CHANNEL_MODE_MONO) && (capabilities_table[i].channel_mode & SBC_CHANNEL_MODE_MONO))
                config->channel_mode = SBC_CHANNEL_MODE_MONO;
            else if ((capabilities->channel_mode & SBC_CHANNEL_MODE_JOINT_STEREO) && (capabilities_table[i].channel_mode & SBC_CHANNEL_MODE_JOINT_STEREO))
                config->channel_mode = SBC_CHANNEL_MODE_JOINT_STEREO;
            else if ((capabilities->channel_mode & SBC_CHANNEL_MODE_STEREO) && (capabilities_table[i].channel_mode & SBC_CHANNEL_MODE_STEREO))
                config->channel_mode = SBC_CHANNEL_MODE_STEREO;
            else if ((capabilities->channel_mode & SBC_CHANNEL_MODE_DUAL_CHANNEL) && (capabilities_table[i].channel_mode & SBC_CHANNEL_MODE_DUAL_CHANNEL))
                config->channel_mode = SBC_CHANNEL_MODE_DUAL_CHANNEL;
            else {
                pa_log_debug("No supported channel mode in table %u", i);
                continue;
            }
        } else {
            if ((capabilities->channel_mode & SBC_CHANNEL_MODE_JOINT_STEREO) && (capabilities_table[i].channel_mode & SBC_CHANNEL_MODE_JOINT_STEREO))
                config->channel_mode = SBC_CHANNEL_MODE_JOINT_STEREO;
            else if ((capabilities->channel_mode & SBC_CHANNEL_MODE_STEREO) && (capabilities_table[i].channel_mode & SBC_CHANNEL_MODE_STEREO))
                config->channel_mode = SBC_CHANNEL_MODE_STEREO;
            else if ((capabilities->channel_mode & SBC_CHANNEL_MODE_DUAL_CHANNEL) && (capabilities_table[i].channel_mode & SBC_CHANNEL_MODE_DUAL_CHANNEL))
                config->channel_mode = SBC_CHANNEL_MODE_DUAL_CHANNEL;
            else if ((capabilities->channel_mode & SBC_CHANNEL_MODE_MONO) && (capabilities_table[i].channel_mode & SBC_CHANNEL_MODE_MONO))
                config->channel_mode = SBC_CHANNEL_MODE_MONO;
            else {
                pa_log_debug("No supported channel mode in table %u", i);
                continue;
            }
        }

        config->min_bitpool = PA_MAX(capabilities->min_bitpool, capabilities_table[i].min_bitpool);
        config->max_bitpool = PA_MIN(capabilities->max_bitpool, capabilities_table[i].max_bitpool);

        if (config->min_bitpool > config->max_bitpool) {
            pa_log_debug("No supported bitpool in table %u [%u, %u], need [%u, %u]", i, capabilities_table[i].min_bitpool, capabilities_table[i].max_bitpool, capabilities->min_bitpool, capabilities->max_bitpool);
            continue;
        }

        break;
    }

    if (i == capabilities_table_elements) {
        pa_log_error("No supported configuration");
        return 0;
    }

    return sizeof(*config);
}

static uint8_t fill_preferred_configuration_lq(const pa_sample_spec *default_sample_spec, const uint8_t *capabilities_buffer, uint8_t capabilities_size, uint8_t config_buffer[MAX_A2DP_CAPS_SIZE]) {
    return fill_preferred_configuration_table(default_sample_spec, capabilities_buffer, capabilities_size, config_buffer, sbc_lq_caps_table, PA_ELEMENTSOF(sbc_lq_caps_table));
}

static uint8_t fill_preferred_configuration_mq(const pa_sample_spec *default_sample_spec, const uint8_t *capabilities_buffer, uint8_t capabilities_size, uint8_t config_buffer[MAX_A2DP_CAPS_SIZE]) {
    return fill_preferred_configuration_table(default_sample_spec, capabilities_buffer, capabilities_size, config_buffer, sbc_mq_caps_table, PA_ELEMENTSOF(sbc_mq_caps_table));
}

static uint8_t fill_preferred_configuration_hq(const pa_sample_spec *default_sample_spec, const uint8_t *capabilities_buffer, uint8_t capabilities_size, uint8_t config_buffer[MAX_A2DP_CAPS_SIZE]) {
    return fill_preferred_configuration_table(default_sample_spec, capabilities_buffer, capabilities_size, config_buffer, sbc_hq_caps_table, PA_ELEMENTSOF(sbc_hq_caps_table));
}

static uint8_t fill_preferred_configuration_xq1(const pa_sample_spec *default_sample_spec, const uint8_t *capabilities_buffer, uint8_t capabilities_size, uint8_t config_buffer[MAX_A2DP_CAPS_SIZE]) {
    return fill_preferred_configuration_table(default_sample_spec, capabilities_buffer, capabilities_size, config_buffer, sbc_xq1_caps_table, PA_ELEMENTSOF(sbc_xq1_caps_table));
}

static uint8_t fill_preferred_configuration_xq2(const pa_sample_spec *default_sample_spec, const uint8_t *capabilities_buffer, uint8_t capabilities_size, uint8_t config_buffer[MAX_A2DP_CAPS_SIZE]) {
    return fill_preferred_configuration_table(default_sample_spec, capabilities_buffer, capabilities_size, config_buffer, sbc_xq2_caps_table, PA_ELEMENTSOF(sbc_xq2_caps_table));
}

static uint8_t default_bitpool(uint8_t freq, uint8_t mode) {
    /* These bitpool values were chosen based on the A2DP spec recommendation */
    switch (freq) {
        case SBC_SAMPLING_FREQ_16000:
        case SBC_SAMPLING_FREQ_32000:
            switch (mode) {
                case SBC_CHANNEL_MODE_MONO:
                case SBC_CHANNEL_MODE_DUAL_CHANNEL:
                case SBC_CHANNEL_MODE_STEREO:
                case SBC_CHANNEL_MODE_JOINT_STEREO:
                    return SBC_BITPOOL_HQ_JOINT_STEREO_44100;
            }
            break;

        case SBC_SAMPLING_FREQ_44100:
            switch (mode) {
                case SBC_CHANNEL_MODE_MONO:
                case SBC_CHANNEL_MODE_DUAL_CHANNEL:
                    return SBC_BITPOOL_HQ_MONO_44100;

                case SBC_CHANNEL_MODE_STEREO:
                case SBC_CHANNEL_MODE_JOINT_STEREO:
                    return SBC_BITPOOL_HQ_JOINT_STEREO_44100;
            }
            break;

        case SBC_SAMPLING_FREQ_48000:
            switch (mode) {
                case SBC_CHANNEL_MODE_MONO:
                case SBC_CHANNEL_MODE_DUAL_CHANNEL:
                    return SBC_BITPOOL_HQ_MONO_48000;

                case SBC_CHANNEL_MODE_STEREO:
                case SBC_CHANNEL_MODE_JOINT_STEREO:
                    return SBC_BITPOOL_HQ_JOINT_STEREO_48000;
            }
            break;
    }

    pa_assert_not_reached();
}

static uint8_t fill_preferred_configuration(const pa_sample_spec *default_sample_spec, const uint8_t *capabilities_buffer, uint8_t capabilities_size, uint8_t config_buffer[MAX_A2DP_CAPS_SIZE]) {
    a2dp_sbc_t *config = (a2dp_sbc_t *) config_buffer;
    uint8_t ret;

    ret = fill_preferred_configuration_table(default_sample_spec, capabilities_buffer, capabilities_size, config_buffer, sbc_auto_caps_table, PA_ELEMENTSOF(sbc_auto_caps_table));
    config->max_bitpool = PA_MIN(default_bitpool(config->frequency, config->channel_mode), config->max_bitpool);
    config->max_bitpool = PA_MAX(config->max_bitpool, config->min_bitpool);

    return ret;
}

static void set_params(struct sbc_info *sbc_info) {
    sbc_info->sbc.frequency = sbc_info->frequency;
    sbc_info->sbc.blocks = sbc_info->blocks;
    sbc_info->sbc.subbands = sbc_info->subbands;
    sbc_info->sbc.mode = sbc_info->mode;
    sbc_info->sbc.allocation = sbc_info->allocation;
    sbc_info->sbc.bitpool = sbc_info->initial_bitpool;
    sbc_info->sbc.endian = SBC_LE;

    sbc_info->codesize = sbc_get_codesize(&sbc_info->sbc);
    sbc_info->frame_length = sbc_get_frame_length(&sbc_info->sbc);
}

static void *init(bool for_encoding, bool for_backchannel, const uint8_t *config_buffer, uint8_t config_size, pa_sample_spec *sample_spec) {
    struct sbc_info *sbc_info;
    const a2dp_sbc_t *config = (const a2dp_sbc_t *) config_buffer;
    int ret;

    pa_assert(config_size == sizeof(*config));
    pa_assert(!for_backchannel);

    sbc_info = pa_xnew0(struct sbc_info, 1);

    ret = sbc_init(&sbc_info->sbc, 0);
    if (ret != 0) {
        pa_xfree(sbc_info);
        pa_log_error("SBC initialization failed: %d", ret);
        return NULL;
    }

    sample_spec->format = PA_SAMPLE_S16LE;

    switch (config->frequency) {
        case SBC_SAMPLING_FREQ_16000:
            sbc_info->frequency = SBC_FREQ_16000;
            sample_spec->rate = 16000U;
            break;
        case SBC_SAMPLING_FREQ_32000:
            sbc_info->frequency = SBC_FREQ_32000;
            sample_spec->rate = 32000U;
            break;
        case SBC_SAMPLING_FREQ_44100:
            sbc_info->frequency = SBC_FREQ_44100;
            sample_spec->rate = 44100U;
            break;
        case SBC_SAMPLING_FREQ_48000:
            sbc_info->frequency = SBC_FREQ_48000;
            sample_spec->rate = 48000U;
            break;
        default:
            pa_assert_not_reached();
    }

    switch (config->channel_mode) {
        case SBC_CHANNEL_MODE_MONO:
            sbc_info->mode = SBC_MODE_MONO;
            sample_spec->channels = 1;
            break;
        case SBC_CHANNEL_MODE_DUAL_CHANNEL:
            sbc_info->mode = SBC_MODE_DUAL_CHANNEL;
            sample_spec->channels = 2;
            break;
        case SBC_CHANNEL_MODE_STEREO:
            sbc_info->mode = SBC_MODE_STEREO;
            sample_spec->channels = 2;
            break;
        case SBC_CHANNEL_MODE_JOINT_STEREO:
            sbc_info->mode = SBC_MODE_JOINT_STEREO;
            sample_spec->channels = 2;
            break;
        default:
            pa_assert_not_reached();
    }

    switch (config->allocation_method) {
        case SBC_ALLOCATION_SNR:
            sbc_info->allocation = SBC_AM_SNR;
            break;
        case SBC_ALLOCATION_LOUDNESS:
            sbc_info->allocation = SBC_AM_LOUDNESS;
            break;
        default:
            pa_assert_not_reached();
    }

    switch (config->subbands) {
        case SBC_SUBBANDS_4:
            sbc_info->subbands = SBC_SB_4;
            break;
        case SBC_SUBBANDS_8:
            sbc_info->subbands = SBC_SB_8;
            break;
        default:
            pa_assert_not_reached();
    }

    switch (config->block_length) {
        case SBC_BLOCK_LENGTH_4:
            sbc_info->blocks = SBC_BLK_4;
            break;
        case SBC_BLOCK_LENGTH_8:
            sbc_info->blocks = SBC_BLK_8;
            break;
        case SBC_BLOCK_LENGTH_12:
            sbc_info->blocks = SBC_BLK_12;
            break;
        case SBC_BLOCK_LENGTH_16:
            sbc_info->blocks = SBC_BLK_16;
            break;
        default:
            pa_assert_not_reached();
    }

    sbc_info->min_bitpool = config->min_bitpool;
    sbc_info->max_bitpool = config->max_bitpool;

    /* Set minimum bitpool for source to get the maximum possible block_size
     * in get_block_size() function. This block_size is length of buffer used
     * for decoded audio data and so is inversely proportional to frame length
     * which depends on bitpool value. Bitpool is controlled by other side from
     * range [min_bitpool, max_bitpool]. */
    sbc_info->initial_bitpool = for_encoding ? sbc_info->max_bitpool : sbc_info->min_bitpool;

    set_params(sbc_info);

    pa_log_info("SBC parameters: allocation=%s, subbands=%u, blocks=%u, mode=%s bitpool=%u codesize=%u frame_length=%u",
                sbc_info->sbc.allocation ? "SNR" : "Loudness", sbc_info->sbc.subbands ? 8 : 4,
                (sbc_info->sbc.blocks+1)*4, sbc_info->sbc.mode == SBC_MODE_MONO ? "Mono" :
                sbc_info->sbc.mode == SBC_MODE_DUAL_CHANNEL ? "DualChannel" :
                sbc_info->sbc.mode == SBC_MODE_STEREO ? "Stereo" : "JointStereo",
                sbc_info->sbc.bitpool, (unsigned)sbc_info->codesize, (unsigned)sbc_info->frame_length);

    return sbc_info;
}

static void deinit(void *codec_info) {
    struct sbc_info *sbc_info = (struct sbc_info *) codec_info;

    sbc_finish(&sbc_info->sbc);
    pa_xfree(sbc_info);
}

static void set_bitpool(struct sbc_info *sbc_info, uint8_t bitpool) {
    if (bitpool > sbc_info->max_bitpool)
        bitpool = sbc_info->max_bitpool;
    else if (bitpool < sbc_info->min_bitpool)
        bitpool = sbc_info->min_bitpool;

    sbc_info->sbc.bitpool = bitpool;

    sbc_info->codesize = sbc_get_codesize(&sbc_info->sbc);
    sbc_info->frame_length = sbc_get_frame_length(&sbc_info->sbc);

    pa_log_debug("Bitpool has changed to %u", sbc_info->sbc.bitpool);
}

static int reset(void *codec_info) {
    struct sbc_info *sbc_info = (struct sbc_info *) codec_info;
    int ret;

    ret = sbc_reinit(&sbc_info->sbc, 0);
    if (ret != 0) {
        pa_log_error("SBC reinitialization failed: %d", ret);
        return -1;
    }

    /* sbc_reinit() sets also default parameters, so reset them back */
    set_params(sbc_info);

    sbc_info->seq_num = 0;
    return 0;
}

static size_t get_block_size(void *codec_info, size_t link_mtu) {
    struct sbc_info *sbc_info = (struct sbc_info *) codec_info;
    size_t rtp_size = sizeof(struct rtp_header) + sizeof(struct rtp_sbc_payload);
    size_t frame_count = (link_mtu - rtp_size) / sbc_info->frame_length;

    /* frame_count is only 4 bit number */
    if (frame_count > 15)
        frame_count = 15;

    return frame_count * sbc_info->codesize;
}

static size_t reduce_encoder_bitrate(void *codec_info, size_t write_link_mtu) {
    struct sbc_info *sbc_info = (struct sbc_info *) codec_info;
    uint8_t bitpool;

    /* Check if bitpool is already at its limit */
    if (sbc_info->mode == SBC_CHANNEL_MODE_MONO || sbc_info->mode == SBC_CHANNEL_MODE_DUAL_CHANNEL) {
        /* For Mono and Dual Channel modes bitpool value is separete for each channel */
        bitpool = sbc_info->sbc.bitpool - SBC_SEPARATE_BITPOOL_DEC_STEP;
        if (bitpool <= SBC_SEPARATE_BITPOOL_DEC_LIMIT)
            return 0;
    } else {
        /* For Stereo modes bitpool value is combined for both channels */
        bitpool = sbc_info->sbc.bitpool - SBC_COMBINED_BITPOOL_DEC_STEP;
        if (bitpool <= SBC_COMBINED_BITPOOL_DEC_LIMIT)
            return 0;
    }

    if (sbc_info->sbc.bitpool == bitpool)
        return 0;

    set_bitpool(sbc_info, bitpool);
    return get_block_size(codec_info, write_link_mtu);
}

static size_t reduce_encoder_bitrate_none(void *codec_info, size_t write_link_mtu) {
    return 0;
}

static size_t encode_buffer(void *codec_info, uint32_t timestamp, const uint8_t *input_buffer, size_t input_size, uint8_t *output_buffer, size_t output_size, size_t *processed) {
    struct sbc_info *sbc_info = (struct sbc_info *) codec_info;
    struct rtp_header *header;
    struct rtp_sbc_payload *payload;
    uint8_t *d;
    const uint8_t *p;
    size_t to_write, to_encode;
    uint8_t frame_count;

    header = (struct rtp_header*) output_buffer;
    payload = (struct rtp_sbc_payload*) (output_buffer + sizeof(*header));

    frame_count = 0;

    p = input_buffer;
    to_encode = input_size;

    d = output_buffer + sizeof(*header) + sizeof(*payload);
    to_write = output_size - sizeof(*header) - sizeof(*payload);

    /* frame_count is only 4 bit number */
    while (PA_LIKELY(to_encode > 0 && to_write > 0 && frame_count < 15)) {
        ssize_t written;
        ssize_t encoded;

        encoded = sbc_encode(&sbc_info->sbc,
                             p, to_encode,
                             d, to_write,
                             &written);

        if (PA_UNLIKELY(encoded <= 0)) {
            pa_log_error("SBC encoding error (%li)", (long) encoded);
            break;
        }

        if (PA_UNLIKELY(written < 0)) {
            pa_log_error("SBC encoding error (%li)", (long) written);
            break;
        }

        pa_assert_fp((size_t) encoded <= to_encode);
        pa_assert_fp((size_t) encoded == sbc_info->codesize);

        pa_assert_fp((size_t) written <= to_write);
        pa_assert_fp((size_t) written == sbc_info->frame_length);

        p += encoded;
        to_encode -= encoded;

        d += written;
        to_write -= written;

        frame_count++;
    }

    PA_ONCE_BEGIN {
        pa_log_debug("Using SBC codec implementation: %s", pa_strnull(sbc_get_implementation_info(&sbc_info->sbc)));
    } PA_ONCE_END;

    if (PA_UNLIKELY(frame_count == 0)) {
        *processed = 0;
        return 0;
    }

    /* write it to the fifo */
    pa_memzero(output_buffer, sizeof(*header) + sizeof(*payload));
    header->v = 2;

    /* A2DP spec: "A payload type in the RTP dynamic range shall be chosen".
     * RFC3551 defines the dynamic range to span from 96 to 127, and 96 appears
     * to be the most common choice in A2DP implementations. */
    header->pt = 96;

    header->sequence_number = htons(sbc_info->seq_num++);
    header->timestamp = htonl(timestamp);
    header->ssrc = htonl(1);
    payload->frame_count = frame_count;

    *processed = p - input_buffer;
    return d - output_buffer;
}

static size_t decode_buffer(void *codec_info, uint32_t *timestamp, const uint8_t *input_buffer, size_t input_size, uint8_t *output_buffer, size_t output_size, size_t *processed) {
    struct sbc_info *sbc_info = (struct sbc_info *) codec_info;

    struct rtp_header *header;
    struct rtp_sbc_payload *payload;
    const uint8_t *p;
    uint8_t *d;
    size_t to_write, to_decode;
    uint8_t frame_count;

    header = (struct rtp_header *) input_buffer;
    payload = (struct rtp_sbc_payload*) (input_buffer + sizeof(*header));

    frame_count = payload->frame_count;

    /* TODO: Add support for decoding fragmented SBC frames */
    if (payload->is_fragmented) {
        pa_log_error("Unsupported fragmented SBC frame");
        *processed = 0;
        return 0;
    }

    p = input_buffer + sizeof(*header) + sizeof(*payload);
    to_decode = input_size - sizeof(*header) - sizeof(*payload);

    d = output_buffer;
    to_write = output_size;

    while (PA_LIKELY(to_decode > 0 && to_write > 0 && frame_count > 0)) {
        size_t written;
        ssize_t decoded;

        decoded = sbc_decode(&sbc_info->sbc,
                             p, to_decode,
                             d, to_write,
                             &written);

        if (PA_UNLIKELY(decoded <= 0)) {
            pa_log_error("SBC decoding error (%li)", (long) decoded);
            break;
        }

        /* Reset frame length, it can be changed due to bitpool change */
        sbc_info->frame_length = sbc_get_frame_length(&sbc_info->sbc);

        pa_assert_fp((size_t) decoded <= to_decode);
        pa_assert_fp((size_t) decoded == sbc_info->frame_length);

        pa_assert_fp((size_t) written <= to_write);
        pa_assert_fp((size_t) written == sbc_info->codesize);

        p += decoded;
        to_decode -= decoded;

        d += written;
        to_write -= written;

        frame_count--;
    }

    *timestamp = ntohl(header->timestamp);
    *processed = p - input_buffer;
    return d - output_buffer;
}

const pa_a2dp_codec pa_a2dp_codec_sbc_lq = {
    .name = "sbc_lq",
    .description = "SBC (Low Quality)",
    .id = { A2DP_CODEC_SBC, 0, 0 },
    .support_backchannel = false,
    .can_accept_capabilities = can_accept_capabilities_lq,
    .choose_remote_endpoint = choose_remote_endpoint_lq,
    .fill_capabilities = fill_capabilities_lq,
    .is_configuration_valid = is_configuration_valid_lq,
    .fill_preferred_configuration = fill_preferred_configuration_lq,
    .init = init,
    .deinit = deinit,
    .reset = reset,
    .get_read_block_size = get_block_size,
    .get_write_block_size = get_block_size,
    .reduce_encoder_bitrate = reduce_encoder_bitrate_none,
    .encode_buffer = encode_buffer,
    .decode_buffer = decode_buffer,
};

const pa_a2dp_codec pa_a2dp_codec_sbc_mq = {
    .name = "sbc_mq",
    .description = "SBC (Middle Quality)",
    .id = { A2DP_CODEC_SBC, 0, 0 },
    .support_backchannel = false,
    .can_accept_capabilities = can_accept_capabilities_mq,
    .choose_remote_endpoint = choose_remote_endpoint_mq,
    .fill_capabilities = fill_capabilities_mq,
    .is_configuration_valid = is_configuration_valid_mq,
    .fill_preferred_configuration = fill_preferred_configuration_mq,
    .init = init,
    .deinit = deinit,
    .reset = reset,
    .get_read_block_size = get_block_size,
    .get_write_block_size = get_block_size,
    .reduce_encoder_bitrate = reduce_encoder_bitrate_none,
    .encode_buffer = encode_buffer,
    .decode_buffer = decode_buffer,
};

const pa_a2dp_codec pa_a2dp_codec_sbc_hq = {
    .name = "sbc_hq",
    .description = "SBC (High Quality)",
    .id = { A2DP_CODEC_SBC, 0, 0 },
    .support_backchannel = false,
    .can_accept_capabilities = can_accept_capabilities_hq,
    .choose_remote_endpoint = choose_remote_endpoint_hq,
    .fill_capabilities = fill_capabilities_hq,
    .is_configuration_valid = is_configuration_valid_hq,
    .fill_preferred_configuration = fill_preferred_configuration_hq,
    .init = init,
    .deinit = deinit,
    .reset = reset,
    .get_read_block_size = get_block_size,
    .get_write_block_size = get_block_size,
    .reduce_encoder_bitrate = reduce_encoder_bitrate_none,
    .encode_buffer = encode_buffer,
    .decode_buffer = decode_buffer,
};

const pa_a2dp_codec pa_a2dp_codec_sbc = {
    .name = "sbc",
    .description = "SBC (Automatic Quality)",
    .id = { A2DP_CODEC_SBC, 0, 0 },
    .support_backchannel = false,
    .can_accept_capabilities = can_accept_capabilities,
    .choose_remote_endpoint = choose_remote_endpoint,
    .fill_capabilities = fill_capabilities,
    .is_configuration_valid = is_configuration_valid,
    .fill_preferred_configuration = fill_preferred_configuration,
    .init = init,
    .deinit = deinit,
    .reset = reset,
    .get_read_block_size = get_block_size,
    .get_write_block_size = get_block_size,
    .reduce_encoder_bitrate = reduce_encoder_bitrate,
    .encode_buffer = encode_buffer,
    .decode_buffer = decode_buffer,
};

const pa_a2dp_codec pa_a2dp_codec_sbc_xq1 = {
    .name = "sbc_xq1",
    .description = "SBC (eXtreme Quality profile 1)",
    .id = { A2DP_CODEC_SBC, 0, 0 },
    .support_backchannel = false,
    .can_accept_capabilities = can_accept_capabilities_xq1,
    .choose_remote_endpoint = choose_remote_endpoint_xq1,
    .fill_capabilities = fill_capabilities_xq1,
    .is_configuration_valid = is_configuration_valid_xq1,
    .fill_preferred_configuration = fill_preferred_configuration_xq1,
    .init = init,
    .deinit = deinit,
    .reset = reset,
    .get_read_block_size = get_block_size,
    .get_write_block_size = get_block_size,
    .reduce_encoder_bitrate = reduce_encoder_bitrate_none,
    .encode_buffer = encode_buffer,
    .decode_buffer = decode_buffer,
};

const pa_a2dp_codec pa_a2dp_codec_sbc_xq2 = {
    .name = "sbc_xq2",
    .description = "SBC (eXtreme Quality profile 2)",
    .id = { A2DP_CODEC_SBC, 0, 0 },
    .support_backchannel = false,
    .can_accept_capabilities = can_accept_capabilities_xq2,
    .choose_remote_endpoint = choose_remote_endpoint_xq2,
    .fill_capabilities = fill_capabilities_xq2,
    .is_configuration_valid = is_configuration_valid_xq2,
    .fill_preferred_configuration = fill_preferred_configuration_xq2,
    .init = init,
    .deinit = deinit,
    .reset = reset,
    .get_read_block_size = get_block_size,
    .get_write_block_size = get_block_size,
    .reduce_encoder_bitrate = reduce_encoder_bitrate_none,
    .encode_buffer = encode_buffer,
    .decode_buffer = decode_buffer,
};
