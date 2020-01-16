/***
    This file is part of PulseAudio.

    Copyright 2010 Intel Corporation
    Contributor: Pierre-Louis Bossart <pierre-louis.bossart@intel.com>
    Copyright 2012 Niels Ole Salscheider <niels_ole@salscheider-online.de>

    PulseAudio is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published
    by the Free Software Foundation; either version 2.1 of the License,
    or (at your option) any later version.

    PulseAudio is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
    General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with PulseAudio; if not, see <http://www.gnu.org/licenses/>.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <modules/virtual-sink-common.h>

#include <pulse/gccmacro.h>
#include <pulse/xmalloc.h>

#include <pulsecore/i18n.h>
#include <pulsecore/namereg.h>
#include <pulsecore/module.h>
#include <pulsecore/core-util.h>
#include <pulsecore/log.h>
#include <pulsecore/rtpoll.h>
#include <pulsecore/sample-util.h>
#include <pulsecore/ltdl-helper.h>
#include <pulsecore/sound-file.h>
#include <pulsecore/resampler.h>

#include <math.h>

PA_MODULE_AUTHOR("Niels Ole Salscheider");
PA_MODULE_DESCRIPTION(_("Virtual surround sink"));
PA_MODULE_VERSION(PACKAGE_VERSION);
PA_MODULE_LOAD_ONCE(false);
PA_MODULE_USAGE(
        _("sink_name=<name for the sink> "
          "sink_properties=<properties for the sink> "
          "master=<name of sink to filter> "
          "sink_master=<name of sink to filter> "
          "format=<sample format> "
          "rate=<sample rate> "
          "channels=<number of channels> "
          "channel_map=<channel map> "
          "use_volume_sharing=<yes or no> "
          "force_flat_volume=<yes or no> "
          "hrir=/path/to/left_hrir.wav "
          "autoloaded=<set if this module is being loaded automatically> "
        ));

#define MEMBLOCKQ_MAXLENGTH (16*1024*1024)
#define DEFAULT_AUTOLOADED false

struct userdata {
    pa_module *module;

    /* FIXME: Uncomment this and take "autoloaded" as a modarg if this is a filter */
    /* bool autoloaded; */

    pa_vsink *vsink;

    unsigned channels;
    unsigned hrir_channels;

    unsigned fs, sink_fs;

    unsigned *mapping_left;
    unsigned *mapping_right;

    unsigned hrir_samples;
    float *hrir_data;

    float *input_buffer;
    int input_buffer_offset;

};

static const char* const valid_modargs[] = {
    "sink_name",
    "sink_properties",
    "master",  /* Will be deprecated. */
    "sink_master",
    "format",
    "rate",
    "channels",
    "channel_map",
    "use_volume_sharing",
    "force_flat_volume",
    "hrir",
    "autoloaded",
    NULL
};

/* Called from I/O thread context */
static void filter_process_chunk(float *src, float *dst, unsigned in_count, unsigned out_count, void *userdata) {
    struct userdata *u;

    unsigned j, k, l;
    float sum_right, sum_left;
    float current_sample;

    pa_assert_se(u = userdata);
    pa_assert(in_count == out_count);

    for (l = 0; l < in_count; l++) {
        memcpy(((char*) u->input_buffer) + u->input_buffer_offset * u->sink_fs, ((char *) src) + l * u->sink_fs, u->sink_fs);

        sum_right = 0;
        sum_left = 0;

        /* fold the input buffer with the impulse response */
        for (j = 0; j < u->hrir_samples; j++) {
            for (k = 0; k < u->channels; k++) {
                current_sample = u->input_buffer[((u->input_buffer_offset + j) % u->hrir_samples) * u->channels + k];

                sum_left += current_sample * u->hrir_data[j * u->hrir_channels + u->mapping_left[k]];
                sum_right += current_sample * u->hrir_data[j * u->hrir_channels + u->mapping_right[k]];
            }
        }

        dst[2 * l] = PA_CLAMP_UNLIKELY(sum_left, -1.0f, 1.0f);
        dst[2 * l + 1] = PA_CLAMP_UNLIKELY(sum_right, -1.0f, 1.0f);

        u->input_buffer_offset--;
        if (u->input_buffer_offset < 0)
            u->input_buffer_offset += u->hrir_samples;
    }
}

/* Called from I/O thread context */
static void reset_filter(pa_sink *s, size_t amount) {
    struct userdata *u;

    pa_assert_se(u = s->userdata);

    /* Reset the input buffer */
    memset(u->input_buffer, 0, u->hrir_samples * u->sink_fs);
    u->input_buffer_offset = 0;
}

static pa_channel_position_t mirror_channel(pa_channel_position_t channel) {
    switch (channel) {
        case PA_CHANNEL_POSITION_FRONT_LEFT:
            return PA_CHANNEL_POSITION_FRONT_RIGHT;

        case PA_CHANNEL_POSITION_FRONT_RIGHT:
            return PA_CHANNEL_POSITION_FRONT_LEFT;

        case PA_CHANNEL_POSITION_REAR_LEFT:
            return PA_CHANNEL_POSITION_REAR_RIGHT;

        case PA_CHANNEL_POSITION_REAR_RIGHT:
            return PA_CHANNEL_POSITION_REAR_LEFT;

        case PA_CHANNEL_POSITION_SIDE_LEFT:
            return PA_CHANNEL_POSITION_SIDE_RIGHT;

        case PA_CHANNEL_POSITION_SIDE_RIGHT:
            return PA_CHANNEL_POSITION_SIDE_LEFT;

        case PA_CHANNEL_POSITION_FRONT_LEFT_OF_CENTER:
            return PA_CHANNEL_POSITION_FRONT_RIGHT_OF_CENTER;

        case PA_CHANNEL_POSITION_FRONT_RIGHT_OF_CENTER:
            return PA_CHANNEL_POSITION_FRONT_LEFT_OF_CENTER;

        case PA_CHANNEL_POSITION_TOP_FRONT_LEFT:
            return PA_CHANNEL_POSITION_TOP_FRONT_RIGHT;

        case PA_CHANNEL_POSITION_TOP_FRONT_RIGHT:
            return PA_CHANNEL_POSITION_TOP_FRONT_LEFT;

        case PA_CHANNEL_POSITION_TOP_REAR_LEFT:
            return PA_CHANNEL_POSITION_TOP_REAR_RIGHT;

        case PA_CHANNEL_POSITION_TOP_REAR_RIGHT:
            return PA_CHANNEL_POSITION_TOP_REAR_LEFT;

        default:
            return channel;
    }
}

static void normalize_hrir(struct userdata *u) {
    /* normalize hrir to avoid audible clipping
     *
     * The following heuristic tries to avoid audible clipping. It cannot avoid
     * clipping in the worst case though, because the scaling factor would
     * become too large resulting in a too quiet signal.
     * The idea of the heuristic is to avoid clipping when a single click is
     * played back on all channels. The scaling factor describes the additional
     * factor that is necessary to avoid clipping for "normal" signals.
     *
     * This algorithm doesn't pretend to be perfect, it's just something that
     * appears to work (not too quiet, no audible clipping) on the material that
     * it has been tested on. If you find a real-world example where this
     * algorithm results in audible clipping, please write a patch that adjusts
     * the scaling factor constants or improves the algorithm (or if you can't
     * write a patch, at least report the problem to the PulseAudio mailing list
     * or bug tracker). */

    const float scaling_factor = 2.5;

    float hrir_sum, hrir_max;
    unsigned i, j;

    hrir_max = 0;
    for (i = 0; i < u->hrir_samples; i++) {
        hrir_sum = 0;
        for (j = 0; j < u->hrir_channels; j++)
            hrir_sum += fabs(u->hrir_data[i * u->hrir_channels + j]);

        if (hrir_sum > hrir_max)
            hrir_max = hrir_sum;
    }

    for (i = 0; i < u->hrir_samples; i++) {
        for (j = 0; j < u->hrir_channels; j++)
            u->hrir_data[i * u->hrir_channels + j] /= hrir_max * scaling_factor;
    }
}

int pa__init(pa_module*m) {
    struct userdata *u;
    pa_sample_spec ss, sink_input_ss;
    pa_channel_map map, sink_input_map;
    pa_modargs *ma;
    const char *master_name;
    pa_sink *master = NULL;
    bool use_volume_sharing = true;

    const char *hrir_file;
    unsigned i, j, found_channel_left, found_channel_right;
    float *hrir_data;

    pa_sample_spec hrir_ss;
    pa_channel_map hrir_map;

    pa_sample_spec hrir_temp_ss;
    pa_memchunk hrir_temp_chunk, hrir_temp_chunk_resampled;
    pa_resampler *resampler;

    size_t hrir_copied_length, hrir_total_length;

    hrir_temp_chunk.memblock = NULL;
    hrir_temp_chunk_resampled.memblock = NULL;

    pa_assert(m);

    if (!(ma = pa_modargs_new(m->argument, valid_modargs))) {
        pa_log("Failed to parse module arguments.");
        goto fail;
    }

    master_name = pa_modargs_get_value(ma, "sink_master", NULL);
    if (!master_name) {
        master_name = pa_modargs_get_value(ma, "master", NULL);
        if (master_name)
            pa_log_warn("The 'master' module argument is deprecated and may be removed in the future, "
                        "please use the 'sink_master' argument instead.");
    }

    master = pa_namereg_get(m->core, master_name, PA_NAMEREG_SINK);
    if (!master) {
        pa_log("Master sink not found.");
        goto fail;
    }

    pa_assert(master);

    u = pa_xnew0(struct userdata, 1);
    u->module = m;
    m->userdata = u;

    /* Initialize hrir and input buffer */
    /* this is the hrir file for the left ear! */
    if (!(hrir_file = pa_modargs_get_value(ma, "hrir", NULL))) {
        pa_log("The mandatory 'hrir' module argument is missing.");
        goto fail;
    }

    if (pa_sound_file_load(master->core->mempool, hrir_file, &hrir_temp_ss, &hrir_map, &hrir_temp_chunk, NULL) < 0) {
        pa_log("Cannot load hrir file.");
        goto fail;
    }

    /* sample spec / map of hrir */
    hrir_ss.format = PA_SAMPLE_FLOAT32;
    hrir_ss.rate = master->sample_spec.rate;
    hrir_ss.channels = hrir_temp_ss.channels;

    /* sample spec of sink */
    ss = hrir_ss;
    map = hrir_map;
    if (pa_modargs_get_sample_spec_and_channel_map(ma, &ss, &map, PA_CHANNEL_MAP_DEFAULT) < 0) {
        pa_log("Invalid sample format specification or channel map");
        goto fail;
    }
    ss.format = PA_SAMPLE_FLOAT32;
    hrir_ss.rate = ss.rate;
    u->channels = ss.channels;

    if (pa_modargs_get_value_boolean(ma, "use_volume_sharing", &use_volume_sharing) < 0) {
        pa_log("use_volume_sharing= expects a boolean argument");
        goto fail;
    }

    /* sample spec / map of sink input */
    pa_channel_map_init_stereo(&sink_input_map);
    sink_input_ss.channels = 2;
    sink_input_ss.format = PA_SAMPLE_FLOAT32;
    sink_input_ss.rate = ss.rate;

    u->sink_fs = pa_frame_size(&ss);
    u->fs = pa_frame_size(&sink_input_ss);

    /* Create virtual sink */
    if (!(u->vsink = pa_virtual_sink_create(master, "vsurroundsink", "Virtual Surround Sink", &ss, &map,
                                 &sink_input_ss, &sink_input_map, m, u, ma, use_volume_sharing, true, 0)))
        goto fail;

    u->vsink->process_chunk = filter_process_chunk;
    u->vsink->rewind_filter = reset_filter;

    /* resample hrir */
    resampler = pa_resampler_new(u->vsink->sink->core->mempool, &hrir_temp_ss, &hrir_map, &hrir_ss, &hrir_map, u->vsink->sink->core->lfe_crossover_freq,
                                 PA_RESAMPLER_SRC_SINC_BEST_QUALITY, PA_RESAMPLER_NO_REMAP);

    u->hrir_samples = hrir_temp_chunk.length / pa_frame_size(&hrir_temp_ss) * hrir_ss.rate / hrir_temp_ss.rate;
    if (u->hrir_samples > 64) {
        u->hrir_samples = 64;
        pa_log("The (resampled) hrir contains more than 64 samples. Only the first 64 samples will be used to limit processor usage.");
    }

    hrir_total_length = u->hrir_samples * pa_frame_size(&hrir_ss);
    u->hrir_channels = hrir_ss.channels;

    u->hrir_data = (float *) pa_xmalloc(hrir_total_length);
    hrir_copied_length = 0;

    /* add silence to the hrir until we get enough samples out of the resampler */
    while (hrir_copied_length < hrir_total_length) {
        pa_resampler_run(resampler, &hrir_temp_chunk, &hrir_temp_chunk_resampled);
        if (hrir_temp_chunk.memblock != hrir_temp_chunk_resampled.memblock) {
            /* Silence input block */
            pa_silence_memblock(hrir_temp_chunk.memblock, &hrir_temp_ss);
        }

        if (hrir_temp_chunk_resampled.memblock) {
            /* Copy hrir data */
            hrir_data = (float *) pa_memblock_acquire(hrir_temp_chunk_resampled.memblock);

            if (hrir_total_length - hrir_copied_length >= hrir_temp_chunk_resampled.length) {
                memcpy(u->hrir_data + hrir_copied_length, hrir_data, hrir_temp_chunk_resampled.length);
                hrir_copied_length += hrir_temp_chunk_resampled.length;
            } else {
                memcpy(u->hrir_data + hrir_copied_length, hrir_data, hrir_total_length - hrir_copied_length);
                hrir_copied_length = hrir_total_length;
            }

            pa_memblock_release(hrir_temp_chunk_resampled.memblock);
            pa_memblock_unref(hrir_temp_chunk_resampled.memblock);
            hrir_temp_chunk_resampled.memblock = NULL;
        }
    }

    pa_resampler_free(resampler);

    pa_memblock_unref(hrir_temp_chunk.memblock);
    hrir_temp_chunk.memblock = NULL;

    if (hrir_map.channels < map.channels) {
        pa_log("hrir file does not have enough channels!");
        goto fail;
    }

    normalize_hrir(u);

    /* create mapping between hrir and input */
    u->mapping_left = (unsigned *) pa_xnew0(unsigned, u->channels);
    u->mapping_right = (unsigned *) pa_xnew0(unsigned, u->channels);
    for (i = 0; i < map.channels; i++) {
        found_channel_left = 0;
        found_channel_right = 0;

        for (j = 0; j < hrir_map.channels; j++) {
            if (hrir_map.map[j] == map.map[i]) {
                u->mapping_left[i] = j;
                found_channel_left = 1;
            }

            if (hrir_map.map[j] == mirror_channel(map.map[i])) {
                u->mapping_right[i] = j;
                found_channel_right = 1;
            }
        }

        if (!found_channel_left) {
            pa_log("Cannot find mapping for channel %s", pa_channel_position_to_string(map.map[i]));
            goto fail;
        }
        if (!found_channel_right) {
            pa_log("Cannot find mapping for channel %s", pa_channel_position_to_string(mirror_channel(map.map[i])));
            goto fail;
        }
    }

    u->input_buffer = pa_xmalloc0(u->hrir_samples * u->sink_fs);
    u->input_buffer_offset = 0;

    if (pa_virtual_sink_activate(u->vsink) < 0)
        goto fail;

    pa_modargs_free(ma);
    return 0;

fail:
    if (hrir_temp_chunk.memblock)
        pa_memblock_unref(hrir_temp_chunk.memblock);

    if (hrir_temp_chunk_resampled.memblock)
        pa_memblock_unref(hrir_temp_chunk_resampled.memblock);

    if (ma)
        pa_modargs_free(ma);

    pa__done(m);

    return -1;
}

int pa__get_n_used(pa_module *m) {
    struct userdata *u;

    pa_assert(m);
    pa_assert_se(u = m->userdata);

    return pa_sink_linked_by(u->vsink->sink);
}

void pa__done(pa_module*m) {
    struct userdata *u;

    pa_assert(m);

    if (!(u = m->userdata))
        return;

    if (u->vsink)
        pa_virtual_sink_destroy(u->vsink);

    if (u->hrir_data)
        pa_xfree(u->hrir_data);

    if (u->input_buffer)
        pa_xfree(u->input_buffer);

    if (u->mapping_left)
        pa_xfree(u->mapping_left);
    if (u->mapping_right)
        pa_xfree(u->mapping_right);

    pa_xfree(u);
}
