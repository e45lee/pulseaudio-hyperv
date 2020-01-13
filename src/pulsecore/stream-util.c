/***
  This file is part of PulseAudio.

  Copyright 2013 Intel Corporation

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

#include "stream-util.h"

#include <pulse/def.h>

#include <pulsecore/core-format.h>
#include <pulsecore/macro.h>

int pa_stream_get_volume_channel_map(const pa_cvolume *volume, const pa_channel_map *original_map, const pa_format_info *format,
                                     pa_channel_map *volume_map) {
    int r;
    pa_channel_map volume_map_local;

    pa_assert(volume);
    pa_assert(format);
    pa_assert(volume_map);

    if (original_map) {
        if (volume->channels == original_map->channels) {
            *volume_map = *original_map;
            return 0;
        }

        if (volume->channels == 1) {
            pa_channel_map_init_mono(volume_map);
            return 0;
        }

        pa_log_info("Invalid stream parameters: the volume is incompatible with the channel map.");
        return -PA_ERR_INVALID;
    }

    r = pa_format_info_get_channel_map(format, &volume_map_local);
    if (r == -PA_ERR_NOENTITY) {
        if (volume->channels == 1) {
            pa_channel_map_init_mono(volume_map);
            return 0;
        }

        pa_log_info("Invalid stream parameters: multi-channel volume is set, but channel map is not.");
        return -PA_ERR_INVALID;
    }

    if (r < 0) {
        pa_log_info("Invalid channel map.");
        return -PA_ERR_INVALID;
    }

    if (volume->channels == volume_map_local.channels) {
        *volume_map = volume_map_local;
        return 0;
    }

    if (volume->channels == 1) {
        pa_channel_map_init_mono(volume_map);
        return 0;
    }

    pa_log_info("Invalid stream parameters: the volume is incompatible with the channel map.");

    return -PA_ERR_INVALID;
}

/* Translates bytes from sink input sample spec to bytes in sink sample
 * spec. The number of frames is always rounded down. */
size_t pa_convert_to_sink_length(pa_sink_input *i, size_t length) {

    /* Convert to frames */
    length = length / pa_frame_size(&i->sample_spec);
    /* Convert frames to sink sample rate */
    length = length * i->sink->sample_spec.rate / i->sample_spec.rate;
    /* Convert to bytes */
    length *= pa_frame_size(&i->sink->sample_spec);
    return length;
}

/* Translates bytes from sink sample spec to bytes in sink input sample
 * spec. The number of frames is rounded down if the sink rate is larger
 * than the sink input rate to avoid producing too many samples on the
 * sink side. */
size_t pa_convert_to_sink_input_length(pa_sink_input *i, size_t length) {

    /* Transform from sink into sink input domain */
    if (i->thread_info.resampler)
        length = pa_resampler_request(i->thread_info.resampler, length);
    if (i->sample_spec.rate < i->sink->sample_spec.rate && length > 0)
        length = length - pa_frame_size(&i->sample_spec);
    return length;
}
