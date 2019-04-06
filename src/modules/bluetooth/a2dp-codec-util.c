/***
  This file is part of PulseAudio.

  Copyright 2019 Pali Rohár <pali.rohar@gmail.com>

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

#include <pulsecore/core.h>
#include <pulsecore/core-util.h>

#include "a2dp-codec-util.h"

extern const pa_a2dp_codec pa_a2dp_codec_sbc_lq;
extern const pa_a2dp_codec pa_a2dp_codec_faststream;
extern const pa_a2dp_codec pa_a2dp_codec_faststream_mic;
extern const pa_a2dp_codec pa_a2dp_codec_sbc_mq;
extern const pa_a2dp_codec pa_a2dp_codec_sbc;
#ifdef HAVE_OPENAPTX
extern const pa_a2dp_codec pa_a2dp_codec_aptx;
#endif
extern const pa_a2dp_codec pa_a2dp_codec_sbc_hq;
#ifdef HAVE_OPENAPTX
extern const pa_a2dp_codec pa_a2dp_codec_aptx_hd;
#endif
extern const pa_a2dp_codec pa_a2dp_codec_sbc_xq1;
extern const pa_a2dp_codec pa_a2dp_codec_sbc_xq2;

/* This is list of supported codecs. Their order is important.
 * Codec with higher index has higher priority. */
const pa_a2dp_codec *pa_a2dp_codecs[] = {
    &pa_a2dp_codec_sbc_lq,
    &pa_a2dp_codec_faststream,        /* Exactly same as SBC-LQ, but could provide lower latency */
    &pa_a2dp_codec_faststream_mic,    /* Exactly same as FastStream, but with voice backchannel */
    &pa_a2dp_codec_sbc_mq,
    &pa_a2dp_codec_sbc,               /* SBC in automatic mode, from SBC-LQ to SBC-HQ; not SBC-XQ */
#ifdef HAVE_OPENAPTX
    &pa_a2dp_codec_aptx,
#endif
    &pa_a2dp_codec_sbc_hq,            /* SBC-HQ has similar quality as aptX */
#ifdef HAVE_OPENAPTX
    &pa_a2dp_codec_aptx_hd,
#endif
    &pa_a2dp_codec_sbc_xq1,           /* SBC-XQ has similar quality as aptX-HD */
    &pa_a2dp_codec_sbc_xq2,           /* SBC-XQ has similar quality as aptX-HD */
};

unsigned int pa_bluetooth_a2dp_codec_count(void) {
    return PA_ELEMENTSOF(pa_a2dp_codecs);
}

const pa_a2dp_codec *pa_bluetooth_a2dp_codec_iter(unsigned int i) {
    pa_assert(i < pa_bluetooth_a2dp_codec_count());
    return pa_a2dp_codecs[i];
}

const pa_a2dp_codec *pa_bluetooth_get_a2dp_codec(const char *name) {
    unsigned int i;
    unsigned int count = pa_bluetooth_a2dp_codec_count();

    for (i = 0; i < count; i++) {
        if (pa_streq(pa_a2dp_codecs[i]->name, name))
            return pa_a2dp_codecs[i];
    }

    return NULL;
}
