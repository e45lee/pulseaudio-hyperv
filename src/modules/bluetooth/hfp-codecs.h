#ifndef foohfpcodecsfoo
#define foohfpcodecsfoo
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
#include <sbc/sbc.h>
#include "bt-codec-api.h"

#define HFP_AUDIO_CODEC_CVSD    0x01
#define HFP_AUDIO_CODEC_MSBC    0x02

struct hf_config {
    size_t mtu;
};

const pa_bt_codec *hf_codec_from_id(int codec);
#endif
