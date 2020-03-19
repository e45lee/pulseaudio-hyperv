#ifndef foobluez5utilhfoo
#define foobluez5utilhfoo

/***
  This file is part of PulseAudio.

  Copyright 2008-2013 João Paulo Rechi Vita
  Copyrigth 2018-2019 Pali Rohár <pali.rohar@gmail.com>

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

#include <pulsecore/core.h>

#include "a2dp-codec-util.h"

#define PA_BLUETOOTH_UUID_A2DP_SOURCE "0000110a-0000-1000-8000-00805f9b34fb"
#define PA_BLUETOOTH_UUID_A2DP_SINK   "0000110b-0000-1000-8000-00805f9b34fb"

/* There are two HSP HS UUIDs. The first one (older?) is used both as the HSP
 * profile identifier and as the HS role identifier, while the second one is
 * only used to identify the role. As far as PulseAudio is concerned, the two
 * UUIDs mean exactly the same thing. */
#define PA_BLUETOOTH_UUID_HSP_HS      "00001108-0000-1000-8000-00805f9b34fb"
#define PA_BLUETOOTH_UUID_HSP_HS_ALT  "00001131-0000-1000-8000-00805f9b34fb"

#define PA_BLUETOOTH_UUID_HSP_AG      "00001112-0000-1000-8000-00805f9b34fb"
#define PA_BLUETOOTH_UUID_HFP_HF      "0000111e-0000-1000-8000-00805f9b34fb"
#define PA_BLUETOOTH_UUID_HFP_AG      "0000111f-0000-1000-8000-00805f9b34fb"

typedef struct pa_bluetooth_transport pa_bluetooth_transport;
typedef struct pa_bluetooth_device pa_bluetooth_device;
typedef struct pa_bluetooth_adapter pa_bluetooth_adapter;
typedef struct pa_bluetooth_discovery pa_bluetooth_discovery;
typedef struct pa_bluetooth_backend pa_bluetooth_backend;

typedef enum pa_bluetooth_hook {
    PA_BLUETOOTH_HOOK_DEVICE_CONNECTION_CHANGED,          /* Call data: pa_bluetooth_device */
    PA_BLUETOOTH_HOOK_DEVICE_UNLINK,                      /* Call data: pa_bluetooth_device */
    PA_BLUETOOTH_HOOK_TRANSPORT_STATE_CHANGED,            /* Call data: pa_bluetooth_transport */
    PA_BLUETOOTH_HOOK_TRANSPORT_MICROPHONE_GAIN_CHANGED,  /* Call data: pa_bluetooth_transport */
    PA_BLUETOOTH_HOOK_TRANSPORT_SPEAKER_GAIN_CHANGED,     /* Call data: pa_bluetooth_transport */
    PA_BLUETOOTH_HOOK_MAX
} pa_bluetooth_hook_t;

/* Profile index is used also for card profile priority. Higher number has higher priority.
 * All A2DP profiles have higher priority as all non-A2DP profiles.
 * And all A2DP sink profiles have higher priority as all A2DP source profiles. */
#define PA_BLUETOOTH_PROFILE_OFF                    0
#define PA_BLUETOOTH_PROFILE_HEADSET_AUDIO_GATEWAY  1
#define PA_BLUETOOTH_PROFILE_HEADSET_HEAD_UNIT      2
#define PA_BLUETOOTH_PROFILE_A2DP_START_INDEX       3
typedef unsigned pa_bluetooth_profile_t;

typedef enum pa_bluetooth_transport_state {
    PA_BLUETOOTH_TRANSPORT_STATE_DISCONNECTED,
    PA_BLUETOOTH_TRANSPORT_STATE_IDLE,
    PA_BLUETOOTH_TRANSPORT_STATE_PLAYING
} pa_bluetooth_transport_state_t;

typedef int (*pa_bluetooth_transport_acquire_cb)(pa_bluetooth_transport *t, bool optional, size_t *imtu, size_t *omtu);
typedef void (*pa_bluetooth_transport_release_cb)(pa_bluetooth_transport *t);
typedef void (*pa_bluetooth_transport_destroy_cb)(pa_bluetooth_transport *t);
typedef void (*pa_bluetooth_transport_set_speaker_gain_cb)(pa_bluetooth_transport *t, uint16_t gain);
typedef void (*pa_bluetooth_transport_set_microphone_gain_cb)(pa_bluetooth_transport *t, uint16_t gain);

struct pa_bluetooth_transport {
    pa_bluetooth_device *device;

    char *owner;
    char *path;
    pa_bluetooth_profile_t profile;

    uint8_t *config;
    size_t config_size;

    uint16_t microphone_gain;
    uint16_t speaker_gain;

    pa_bluetooth_transport_state_t state;

    pa_bluetooth_transport_acquire_cb acquire;
    pa_bluetooth_transport_release_cb release;
    pa_bluetooth_transport_destroy_cb destroy;
    pa_bluetooth_transport_set_speaker_gain_cb set_speaker_gain;
    pa_bluetooth_transport_set_microphone_gain_cb set_microphone_gain;
    void *userdata;
};

struct pa_bluetooth_device {
    pa_bluetooth_discovery *discovery;
    pa_bluetooth_adapter *adapter;

    bool properties_received;
    bool tried_to_link_with_adapter;
    bool valid;
    bool autodetect_mtu;
    bool change_a2dp_profile_in_progress;

    /* Device information */
    char *path;
    char *adapter_path;
    char *alias;
    char *address;
    uint32_t class_of_device;
    pa_hashmap *uuids; /* char* -> char* (hashmap-as-a-set) */
    pa_hashmap *a2dp_sink_endpoints; /* pa_a2dp_codec_id* -> pa_hashmap ( char* (remote endpoint) -> struct a2dp_codec_capabilities* ) */
    pa_hashmap *a2dp_source_endpoints; /* pa_a2dp_codec_id* -> pa_hashmap ( char* (remote endpoint) -> struct a2dp_codec_capabilities* ) */

    pa_bluetooth_transport **transports;

    pa_time_event *wait_for_profiles_timer;
};

struct pa_bluetooth_adapter {
    pa_bluetooth_discovery *discovery;
    char *path;
    char *address;

    bool valid;
    bool media_application_registered;
};

#ifdef HAVE_BLUEZ_5_LEGACY_HSP
pa_bluetooth_backend *pa_bluetooth_legacy_hsp_backend_new(pa_core *c, pa_bluetooth_discovery *y, bool enable_hs_role);
void pa_bluetooth_legacy_hsp_backend_free(pa_bluetooth_backend *b);
void pa_bluetooth_legacy_hsp_backend_enable_hs_role(pa_bluetooth_backend *b, bool enable_hs_role);
#else
static inline pa_bluetooth_backend *pa_bluetooth_legacy_hsp_backend_new(pa_core *c, pa_bluetooth_discovery *y, bool enable_hs_role) {
    return NULL;
}
static inline void pa_bluetooth_legacy_hsp_backend_free(pa_bluetooth_backend *b) {}
static inline void pa_bluetooth_legacy_hsp_backend_enable_hs_role(pa_bluetooth_backend *b, bool enable_hs_role) {}
#endif

pa_bluetooth_transport *pa_bluetooth_transport_new(pa_bluetooth_device *d, const char *owner, const char *path,
                                                   pa_bluetooth_profile_t p, const uint8_t *config, size_t size);

void pa_bluetooth_transport_set_state(pa_bluetooth_transport *t, pa_bluetooth_transport_state_t state);
void pa_bluetooth_transport_put(pa_bluetooth_transport *t);
void pa_bluetooth_transport_unlink(pa_bluetooth_transport *t);
void pa_bluetooth_transport_free(pa_bluetooth_transport *t);

size_t pa_bluetooth_device_find_a2dp_endpoints_for_codec(const pa_bluetooth_device *device, const pa_a2dp_codec *a2dp_codec, bool is_a2dp_sink, const char **endpoints, size_t endpoints_max_count);
bool pa_bluetooth_device_change_a2dp_profile(pa_bluetooth_device *d, pa_bluetooth_profile_t profile, void (*cb)(bool, void *), void *userdata);

bool pa_bluetooth_device_any_transport_connected(const pa_bluetooth_device *d);

pa_bluetooth_device* pa_bluetooth_discovery_get_device_by_path(pa_bluetooth_discovery *y, const char *path);
pa_bluetooth_device* pa_bluetooth_discovery_get_device_by_address(pa_bluetooth_discovery *y, const char *remote, const char *local);

pa_hook* pa_bluetooth_discovery_hook(pa_bluetooth_discovery *y, pa_bluetooth_hook_t hook);

unsigned pa_bluetooth_profile_count(void);
bool pa_bluetooth_profile_is_a2dp_sink(pa_bluetooth_profile_t profile);
bool pa_bluetooth_profile_is_a2dp_source(pa_bluetooth_profile_t profile);
const pa_a2dp_codec *pa_bluetooth_profile_to_a2dp_codec(pa_bluetooth_profile_t profile);
pa_bluetooth_profile_t pa_bluetooth_profile_for_a2dp_codec(const char *codec_name, bool is_a2dp_sink);
const char *pa_bluetooth_profile_to_string(pa_bluetooth_profile_t profile);

static inline bool pa_bluetooth_profile_is_a2dp(pa_bluetooth_profile_t profile) {
    return pa_bluetooth_profile_is_a2dp_sink(profile) || pa_bluetooth_profile_is_a2dp_source(profile);
}

static inline bool pa_bluetooth_profile_support_a2dp_backchannel(pa_bluetooth_profile_t profile) {
    return pa_bluetooth_profile_to_a2dp_codec(profile)->support_backchannel;
}

static inline bool pa_bluetooth_uuid_is_hsp_hs(const char *uuid) {
    return pa_streq(uuid, PA_BLUETOOTH_UUID_HSP_HS) || pa_streq(uuid, PA_BLUETOOTH_UUID_HSP_HS_ALT);
}

#define HEADSET_BACKEND_LEGACY_HSP 1
#define HEADSET_BACKEND_AUTO 2

pa_bluetooth_discovery* pa_bluetooth_discovery_get(pa_core *core, int headset_backend);
pa_bluetooth_discovery* pa_bluetooth_discovery_ref(pa_bluetooth_discovery *y);
void pa_bluetooth_discovery_unref(pa_bluetooth_discovery *y);
#endif
