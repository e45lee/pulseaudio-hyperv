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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pulse/rtclock.h>
#include <pulse/timeval.h>
#include <pulse/xmalloc.h>

#include <pulsecore/core.h>
#include <pulsecore/core-util.h>
#include <pulsecore/dbus-shared.h>
#include <pulsecore/log.h>
#include <pulsecore/macro.h>
#include <pulsecore/refcnt.h>
#include <pulsecore/shared.h>

#include "a2dp-codec-util.h"
#include "a2dp-codecs.h"

#include "bluez5-util.h"

#define WAIT_FOR_PROFILES_TIMEOUT_USEC (3 * PA_USEC_PER_SEC)

#define BLUEZ_SERVICE "org.bluez"
#define BLUEZ_ADAPTER_INTERFACE BLUEZ_SERVICE ".Adapter1"
#define BLUEZ_DEVICE_INTERFACE BLUEZ_SERVICE ".Device1"
#define BLUEZ_MEDIA_INTERFACE BLUEZ_SERVICE ".Media1"
#define BLUEZ_MEDIA_ENDPOINT_INTERFACE BLUEZ_SERVICE ".MediaEndpoint1"
#define BLUEZ_MEDIA_TRANSPORT_INTERFACE BLUEZ_SERVICE ".MediaTransport1"

#define BLUEZ_ERROR_NOT_SUPPORTED "org.bluez.Error.NotSupported"

#define A2DP_OBJECT_MANAGER_PATH "/A2DPEndpoint"
#define A2DP_SOURCE_ENDPOINT A2DP_OBJECT_MANAGER_PATH "/Source"
#define A2DP_SINK_ENDPOINT A2DP_OBJECT_MANAGER_PATH "/Sink"

#define OBJECT_MANAGER_INTROSPECT_XML                                          \
    DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                                  \
    "<node>\n"                                                                 \
    " <interface name=\"org.freedesktop.DBus.ObjectManager\">\n"               \
    "  <method name=\"GetManagedObjects\">\n"                                  \
    "   <arg name=\"objects\" direction=\"out\" type=\"a{oa{sa{sv}}}\"/>\n"    \
    "  </method>\n"                                                            \
    "  <signal name=\"InterfacesAdded\">\n"                                    \
    "   <arg name=\"object\" type=\"o\"/>\n"                                   \
    "   <arg name=\"interfaces\" type=\"a{sa{sv}}\"/>\n"                       \
    "  </signal>\n"                                                            \
    "  <signal name=\"InterfacesRemoved\">\n"                                  \
    "   <arg name=\"object\" type=\"o\"/>\n"                                   \
    "   <arg name=\"interfaces\" type=\"as\"/>\n"                              \
    "  </signal>\n"                                                            \
    " </interface>\n"                                                          \
    " <interface name=\"org.freedesktop.DBus.Introspectable\">\n"              \
    "  <method name=\"Introspect\">\n"                                         \
    "   <arg name=\"data\" direction=\"out\" type=\"s\"/>\n"                   \
    "  </method>\n"                                                            \
    " </interface>\n"                                                          \
    " <node name=\"A2DPSink\"/>\n"                                             \
    " <node name=\"A2DPSource\"/>\n"                                           \
    "</node>\n"

#define ENDPOINT_INTROSPECT_XML                                         \
    DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                           \
    "<node>\n"                                                          \
    " <interface name=\"" BLUEZ_MEDIA_ENDPOINT_INTERFACE "\">\n"        \
    "  <method name=\"SetConfiguration\">\n"                            \
    "   <arg name=\"transport\" direction=\"in\" type=\"o\"/>\n"        \
    "   <arg name=\"properties\" direction=\"in\" type=\"ay\"/>\n"      \
    "  </method>\n"                                                     \
    "  <method name=\"SelectConfiguration\">\n"                         \
    "   <arg name=\"capabilities\" direction=\"in\" type=\"ay\"/>\n"    \
    "   <arg name=\"configuration\" direction=\"out\" type=\"ay\"/>\n"  \
    "  </method>\n"                                                     \
    "  <method name=\"ClearConfiguration\">\n"                          \
    "   <arg name=\"transport\" direction=\"in\" type=\"o\"/>\n"        \
    "  </method>\n"                                                     \
    "  <method name=\"Release\">\n"                                     \
    "  </method>\n"                                                     \
    " </interface>\n"                                                   \
    " <interface name=\"org.freedesktop.DBus.Introspectable\">\n"       \
    "  <method name=\"Introspect\">\n"                                  \
    "   <arg name=\"data\" type=\"s\" direction=\"out\"/>\n"            \
    "  </method>\n"                                                     \
    " </interface>\n"                                                   \
    "</node>\n"

struct pa_bluetooth_discovery {
    PA_REFCNT_DECLARE;

    pa_core *core;
    pa_dbus_connection *connection;
    bool filter_added;
    bool matches_added;
    bool objects_listed;
    pa_hook hooks[PA_BLUETOOTH_HOOK_MAX];
    pa_hashmap *adapters;
    pa_hashmap *devices;
    pa_hashmap *transports;

    int headset_backend;
    pa_bluetooth_backend *hsphfpd_backend;
    pa_bluetooth_backend *legacy_hsp_backend;
    PA_LLIST_HEAD(pa_dbus_pending, pending);
};

struct a2dp_codec_capabilities {
    uint8_t size;
    uint8_t buffer[]; /* max size is 254 bytes */
};

static pa_dbus_pending* send_and_add_to_pending(pa_bluetooth_discovery *y, DBusMessage *m,
                                                                  DBusPendingCallNotifyFunction func, void *call_data) {
    pa_dbus_pending *p;
    DBusPendingCall *call;

    pa_assert(y);
    pa_assert(m);

    pa_assert_se(dbus_connection_send_with_reply(pa_dbus_connection_get(y->connection), m, &call, -1));

    p = pa_dbus_pending_new(pa_dbus_connection_get(y->connection), m, call, y, call_data);
    PA_LLIST_PREPEND(pa_dbus_pending, y->pending, p);
    dbus_pending_call_set_notify(call, func, p, NULL);

    return p;
}

static const char *check_variant_property(DBusMessageIter *i) {
    const char *key;

    pa_assert(i);

    if (dbus_message_iter_get_arg_type(i) != DBUS_TYPE_STRING) {
        pa_log_error("Property name not a string.");
        return NULL;
    }

    dbus_message_iter_get_basic(i, &key);

    if (!dbus_message_iter_next(i)) {
        pa_log_error("Property value missing");
        return NULL;
    }

    if (dbus_message_iter_get_arg_type(i) != DBUS_TYPE_VARIANT) {
        pa_log_error("Property value not a variant.");
        return NULL;
    }

    return key;
}

pa_bluetooth_transport *pa_bluetooth_transport_new(pa_bluetooth_device *d, const char *owner, const char *path,
                                                   pa_bluetooth_profile_t p, const uint8_t *config, size_t size) {
    pa_bluetooth_transport *t;

    t = pa_xnew0(pa_bluetooth_transport, 1);
    t->device = d;
    t->owner = pa_xstrdup(owner);
    t->path = pa_xstrdup(path);
    t->profile = p;
    t->config_size = size;

    if (size > 0) {
        t->config = pa_xnew(uint8_t, size);
        memcpy(t->config, config, size);
    }

    return t;
}

static const char *transport_state_to_string(pa_bluetooth_transport_state_t state) {
    switch(state) {
        case PA_BLUETOOTH_TRANSPORT_STATE_DISCONNECTED:
            return "disconnected";
        case PA_BLUETOOTH_TRANSPORT_STATE_IDLE:
            return "idle";
        case PA_BLUETOOTH_TRANSPORT_STATE_PLAYING:
            return "playing";
    }

    return "invalid";
}

static bool device_supports_profile(pa_bluetooth_device *device, pa_bluetooth_profile_t profile) {
    const struct a2dp_codec_capabilities *a2dp_codec_capabilities;
    const pa_a2dp_codec *a2dp_codec;
    bool is_a2dp_sink;
    pa_hashmap *endpoints;
    void *state;

    switch (profile) {
        case PA_BLUETOOTH_PROFILE_HSP_HEAD_UNIT:
            return !!pa_hashmap_get(device->uuids, PA_BLUETOOTH_UUID_HSP_HS)
                || !!pa_hashmap_get(device->uuids, PA_BLUETOOTH_UUID_HSP_HS_ALT);
        case PA_BLUETOOTH_PROFILE_HFP_HEAD_UNIT:
            return !!pa_hashmap_get(device->uuids, PA_BLUETOOTH_UUID_HFP_HF);
        case PA_BLUETOOTH_PROFILE_HSP_AUDIO_GATEWAY:
            return !!pa_hashmap_get(device->uuids, PA_BLUETOOTH_UUID_HSP_AG);
        case PA_BLUETOOTH_PROFILE_HFP_AUDIO_GATEWAY:
            return !!pa_hashmap_get(device->uuids, PA_BLUETOOTH_UUID_HFP_AG);
        case PA_BLUETOOTH_PROFILE_OFF:
            return true;
        default:
            break;
    }

    a2dp_codec = pa_bluetooth_profile_to_a2dp_codec(profile);
    is_a2dp_sink = pa_bluetooth_profile_is_a2dp_sink(profile);

    if (is_a2dp_sink && !pa_hashmap_get(device->uuids, PA_BLUETOOTH_UUID_A2DP_SINK))
        return false;
    else if (!is_a2dp_sink && !pa_hashmap_get(device->uuids, PA_BLUETOOTH_UUID_A2DP_SOURCE))
        return false;

    if (is_a2dp_sink)
        endpoints = pa_hashmap_get(device->a2dp_sink_endpoints, &a2dp_codec->id);
    else
        endpoints = pa_hashmap_get(device->a2dp_source_endpoints, &a2dp_codec->id);

    if (!endpoints)
        return false;

    PA_HASHMAP_FOREACH(a2dp_codec_capabilities, endpoints, state) {
        if (a2dp_codec->can_accept_capabilities(a2dp_codec_capabilities->buffer, a2dp_codec_capabilities->size, is_a2dp_sink))
            return true;
    }

    return false;
}

static bool device_is_profile_connected(pa_bluetooth_device *device, pa_bluetooth_profile_t profile) {
    if (device->transports[profile] && device->transports[profile]->state != PA_BLUETOOTH_TRANSPORT_STATE_DISCONNECTED)
        return true;
    else
        return false;
}

static unsigned device_count_disconnected_profiles(pa_bluetooth_device *device) {
    pa_bluetooth_profile_t profile;
    unsigned bluetooth_profile_count;
    unsigned count = 0;

    bluetooth_profile_count = pa_bluetooth_profile_count();
    for (profile = 0; profile < bluetooth_profile_count; profile++) {
        if (!device_supports_profile(device, profile))
            continue;

        if (!device_is_profile_connected(device, profile))
            count++;
    }

    return count;
}

static void device_stop_waiting_for_profiles(pa_bluetooth_device *device) {
    if (!device->wait_for_profiles_timer)
        return;

    device->discovery->core->mainloop->time_free(device->wait_for_profiles_timer);
    device->wait_for_profiles_timer = NULL;
}

static void wait_for_profiles_cb(pa_mainloop_api *api, pa_time_event* event, const struct timeval *tv, void *userdata) {
    pa_bluetooth_device *device = userdata;
    pa_strbuf *buf;
    pa_bluetooth_profile_t profile;
    unsigned bluetooth_profile_count;
    bool first = true;
    char *profiles_str;

    device_stop_waiting_for_profiles(device);

    buf = pa_strbuf_new();

    bluetooth_profile_count = pa_bluetooth_profile_count();
    for (profile = 0; profile < bluetooth_profile_count; profile++) {
        if (device_is_profile_connected(device, profile))
            continue;

        if (!device_supports_profile(device, profile))
            continue;

        if (first)
            first = false;
        else
            pa_strbuf_puts(buf, ", ");

        pa_strbuf_puts(buf, pa_bluetooth_profile_to_string(profile));
    }

    profiles_str = pa_strbuf_to_string_free(buf);
    pa_log_debug("Timeout expired, and device %s still has disconnected profiles: %s",
                 device->path, profiles_str);
    pa_xfree(profiles_str);
    pa_hook_fire(&device->discovery->hooks[PA_BLUETOOTH_HOOK_DEVICE_CONNECTION_CHANGED], device);
}

static void device_start_waiting_for_profiles(pa_bluetooth_device *device) {
    pa_assert(!device->wait_for_profiles_timer);
    device->wait_for_profiles_timer = pa_core_rttime_new(device->discovery->core,
                                                         pa_rtclock_now() + WAIT_FOR_PROFILES_TIMEOUT_USEC,
                                                         wait_for_profiles_cb, device);
}

void pa_bluetooth_transport_set_state(pa_bluetooth_transport *t, pa_bluetooth_transport_state_t state) {
    bool old_any_connected;
    unsigned n_disconnected_profiles;
    bool new_device_appeared;
    bool device_disconnected;

    pa_assert(t);

    if (t->state == state)
        return;

    old_any_connected = pa_bluetooth_device_any_transport_connected(t->device);

    pa_log_debug("Transport %s state: %s -> %s",
                 t->path, transport_state_to_string(t->state), transport_state_to_string(state));

    t->state = state;

    pa_hook_fire(&t->device->discovery->hooks[PA_BLUETOOTH_HOOK_TRANSPORT_STATE_CHANGED], t);

    /* If there are profiles that are expected to get connected soon (based
     * on the UUID list), we wait for a bit before announcing the new
     * device, so that all profiles have time to get connected before the
     * card object is created. If we didn't wait, the card would always
     * have only one profile marked as available in the initial state,
     * which would prevent module-card-restore from restoring the initial
     * profile properly. */

    n_disconnected_profiles = device_count_disconnected_profiles(t->device);

    new_device_appeared = !old_any_connected && pa_bluetooth_device_any_transport_connected(t->device);
    device_disconnected = old_any_connected && !pa_bluetooth_device_any_transport_connected(t->device);

    if (new_device_appeared) {
        if (n_disconnected_profiles > 0)
            device_start_waiting_for_profiles(t->device);
        else
            pa_hook_fire(&t->device->discovery->hooks[PA_BLUETOOTH_HOOK_DEVICE_CONNECTION_CHANGED], t->device);
        return;
    }

    if (device_disconnected) {
        if (t->device->wait_for_profiles_timer) {
            /* If the timer is still running when the device disconnects, we
             * never sent the notification of the device getting connected, so
             * we don't need to send a notification about the disconnection
             * either. Let's just stop the timer. */
            device_stop_waiting_for_profiles(t->device);
        } else
            pa_hook_fire(&t->device->discovery->hooks[PA_BLUETOOTH_HOOK_DEVICE_CONNECTION_CHANGED], t->device);
        return;
    }

    if (n_disconnected_profiles == 0 && t->device->wait_for_profiles_timer) {
        /* All profiles are now connected, so we can stop the wait timer and
         * send a notification of the new device. */
        device_stop_waiting_for_profiles(t->device);
        pa_hook_fire(&t->device->discovery->hooks[PA_BLUETOOTH_HOOK_DEVICE_CONNECTION_CHANGED], t->device);
    }
}

pa_bluetooth_transport *pa_bluetooth_transport_get(pa_bluetooth_discovery *y, const char *path) {
    pa_assert(path);
    return pa_hashmap_get(y->transports, path);
}

pa_hashmap *pa_bluetooth_transport_get_all(pa_bluetooth_discovery *y) {
    return y->transports;
}

void pa_bluetooth_transport_put(pa_bluetooth_transport *t) {
    pa_assert(t);

    t->device->transports[t->profile] = t;
    pa_assert_se(pa_hashmap_put(t->device->discovery->transports, t->path, t) >= 0);
    pa_bluetooth_transport_set_state(t, PA_BLUETOOTH_TRANSPORT_STATE_IDLE);
}

void pa_bluetooth_transport_free(pa_bluetooth_transport *t) {
    pa_assert(t);

    if (t->destroy)
        t->destroy(t);

    pa_bluetooth_transport_set_state(t, PA_BLUETOOTH_TRANSPORT_STATE_DISCONNECTED);
    pa_hashmap_remove(t->device->discovery->transports, t->path);
    t->device->transports[t->profile] = NULL;

    pa_xfree(t->owner);
    pa_xfree(t->path);
    pa_xfree(t->config);
    pa_xfree(t);
}

static int bluez5_transport_acquire_cb(pa_bluetooth_transport *t, size_t *imtu, size_t *omtu) {
    DBusMessage *m, *r;
    DBusError err;
    int ret;
    uint16_t i, o;

    pa_assert(t);
    pa_assert(t->device);
    pa_assert(t->device->discovery);

    pa_assert_se(m = dbus_message_new_method_call(t->owner, t->path, BLUEZ_MEDIA_TRANSPORT_INTERFACE, "Acquire"));

    dbus_error_init(&err);

    r = dbus_connection_send_with_reply_and_block(pa_dbus_connection_get(t->device->discovery->connection), m, -1, &err);
    dbus_message_unref(m);
    m = NULL;
    if (!r) {
        pa_log_error("Transport Acquire() failed for transport %s (%s)", t->path, err.message);

        dbus_error_free(&err);
        return -1;
    }

    if (!dbus_message_get_args(r, &err, DBUS_TYPE_UNIX_FD, &ret, DBUS_TYPE_UINT16, &i, DBUS_TYPE_UINT16, &o,
                               DBUS_TYPE_INVALID)) {
        pa_log_error("Failed to parse Acquire() reply: %s", err.message);
        dbus_error_free(&err);
        ret = -1;
        goto finish;
    }

    if (imtu)
        *imtu = i;

    if (omtu)
        *omtu = o;

finish:
    dbus_message_unref(r);
    return ret;
}

static void bluez5_transport_release_cb(pa_bluetooth_transport *t) {
    DBusMessage *m, *r;
    DBusError err;

    pa_assert(t);
    pa_assert(t->device);
    pa_assert(t->device->discovery);

    dbus_error_init(&err);

    if (t->state <= PA_BLUETOOTH_TRANSPORT_STATE_IDLE) {
        pa_log_info("Transport %s auto-released by BlueZ or already released", t->path);
        return;
    }

    pa_assert_se(m = dbus_message_new_method_call(t->owner, t->path, BLUEZ_MEDIA_TRANSPORT_INTERFACE, "Release"));
    r = dbus_connection_send_with_reply_and_block(pa_dbus_connection_get(t->device->discovery->connection), m, -1, &err);
    dbus_message_unref(m);
    m = NULL;
    if (r) {
        dbus_message_unref(r);
        r = NULL;
    }

    if (dbus_error_is_set(&err)) {
        pa_log_error("Failed to release transport %s: %s", t->path, err.message);
        dbus_error_free(&err);
    } else
        pa_log_info("Transport %s released", t->path);
}

bool pa_bluetooth_device_any_transport_connected(const pa_bluetooth_device *d) {
    unsigned i, bluetooth_profile_count;

    pa_assert(d);

    if (!d->valid)
        return false;

    bluetooth_profile_count = pa_bluetooth_profile_count();
    for (i = 0; i < bluetooth_profile_count; i++)
        if (d->transports[i] && d->transports[i]->state != PA_BLUETOOTH_TRANSPORT_STATE_DISCONNECTED)
            return true;

    return false;
}

static int transport_state_from_string(const char* value, pa_bluetooth_transport_state_t *state) {
    pa_assert(value);
    pa_assert(state);

    if (pa_streq(value, "idle"))
        *state = PA_BLUETOOTH_TRANSPORT_STATE_IDLE;
    else if (pa_streq(value, "pending") || pa_streq(value, "active"))
        *state = PA_BLUETOOTH_TRANSPORT_STATE_PLAYING;
    else
        return -1;

    return 0;
}

static void parse_transport_property(pa_bluetooth_transport *t, DBusMessageIter *i) {
    const char *key;
    DBusMessageIter variant_i;

    key = check_variant_property(i);
    if (key == NULL)
        return;

    dbus_message_iter_recurse(i, &variant_i);

    switch (dbus_message_iter_get_arg_type(&variant_i)) {

        case DBUS_TYPE_STRING: {

            const char *value;
            dbus_message_iter_get_basic(&variant_i, &value);

            if (pa_streq(key, "State")) {
                pa_bluetooth_transport_state_t state;

                if (transport_state_from_string(value, &state) < 0) {
                    pa_log_error("Invalid state received: %s", value);
                    return;
                }

                pa_bluetooth_transport_set_state(t, state);
            }

            break;
        }
    }

    return;
}

static int parse_transport_properties(pa_bluetooth_transport *t, DBusMessageIter *i) {
    DBusMessageIter element_i;

    dbus_message_iter_recurse(i, &element_i);

    while (dbus_message_iter_get_arg_type(&element_i) == DBUS_TYPE_DICT_ENTRY) {
        DBusMessageIter dict_i;

        dbus_message_iter_recurse(&element_i, &dict_i);

        parse_transport_property(t, &dict_i);

        dbus_message_iter_next(&element_i);
    }

    return 0;
}

static unsigned pa_a2dp_codec_id_hash_func(const void *_p) {
    unsigned hash;
    const pa_a2dp_codec_id *p = _p;

    hash = p->codec_id;
    hash = 31 * hash + ((p->vendor_id >>  0) & 0xFF);
    hash = 31 * hash + ((p->vendor_id >>  8) & 0xFF);
    hash = 31 * hash + ((p->vendor_id >> 16) & 0xFF);
    hash = 31 * hash + ((p->vendor_id >> 24) & 0xFF);
    hash = 31 * hash + ((p->vendor_codec_id >> 0) & 0xFF);
    hash = 31 * hash + ((p->vendor_codec_id >> 8) & 0xFF);
    return hash;
}

static int pa_a2dp_codec_id_compare_func(const void *_a, const void *_b) {
    const pa_a2dp_codec_id *a = _a;
    const pa_a2dp_codec_id *b = _b;

    if (a->codec_id < b->codec_id)
        return -1;
    if (a->codec_id > b->codec_id)
        return 1;

    if (a->vendor_id < b->vendor_id)
        return -1;
    if (a->vendor_id > b->vendor_id)
        return 1;

    if (a->vendor_codec_id < b->vendor_codec_id)
        return -1;
    if (a->vendor_codec_id > b->vendor_codec_id)
        return 1;

    return 0;
}

static pa_bluetooth_device* device_create(pa_bluetooth_discovery *y, const char *path) {
    pa_bluetooth_device *d;

    pa_assert(y);
    pa_assert(path);

    d = pa_xnew0(pa_bluetooth_device, 1);
    d->discovery = y;
    d->path = pa_xstrdup(path);
    d->uuids = pa_hashmap_new_full(pa_idxset_string_hash_func, pa_idxset_string_compare_func, NULL, pa_xfree);
    d->a2dp_sink_endpoints = pa_hashmap_new_full(pa_a2dp_codec_id_hash_func, pa_a2dp_codec_id_compare_func, pa_xfree, (pa_free_cb_t)pa_hashmap_free);
    d->a2dp_source_endpoints = pa_hashmap_new_full(pa_a2dp_codec_id_hash_func, pa_a2dp_codec_id_compare_func, pa_xfree, (pa_free_cb_t)pa_hashmap_free);
    d->transports = pa_xnew0(pa_bluetooth_transport *, pa_bluetooth_profile_count());

    pa_hashmap_put(y->devices, d->path, d);

    return d;
}

pa_bluetooth_device* pa_bluetooth_discovery_get_device_by_path(pa_bluetooth_discovery *y, const char *path) {
    pa_bluetooth_device *d;

    pa_assert(y);
    pa_assert(PA_REFCNT_VALUE(y) > 0);
    pa_assert(path);

    if ((d = pa_hashmap_get(y->devices, path)) && d->valid)
        return d;

    return NULL;
}

pa_bluetooth_device* pa_bluetooth_discovery_get_device_by_address(pa_bluetooth_discovery *y, const char *remote, const char *local) {
    pa_bluetooth_device *d;
    void *state = NULL;

    pa_assert(y);
    pa_assert(PA_REFCNT_VALUE(y) > 0);
    pa_assert(remote);
    pa_assert(local);

    while ((d = pa_hashmap_iterate(y->devices, &state, NULL)))
        if (d->valid && pa_streq(d->address, remote) && pa_streq(d->adapter->address, local))
            return d;

    return NULL;
}

static void remote_endpoint_remove(pa_bluetooth_discovery *y, const char *path) {
    pa_bluetooth_device *device;
    pa_hashmap *endpoints;
    void *devices_state;
    void *state;

    PA_HASHMAP_FOREACH(device, y->devices, devices_state) {
        PA_HASHMAP_FOREACH(endpoints, device->a2dp_sink_endpoints, state)
            pa_hashmap_remove_and_free(endpoints, path);

        PA_HASHMAP_FOREACH(endpoints, device->a2dp_source_endpoints, state)
            pa_hashmap_remove_and_free(endpoints, path);
    }

    pa_log_debug("Remote endpoint %s was removed", path);
}

static void device_free(pa_bluetooth_device *d) {
    unsigned i, bluetooth_profile_count;

    pa_assert(d);

    device_stop_waiting_for_profiles(d);

    pa_hook_fire(&d->discovery->hooks[PA_BLUETOOTH_HOOK_DEVICE_UNLINK], d);

    bluetooth_profile_count = pa_bluetooth_profile_count();
    for (i = 0; i < bluetooth_profile_count; i++) {
        pa_bluetooth_transport *t;

        if (!(t = d->transports[i]))
            continue;

        pa_bluetooth_transport_free(t);
    }

    pa_hashmap_free(d->uuids);
    pa_hashmap_free(d->a2dp_sink_endpoints);
    pa_hashmap_free(d->a2dp_source_endpoints);

    pa_xfree(d->transports);
    pa_xfree(d->path);
    pa_xfree(d->alias);
    pa_xfree(d->address);
    pa_xfree(d->adapter_path);
    pa_xfree(d);
}

static void device_remove(pa_bluetooth_discovery *y, const char *path) {
    pa_bluetooth_device *d;

    if (!(d = pa_hashmap_remove(y->devices, path)))
        pa_log_warn("Unknown device removed %s", path);
    else {
        pa_log_debug("Device %s removed", path);
        device_free(d);
    }
}

static void device_set_valid(pa_bluetooth_device *device, bool valid) {
    bool old_any_connected;

    pa_assert(device);

    if (valid == device->valid)
        return;

    old_any_connected = pa_bluetooth_device_any_transport_connected(device);
    device->valid = valid;

    if (pa_bluetooth_device_any_transport_connected(device) != old_any_connected)
        pa_hook_fire(&device->discovery->hooks[PA_BLUETOOTH_HOOK_DEVICE_CONNECTION_CHANGED], device);
}

static void device_update_valid(pa_bluetooth_device *d) {
    pa_assert(d);

    if (!d->properties_received) {
        pa_assert(!d->valid);
        return;
    }

    /* Check if mandatory properties are set. */
    if (!d->address || !d->adapter_path || !d->alias) {
        device_set_valid(d, false);
        return;
    }

    if (!d->adapter || !d->adapter->valid) {
        device_set_valid(d, false);
        return;
    }

    device_set_valid(d, true);
}

static void device_set_adapter(pa_bluetooth_device *device, pa_bluetooth_adapter *adapter) {
    pa_assert(device);

    if (adapter == device->adapter)
        return;

    device->adapter = adapter;

    device_update_valid(device);
}

static pa_bluetooth_adapter* adapter_create(pa_bluetooth_discovery *y, const char *path) {
    pa_bluetooth_adapter *a;

    pa_assert(y);
    pa_assert(path);

    a = pa_xnew0(pa_bluetooth_adapter, 1);
    a->discovery = y;
    a->path = pa_xstrdup(path);

    pa_hashmap_put(y->adapters, a->path, a);

    return a;
}

static void adapter_free(pa_bluetooth_adapter *a) {
    pa_bluetooth_device *d;
    void *state;

    pa_assert(a);
    pa_assert(a->discovery);

    PA_HASHMAP_FOREACH(d, a->discovery->devices, state)
        if (d->adapter == a)
            device_set_adapter(d, NULL);

    pa_xfree(a->path);
    pa_xfree(a->address);
    pa_xfree(a);
}

static void adapter_remove(pa_bluetooth_discovery *y, const char *path) {
    pa_bluetooth_adapter *a;

    if (!(a = pa_hashmap_remove(y->adapters, path)))
        pa_log_warn("Unknown adapter removed %s", path);
    else {
        pa_log_debug("Adapter %s removed", path);
        adapter_free(a);
    }
}

static void parse_device_property(pa_bluetooth_device *d, DBusMessageIter *i) {
    const char *key;
    DBusMessageIter variant_i;

    pa_assert(d);

    key = check_variant_property(i);
    if (key == NULL) {
        pa_log_error("Received invalid property for device %s", d->path);
        return;
    }

    dbus_message_iter_recurse(i, &variant_i);

    switch (dbus_message_iter_get_arg_type(&variant_i)) {

        case DBUS_TYPE_STRING: {
            const char *value;
            dbus_message_iter_get_basic(&variant_i, &value);

            if (pa_streq(key, "Alias")) {
                pa_xfree(d->alias);
                d->alias = pa_xstrdup(value);
                pa_log_debug("%s: %s", key, value);
            } else if (pa_streq(key, "Address")) {
                if (d->properties_received) {
                    pa_log_warn("Device property 'Address' expected to be constant but changed for %s, ignoring", d->path);
                    return;
                }

                if (d->address) {
                    pa_log_warn("Device %s: Received a duplicate 'Address' property, ignoring", d->path);
                    return;
                }

                d->address = pa_xstrdup(value);
                pa_log_debug("%s: %s", key, value);
            }

            break;
        }

        case DBUS_TYPE_OBJECT_PATH: {
            const char *value;
            dbus_message_iter_get_basic(&variant_i, &value);

            if (pa_streq(key, "Adapter")) {

                if (d->properties_received) {
                    pa_log_warn("Device property 'Adapter' expected to be constant but changed for %s, ignoring", d->path);
                    return;
                }

                if (d->adapter_path) {
                    pa_log_warn("Device %s: Received a duplicate 'Adapter' property, ignoring", d->path);
                    return;
                }

                d->adapter_path = pa_xstrdup(value);
                pa_log_debug("%s: %s", key, value);
            }

            break;
        }

        case DBUS_TYPE_UINT32: {
            uint32_t value;
            dbus_message_iter_get_basic(&variant_i, &value);

            if (pa_streq(key, "Class")) {
                d->class_of_device = value;
                pa_log_debug("%s: %d", key, value);
            }

            break;
        }

        case DBUS_TYPE_ARRAY: {
            DBusMessageIter ai;
            dbus_message_iter_recurse(&variant_i, &ai);

            if (dbus_message_iter_get_arg_type(&ai) == DBUS_TYPE_STRING && pa_streq(key, "UUIDs")) {
                /* bluetoothd never removes UUIDs from a device object so we
                 * don't need to check for disappeared UUIDs here. */
                while (dbus_message_iter_get_arg_type(&ai) != DBUS_TYPE_INVALID) {
                    const char *value;
                    char *uuid;

                    dbus_message_iter_get_basic(&ai, &value);

                    if (pa_hashmap_get(d->uuids, value)) {
                        dbus_message_iter_next(&ai);
                        continue;
                    }

                    uuid = pa_xstrdup(value);
                    pa_hashmap_put(d->uuids, uuid, uuid);

                    pa_log_debug("%s: %s", key, value);
                    dbus_message_iter_next(&ai);
                }
            }

            break;
        }
    }
}

static void parse_device_properties(pa_bluetooth_device *d, DBusMessageIter *i) {
    DBusMessageIter element_i;

    dbus_message_iter_recurse(i, &element_i);

    while (dbus_message_iter_get_arg_type(&element_i) == DBUS_TYPE_DICT_ENTRY) {
        DBusMessageIter dict_i;

        dbus_message_iter_recurse(&element_i, &dict_i);
        parse_device_property(d, &dict_i);
        dbus_message_iter_next(&element_i);
    }

    if (!d->properties_received) {
        d->properties_received = true;
        device_update_valid(d);

        if (!d->address || !d->adapter_path || !d->alias)
            pa_log_error("Non-optional information missing for device %s", d->path);
    }
}

static void parse_remote_endpoint_properties(pa_bluetooth_discovery *y, const char *endpoint, DBusMessageIter *i) {
    DBusMessageIter element_i;
    pa_bluetooth_device *device;
    pa_hashmap *codec_endpoints;
    pa_hashmap *endpoints;
    pa_a2dp_codec_id *a2dp_codec_id;
    struct a2dp_codec_capabilities *a2dp_codec_capabilities;
    const char *uuid = NULL;
    const char *device_path = NULL;
    uint8_t codec_id = 0;
    bool have_codec_id = false;
    const uint8_t *capabilities = NULL;
    int capabilities_size = 0;

    pa_log_debug("Parsing remote endpoint %s", endpoint);

    dbus_message_iter_recurse(i, &element_i);

    while (dbus_message_iter_get_arg_type(&element_i) == DBUS_TYPE_DICT_ENTRY) {
        DBusMessageIter dict_i, variant_i;
        const char *key;

        dbus_message_iter_recurse(&element_i, &dict_i);

        key = check_variant_property(&dict_i);
        if (key == NULL) {
            pa_log_error("Received invalid property for remote endpoint %s", endpoint);
            return;
        }

        dbus_message_iter_recurse(&dict_i, &variant_i);

        if (pa_streq(key, "UUID")) {
            if (dbus_message_iter_get_arg_type(&variant_i) != DBUS_TYPE_STRING) {
                pa_log_warn("Remote endpoint %s property 'UUID' is not string, ignoring", endpoint);
                return;
            }

            dbus_message_iter_get_basic(&variant_i, &uuid);
        } else if (pa_streq(key, "Codec")) {
            if (dbus_message_iter_get_arg_type(&variant_i) != DBUS_TYPE_BYTE) {
                pa_log_warn("Remote endpoint %s property 'Codec' is not byte, ignoring", endpoint);
                return;
            }

            dbus_message_iter_get_basic(&variant_i, &codec_id);
            have_codec_id = true;
        } else if (pa_streq(key, "Capabilities")) {
            DBusMessageIter array;

            if (dbus_message_iter_get_arg_type(&variant_i) != DBUS_TYPE_ARRAY) {
                pa_log_warn("Remote endpoint %s property 'Capabilities' is not array, ignoring", endpoint);
                return;
            }

            dbus_message_iter_recurse(&variant_i, &array);
            if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_BYTE) {
                pa_log_warn("Remote endpoint %s property 'Capabilities' is not array of bytes, ignoring", endpoint);
                return;
            }

            dbus_message_iter_get_fixed_array(&array, &capabilities, &capabilities_size);
        } else if (pa_streq(key, "Device")) {
            if (dbus_message_iter_get_arg_type(&variant_i) != DBUS_TYPE_OBJECT_PATH) {
                pa_log_warn("Remote endpoint %s property 'Device' is not path, ignoring", endpoint);
                return;
            }

            dbus_message_iter_get_basic(&variant_i, &device_path);
        }

        dbus_message_iter_next(&element_i);
    }

    if (!uuid) {
        pa_log_warn("Remote endpoint %s does not have property 'UUID', ignoring", endpoint);
        return;
    }

    if (!have_codec_id) {
        pa_log_warn("Remote endpoint %s does not have property 'Codec', ignoring", endpoint);
        return;
    }

    if (!capabilities || !capabilities_size) {
        pa_log_warn("Remote endpoint %s does not have property 'Capabilities', ignoring", endpoint);
        return;
    }

    if (!device_path) {
        pa_log_warn("Remote endpoint %s does not have property 'Device', ignoring", endpoint);
        return;
    }

    device = pa_hashmap_get(y->devices, device_path);
    if (!device) {
        pa_log_warn("Device for remote endpoint %s was not found", endpoint);
        return;
    }

    if (pa_streq(uuid, PA_BLUETOOTH_UUID_A2DP_SINK)) {
        codec_endpoints = device->a2dp_sink_endpoints;
    } else if (pa_streq(uuid, PA_BLUETOOTH_UUID_A2DP_SOURCE)) {
        codec_endpoints = device->a2dp_source_endpoints;
    } else {
        pa_log_warn("Remote endpoint %s does not have valid property 'UUID', ignoring", endpoint);
        return;
    }

    if (capabilities_size < 0 || capabilities_size > MAX_A2DP_CAPS_SIZE) {
        pa_log_warn("Remote endpoint %s does not have valid property 'Capabilities', ignoring", endpoint);
        return;
    }

    a2dp_codec_id = pa_xmalloc0(sizeof(*a2dp_codec_id));
    a2dp_codec_id->codec_id = codec_id;
    if (codec_id == A2DP_CODEC_VENDOR) {
        if ((size_t)capabilities_size < sizeof(a2dp_vendor_codec_t)) {
            pa_log_warn("Remote endpoint %s does not have valid property 'Capabilities', ignoring", endpoint);
            return;
        }
        a2dp_codec_id->vendor_id = A2DP_GET_VENDOR_ID(*(a2dp_vendor_codec_t *)capabilities);
        a2dp_codec_id->vendor_codec_id = A2DP_GET_CODEC_ID(*(a2dp_vendor_codec_t *)capabilities);
    } else {
        a2dp_codec_id->vendor_id = 0;
        a2dp_codec_id->vendor_codec_id = 0;
    }

    a2dp_codec_capabilities = pa_xmalloc0(sizeof(*a2dp_codec_capabilities) + capabilities_size);
    a2dp_codec_capabilities->size = capabilities_size;
    memcpy(a2dp_codec_capabilities->buffer, capabilities, capabilities_size);

    endpoints = pa_hashmap_get(codec_endpoints, a2dp_codec_id);
    if (!endpoints) {
        endpoints = pa_hashmap_new_full(pa_idxset_string_hash_func, pa_idxset_string_compare_func, pa_xfree, pa_xfree);
        pa_hashmap_put(codec_endpoints, a2dp_codec_id, endpoints);
    }

    if (pa_hashmap_remove_and_free(endpoints, endpoint) >= 0)
        pa_log_debug("Replacing existing remote endpoint %s", endpoint);
    pa_hashmap_put(endpoints, pa_xstrdup(endpoint), a2dp_codec_capabilities);
}

static void parse_adapter_properties(pa_bluetooth_adapter *a, DBusMessageIter *i, bool is_property_change) {
    DBusMessageIter element_i;

    pa_assert(a);

    dbus_message_iter_recurse(i, &element_i);

    while (dbus_message_iter_get_arg_type(&element_i) == DBUS_TYPE_DICT_ENTRY) {
        DBusMessageIter dict_i, variant_i;
        const char *key;

        dbus_message_iter_recurse(&element_i, &dict_i);

        key = check_variant_property(&dict_i);
        if (key == NULL) {
            pa_log_error("Received invalid property for adapter %s", a->path);
            return;
        }

        dbus_message_iter_recurse(&dict_i, &variant_i);

        if (dbus_message_iter_get_arg_type(&variant_i) == DBUS_TYPE_STRING && pa_streq(key, "Address")) {
            const char *value;

            if (is_property_change) {
                pa_log_warn("Adapter property 'Address' expected to be constant but changed for %s, ignoring", a->path);
                return;
            }

            if (a->address) {
                pa_log_warn("Adapter %s received a duplicate 'Address' property, ignoring", a->path);
                return;
            }

            dbus_message_iter_get_basic(&variant_i, &value);
            a->address = pa_xstrdup(value);
            a->valid = true;
        }

        dbus_message_iter_next(&element_i);
    }
}

static void register_endpoint_reply(DBusPendingCall *pending, void *userdata) {
    DBusMessage *r;
    pa_dbus_pending *p;
    pa_bluetooth_discovery *y;
    char *endpoint;

    pa_assert(pending);
    pa_assert_se(p = userdata);
    pa_assert_se(y = p->context_data);
    pa_assert_se(endpoint = p->call_data);
    pa_assert_se(r = dbus_pending_call_steal_reply(pending));

    if (dbus_message_is_error(r, BLUEZ_ERROR_NOT_SUPPORTED)) {
        pa_log_info("Couldn't register endpoint %s because it is disabled in BlueZ", endpoint);
        goto finish;
    }

    if (dbus_message_get_type(r) == DBUS_MESSAGE_TYPE_ERROR) {
        pa_log_error(BLUEZ_MEDIA_INTERFACE ".RegisterEndpoint() failed: %s: %s", dbus_message_get_error_name(r),
                     pa_dbus_get_error_message(r));
        goto finish;
    }

finish:
    dbus_message_unref(r);

    PA_LLIST_REMOVE(pa_dbus_pending, y->pending, p);
    pa_dbus_pending_free(p);

    pa_xfree(endpoint);
}

static void register_endpoint(pa_bluetooth_discovery *y, const pa_a2dp_codec *a2dp_codec, const char *path, const char *endpoint, const char *uuid) {
    DBusMessage *m;
    DBusMessageIter i, d;
    uint8_t capabilities[MAX_A2DP_CAPS_SIZE];
    size_t capabilities_size;
    uint8_t codec_id;

    pa_log_debug("Registering %s on adapter %s", endpoint, path);

    codec_id = a2dp_codec->id.codec_id;
    capabilities_size = a2dp_codec->fill_capabilities(capabilities);
    pa_assert(capabilities_size != 0);

    pa_assert_se(m = dbus_message_new_method_call(BLUEZ_SERVICE, path, BLUEZ_MEDIA_INTERFACE, "RegisterEndpoint"));

    dbus_message_iter_init_append(m, &i);
    pa_assert_se(dbus_message_iter_append_basic(&i, DBUS_TYPE_OBJECT_PATH, &endpoint));
    dbus_message_iter_open_container(&i, DBUS_TYPE_ARRAY, DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING DBUS_TYPE_STRING_AS_STRING
                                         DBUS_TYPE_VARIANT_AS_STRING DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &d);
    pa_dbus_append_basic_variant_dict_entry(&d, "UUID", DBUS_TYPE_STRING, &uuid);
    pa_dbus_append_basic_variant_dict_entry(&d, "Codec", DBUS_TYPE_BYTE, &codec_id);
    pa_dbus_append_basic_array_variant_dict_entry(&d, "Capabilities", DBUS_TYPE_BYTE, &capabilities, capabilities_size);

    dbus_message_iter_close_container(&i, &d);

    send_and_add_to_pending(y, m, register_endpoint_reply, pa_xstrdup(endpoint));
}

static void register_application_reply(DBusPendingCall *pending, void *userdata) {
    DBusMessage *r;
    pa_dbus_pending *p;
    pa_bluetooth_adapter *a;
    pa_bluetooth_discovery *y;
    char *path;
    bool fallback = true;

    pa_assert(pending);
    pa_assert_se(p = userdata);
    pa_assert_se(y = p->context_data);
    pa_assert_se(path = p->call_data);
    pa_assert_se(r = dbus_pending_call_steal_reply(pending));

    if (dbus_message_is_error(r, BLUEZ_ERROR_NOT_SUPPORTED)) {
        pa_log_info("Couldn't register media application for adapter %s because it is disabled in BlueZ", path);
        goto finish;
    }

    if (dbus_message_get_type(r) == DBUS_MESSAGE_TYPE_ERROR) {
        pa_log_warn(BLUEZ_MEDIA_INTERFACE ".RegisterApplication() failed: %s: %s", dbus_message_get_error_name(r),
                     pa_dbus_get_error_message(r));
        pa_log_warn("Couldn't register media application for adapter %s because of probably old BlueZ version which does not support additional A2DP codecs", path);
        goto finish;
    }

    a = pa_hashmap_get(y->adapters, path);
    if (!a) {
        pa_log_error("Couldn't register media application for adapter %s because it does not exist anymore", path);
        goto finish;
    }

    fallback = false;
    a->media_application_registered = true;
    pa_log_debug("Media application for adapter %s was successfully registered", path);

finish:
    dbus_message_unref(r);

    PA_LLIST_REMOVE(pa_dbus_pending, y->pending, p);
    pa_dbus_pending_free(p);

    if (fallback) {
        /* If bluez does not support RegisterApplication, fallback to old API with just one SBC codec */
        const pa_a2dp_codec *a2dp_codec_sbc = pa_bluetooth_get_a2dp_codec("sbc");
        pa_assert(a2dp_codec_sbc);
        register_endpoint(y, a2dp_codec_sbc, path, A2DP_SINK_ENDPOINT "/sbc", PA_BLUETOOTH_UUID_A2DP_SINK);
        register_endpoint(y, a2dp_codec_sbc, path, A2DP_SOURCE_ENDPOINT "/sbc", PA_BLUETOOTH_UUID_A2DP_SOURCE);
        pa_log_warn("Only SBC codec is available for A2DP profiles");
    }

    pa_xfree(path);
}

static void register_application(pa_bluetooth_adapter *a) {
    DBusMessage *m;
    DBusMessageIter i, d;
    const char *object_manager_path = A2DP_OBJECT_MANAGER_PATH;

    pa_log_debug("Registering media application for adapter %s", a->path);

    pa_assert_se(m = dbus_message_new_method_call(BLUEZ_SERVICE, a->path, BLUEZ_MEDIA_INTERFACE, "RegisterApplication"));

    dbus_message_iter_init_append(m, &i);
    pa_assert_se(dbus_message_iter_append_basic(&i, DBUS_TYPE_OBJECT_PATH, &object_manager_path));
    dbus_message_iter_open_container(&i, DBUS_TYPE_ARRAY, DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &d);
    dbus_message_iter_close_container(&i, &d);

    send_and_add_to_pending(a->discovery, m, register_application_reply, pa_xstrdup(a->path));
}

static void parse_interfaces_and_properties(pa_bluetooth_discovery *y, DBusMessageIter *dict_i) {
    DBusMessageIter element_i;
    const char *path;
    void *state;
    pa_bluetooth_device *d;

    pa_assert(dbus_message_iter_get_arg_type(dict_i) == DBUS_TYPE_OBJECT_PATH);
    dbus_message_iter_get_basic(dict_i, &path);

    pa_assert_se(dbus_message_iter_next(dict_i));
    pa_assert(dbus_message_iter_get_arg_type(dict_i) == DBUS_TYPE_ARRAY);

    dbus_message_iter_recurse(dict_i, &element_i);

    while (dbus_message_iter_get_arg_type(&element_i) == DBUS_TYPE_DICT_ENTRY) {
        DBusMessageIter iface_i;
        const char *interface;

        dbus_message_iter_recurse(&element_i, &iface_i);

        pa_assert(dbus_message_iter_get_arg_type(&iface_i) == DBUS_TYPE_STRING);
        dbus_message_iter_get_basic(&iface_i, &interface);

        pa_assert_se(dbus_message_iter_next(&iface_i));
        pa_assert(dbus_message_iter_get_arg_type(&iface_i) == DBUS_TYPE_ARRAY);

        if (pa_streq(interface, BLUEZ_ADAPTER_INTERFACE)) {

            pa_bluetooth_adapter *a;

            if ((a = pa_hashmap_get(y->adapters, path))) {
                pa_log_error("Found duplicated D-Bus path for adapter %s", path);
                return;
            } else
                a = adapter_create(y, path);

            pa_log_debug("Adapter %s found", path);

            parse_adapter_properties(a, &iface_i, false);

            if (!a->valid)
                return;

            register_application(a);

        } else if (pa_streq(interface, BLUEZ_DEVICE_INTERFACE)) {

            if ((d = pa_hashmap_get(y->devices, path))) {
                if (d->properties_received) {
                    pa_log_error("Found duplicated D-Bus path for device %s", path);
                    return;
                }
            } else
                d = device_create(y, path);

            pa_log_debug("Device %s found", d->path);

            parse_device_properties(d, &iface_i);

        } else if (pa_streq(interface, BLUEZ_MEDIA_ENDPOINT_INTERFACE))
            parse_remote_endpoint_properties(y, path, &iface_i);
        else
            pa_log_debug("Unknown interface %s found, skipping", interface);

        dbus_message_iter_next(&element_i);
    }

    PA_HASHMAP_FOREACH(d, y->devices, state) {
        if (d->properties_received && !d->tried_to_link_with_adapter) {
            if (d->adapter_path) {
                device_set_adapter(d, pa_hashmap_get(d->discovery->adapters, d->adapter_path));

                if (!d->adapter)
                    pa_log("Device %s points to a nonexistent adapter %s.", d->path, d->adapter_path);
                else if (!d->adapter->valid)
                    pa_log("Device %s points to an invalid adapter %s.", d->path, d->adapter_path);
            }

            d->tried_to_link_with_adapter = true;
        }
    }

    return;
}

/* This function may be called only by hsphfpd backend.
   Legacy HSP backend may be enabled only when hsphfpd daemon is not running. */
void pa_bluetooth_discovery_legacy_hsp_backend_enable(pa_bluetooth_discovery *y, bool enable) {
    if (y->legacy_hsp_backend)
        pa_bluetooth_legacy_hsp_backend_enable(y->legacy_hsp_backend, enable);
}

static void get_managed_objects_reply(DBusPendingCall *pending, void *userdata) {
    pa_dbus_pending *p;
    pa_bluetooth_discovery *y;
    DBusMessage *r;
    DBusMessageIter arg_i, element_i;

    pa_assert_se(p = userdata);
    pa_assert_se(y = p->context_data);
    pa_assert_se(r = dbus_pending_call_steal_reply(pending));

    if (dbus_message_is_error(r, DBUS_ERROR_UNKNOWN_METHOD)) {
        pa_log_warn("BlueZ D-Bus ObjectManager not available");
        goto finish;
    }

    if (dbus_message_get_type(r) == DBUS_MESSAGE_TYPE_ERROR) {
        pa_log_error("GetManagedObjects() failed: %s: %s", dbus_message_get_error_name(r), pa_dbus_get_error_message(r));
        goto finish;
    }

    if (!dbus_message_iter_init(r, &arg_i) || !pa_streq(dbus_message_get_signature(r), "a{oa{sa{sv}}}")) {
        pa_log_error("Invalid reply signature for GetManagedObjects()");
        goto finish;
    }

    dbus_message_iter_recurse(&arg_i, &element_i);
    while (dbus_message_iter_get_arg_type(&element_i) == DBUS_TYPE_DICT_ENTRY) {
        DBusMessageIter dict_i;

        dbus_message_iter_recurse(&element_i, &dict_i);

        parse_interfaces_and_properties(y, &dict_i);

        dbus_message_iter_next(&element_i);
    }

    y->objects_listed = true;

    if (!y->legacy_hsp_backend && (y->headset_backend == HEADSET_BACKEND_AUTO || y->headset_backend == HEADSET_BACKEND_LEGACY_HSP))
        y->legacy_hsp_backend = pa_bluetooth_legacy_hsp_backend_new(y->core, y, (y->headset_backend == HEADSET_BACKEND_LEGACY_HSP));

    if (!y->hsphfpd_backend && (y->headset_backend == HEADSET_BACKEND_AUTO || y->headset_backend == HEADSET_BACKEND_HSPHFPD))
        y->hsphfpd_backend = pa_bluetooth_hsphfpd_backend_new(y->core, y);

finish:
    dbus_message_unref(r);

    PA_LLIST_REMOVE(pa_dbus_pending, y->pending, p);
    pa_dbus_pending_free(p);
}

static void get_managed_objects(pa_bluetooth_discovery *y) {
    DBusMessage *m;

    pa_assert(y);

    pa_assert_se(m = dbus_message_new_method_call(BLUEZ_SERVICE, "/", "org.freedesktop.DBus.ObjectManager",
                                                  "GetManagedObjects"));
    send_and_add_to_pending(y, m, get_managed_objects_reply, NULL);
}

pa_hook* pa_bluetooth_discovery_hook(pa_bluetooth_discovery *y, pa_bluetooth_hook_t hook) {
    pa_assert(y);
    pa_assert(PA_REFCNT_VALUE(y) > 0);

    return &y->hooks[hook];
}

static DBusHandlerResult filter_cb(DBusConnection *bus, DBusMessage *m, void *userdata) {
    pa_bluetooth_discovery *y;
    DBusError err;

    pa_assert(bus);
    pa_assert(m);
    pa_assert_se(y = userdata);

    dbus_error_init(&err);

    if (dbus_message_is_signal(m, "org.freedesktop.DBus", "NameOwnerChanged")) {
        const char *name, *old_owner, *new_owner;

        if (!dbus_message_get_args(m, &err,
                                   DBUS_TYPE_STRING, &name,
                                   DBUS_TYPE_STRING, &old_owner,
                                   DBUS_TYPE_STRING, &new_owner,
                                   DBUS_TYPE_INVALID)) {
            pa_log_error("Failed to parse org.freedesktop.DBus.NameOwnerChanged: %s", err.message);
            goto fail;
        }

        if (pa_streq(name, BLUEZ_SERVICE)) {
            if (old_owner && *old_owner) {
                pa_log_debug("Bluetooth daemon disappeared");
                pa_hashmap_remove_all(y->devices);
                pa_hashmap_remove_all(y->adapters);
                y->objects_listed = false;
                if (y->hsphfpd_backend) {
                    pa_bluetooth_hsphfpd_backend_free(y->hsphfpd_backend);
                    y->hsphfpd_backend = NULL;
                }
                if (y->legacy_hsp_backend) {
                    pa_bluetooth_legacy_hsp_backend_free(y->legacy_hsp_backend);
                    y->legacy_hsp_backend = NULL;
                }
            }

            if (new_owner && *new_owner) {
                pa_log_debug("Bluetooth daemon appeared");
                get_managed_objects(y);
            }
        }

        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    } else if (dbus_message_is_signal(m, "org.freedesktop.DBus.ObjectManager", "InterfacesAdded")) {
        DBusMessageIter arg_i;

        if (!y->objects_listed)
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED; /* No reply received yet from GetManagedObjects */

        if (!dbus_message_iter_init(m, &arg_i) || !pa_streq(dbus_message_get_signature(m), "oa{sa{sv}}")) {
            pa_log_error("Invalid signature found in InterfacesAdded");
            goto fail;
        }

        parse_interfaces_and_properties(y, &arg_i);

        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    } else if (dbus_message_is_signal(m, "org.freedesktop.DBus.ObjectManager", "InterfacesRemoved")) {
        const char *p;
        DBusMessageIter arg_i;
        DBusMessageIter element_i;

        if (!y->objects_listed)
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED; /* No reply received yet from GetManagedObjects */

        if (!dbus_message_iter_init(m, &arg_i) || !pa_streq(dbus_message_get_signature(m), "oas")) {
            pa_log_error("Invalid signature found in InterfacesRemoved");
            goto fail;
        }

        dbus_message_iter_get_basic(&arg_i, &p);

        pa_assert_se(dbus_message_iter_next(&arg_i));
        pa_assert(dbus_message_iter_get_arg_type(&arg_i) == DBUS_TYPE_ARRAY);

        dbus_message_iter_recurse(&arg_i, &element_i);

        while (dbus_message_iter_get_arg_type(&element_i) == DBUS_TYPE_STRING) {
            const char *iface;

            dbus_message_iter_get_basic(&element_i, &iface);

            if (pa_streq(iface, BLUEZ_DEVICE_INTERFACE))
                device_remove(y, p);
            else if (pa_streq(iface, BLUEZ_MEDIA_ENDPOINT_INTERFACE))
                remote_endpoint_remove(y, p);
            else if (pa_streq(iface, BLUEZ_ADAPTER_INTERFACE))
                adapter_remove(y, p);

            dbus_message_iter_next(&element_i);
        }

        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    } else if (dbus_message_is_signal(m, "org.freedesktop.DBus.Properties", "PropertiesChanged")) {
        DBusMessageIter arg_i;
        const char *iface;

        if (!y->objects_listed)
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED; /* No reply received yet from GetManagedObjects */

        if (!dbus_message_iter_init(m, &arg_i) || !pa_streq(dbus_message_get_signature(m), "sa{sv}as")) {
            pa_log_error("Invalid signature found in PropertiesChanged");
            goto fail;
        }

        dbus_message_iter_get_basic(&arg_i, &iface);

        pa_assert_se(dbus_message_iter_next(&arg_i));
        pa_assert(dbus_message_iter_get_arg_type(&arg_i) == DBUS_TYPE_ARRAY);

        if (pa_streq(iface, BLUEZ_ADAPTER_INTERFACE)) {
            pa_bluetooth_adapter *a;

            pa_log_debug("Properties changed in adapter %s", dbus_message_get_path(m));

            if (!(a = pa_hashmap_get(y->adapters, dbus_message_get_path(m)))) {
                pa_log_warn("Properties changed in unknown adapter");
                return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
            }

            parse_adapter_properties(a, &arg_i, true);

        } else if (pa_streq(iface, BLUEZ_DEVICE_INTERFACE)) {
            pa_bluetooth_device *d;

            pa_log_debug("Properties changed in device %s", dbus_message_get_path(m));

            if (!(d = pa_hashmap_get(y->devices, dbus_message_get_path(m)))) {
                pa_log_warn("Properties changed in unknown device");
                return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
            }

            if (!d->properties_received)
                return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

            parse_device_properties(d, &arg_i);
        } else if (pa_streq(iface, BLUEZ_MEDIA_ENDPOINT_INTERFACE)) {
            pa_log_info("Properties changed in remote endpoint %s", dbus_message_get_path(m));

            parse_remote_endpoint_properties(y, dbus_message_get_path(m), &arg_i);
        } else if (pa_streq(iface, BLUEZ_MEDIA_TRANSPORT_INTERFACE)) {
            pa_bluetooth_transport *t;

            pa_log_debug("Properties changed in transport %s", dbus_message_get_path(m));

            if (!(t = pa_hashmap_get(y->transports, dbus_message_get_path(m))))
                return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

            parse_transport_properties(t, &arg_i);
        }

        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

fail:
    dbus_error_free(&err);

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/* A2DP bluez endpoint name ends with /sep<num_id> string */
static int a2dp_endpoint_to_id(const char *endpoint) {
    int end = strlen(endpoint)-1;
    int pos = end;

    while (pos >= 0 && endpoint[pos] >= '0' && endpoint[pos] <= '9')
        pos--;

    if (pos == end)
        return -1;

    if (pos < 3 || memcmp(endpoint+pos-3, "/sep", 4) != 0)
        return -1;

    return atoi(endpoint+pos+1);
}

struct cmp_arg {
    const pa_a2dp_codec *a2dp_codec;
    const pa_hashmap *capabilities_hashmap;
    const pa_sample_spec *default_sample_spec;
    bool for_encoding;
};

static int cmp_endpoints(const void *p1, const void *p2, void *arg) {
    const char *endpoint1 = *(const char * const *)p1;
    const char *endpoint2 = *(const char * const *)p2;
    const struct cmp_arg *cmp_arg = (struct cmp_arg *)arg;
    const struct a2dp_codec_capabilities *capabilities1;
    const struct a2dp_codec_capabilities *capabilities2;
    int cmp, id1, id2;

    pa_assert_se(capabilities1 = pa_hashmap_get(cmp_arg->capabilities_hashmap, endpoint1));
    pa_assert_se(capabilities2 = pa_hashmap_get(cmp_arg->capabilities_hashmap, endpoint2));

    cmp = cmp_arg->a2dp_codec->cmp_endpoints(capabilities1->buffer, capabilities1->size, capabilities2->buffer, capabilities2->size, cmp_arg->default_sample_spec, cmp_arg->for_encoding);
    if (cmp != 0)
        return cmp;

    /* Prefer endpoint with smaller SEP id (endpoint which should be tried first) */
    id1 = a2dp_endpoint_to_id(endpoint1);
    id2 = a2dp_endpoint_to_id(endpoint2);
    if (id1 < id2)
        return -1;
    if (id1 > id2)
        return 1;

    return 0;
}

size_t pa_bluetooth_device_find_a2dp_endpoints_for_codec(const pa_bluetooth_device *device, const pa_a2dp_codec *a2dp_codec, bool is_a2dp_sink, const char **endpoints, size_t endpoints_max_count) {
    pa_hashmap *capabilities_hashmap;
    const struct a2dp_codec_capabilities *a2dp_capabilities;
    const char *key;
    void *state;
    size_t count;

    capabilities_hashmap = pa_hashmap_get(is_a2dp_sink ? device->a2dp_sink_endpoints : device->a2dp_source_endpoints, &a2dp_codec->id);
    if (!capabilities_hashmap)
        return 0;

    count = 0;
    /* Filter endpoints which are not compatible */
    PA_HASHMAP_FOREACH_KV(key, a2dp_capabilities, capabilities_hashmap, state) {
        if (!a2dp_codec->can_accept_capabilities(a2dp_capabilities->buffer, a2dp_capabilities->size, is_a2dp_sink))
            continue;
        if (count < endpoints_max_count)
            endpoints[count] = key;
        count++;
    }

    /* Change order of capabilities according to preference */
    qsort_r(&endpoints, (count <= endpoints_max_count) ? count : endpoints_max_count, sizeof(const char *), cmp_endpoints, &(struct cmp_arg){ a2dp_codec, capabilities_hashmap, &device->discovery->core->default_sample_spec, is_a2dp_sink });

    return count;
}

struct change_a2dp_profile_data {
    char *pa_endpoint;
    pa_bluetooth_device *device;
    pa_bluetooth_profile_t profile;
    const char **codec_endpoints;
    size_t codec_endpoints_i;
    size_t codec_endpoints_count;
    void (*cb)(bool, void *);
    void *userdata;
};

static bool change_a2dp_profile_next(pa_bluetooth_device *device, pa_bluetooth_profile_t profile, const char **codec_endpoints, size_t codec_endpoints_i, size_t codec_endpoints_count, bool from_cb, void (*cb)(bool, void *), void *userdata);

static void change_a2dp_profile_reply(DBusPendingCall *pending, void *userdata) {
    DBusMessage *r;
    pa_dbus_pending *p;
    pa_bluetooth_discovery *y;
    struct change_a2dp_profile_data *data;
    bool success;

    pa_assert(pending);
    pa_assert_se(p = userdata);
    pa_assert_se(y = p->context_data);
    pa_assert_se(data = p->call_data);
    pa_assert_se(r = dbus_pending_call_steal_reply(pending));

    success = (dbus_message_get_type(r) != DBUS_MESSAGE_TYPE_ERROR);
    dbus_message_unref(r);

    PA_LLIST_REMOVE(pa_dbus_pending, y->pending, p);
    pa_dbus_pending_free(p);
    pa_xfree(data->pa_endpoint);

    if (success) {
        pa_log_info("Changing a2dp profile for %s to %s via endpoint %s succeeded", data->device->path, pa_bluetooth_profile_to_string(data->profile), data->codec_endpoints[data->codec_endpoints_i-1]);
        data->device->change_a2dp_profile_in_progress = false;
        data->cb(true, data->userdata);
        pa_xfree(data->codec_endpoints);
    } else {
        pa_log_warn("Changing a2dp profile for %s to %s via endpoint %s failed: %s: %s", data->device->path, pa_bluetooth_profile_to_string(data->profile), data->codec_endpoints[data->codec_endpoints_i-1], dbus_message_get_error_name(r), pa_dbus_get_error_message(r));
        change_a2dp_profile_next(data->device, data->profile, data->codec_endpoints, data->codec_endpoints_i, data->codec_endpoints_count, true, data->cb, data->userdata);
    }

    pa_xfree(data);
}

static bool change_a2dp_profile_next(pa_bluetooth_device *device, pa_bluetooth_profile_t profile, const char **codec_endpoints, size_t codec_endpoints_i, size_t codec_endpoints_count, bool from_cb, void (*cb)(bool, void *), void *userdata) {
    const pa_a2dp_codec *a2dp_codec;
    bool is_a2dp_sink;
    const char *endpoint;
    char *pa_endpoint;
    struct change_a2dp_profile_data *data;
    uint8_t config[MAX_A2DP_CAPS_SIZE];
    uint8_t config_size;
    pa_hashmap *all_endpoints;
    struct a2dp_codec_capabilities *capabilities;
    DBusMessage *m;
    DBusMessageIter iter, dict;

    a2dp_codec = pa_bluetooth_profile_to_a2dp_codec(profile);
    is_a2dp_sink = pa_bluetooth_profile_is_a2dp_sink(profile);

    pa_assert_se(all_endpoints = pa_hashmap_get(is_a2dp_sink ? device->a2dp_sink_endpoints : device->a2dp_source_endpoints, &a2dp_codec->id));

next:
    if (codec_endpoints_i >= codec_endpoints_count) {
        pa_log_error("Changing a2dp profile for %s to %s failed: No endpoint accepted connection", device->path, pa_bluetooth_profile_to_string(profile));
        if (from_cb) {
            device->change_a2dp_profile_in_progress = false;
            cb(false, userdata);
        }
        pa_xfree(codec_endpoints);
        return false;
    }

    pa_assert_se(endpoint = codec_endpoints[codec_endpoints_i++]);
    pa_assert_se(capabilities = pa_hashmap_get(all_endpoints, endpoint));

    config_size = a2dp_codec->fill_preferred_configuration(&device->discovery->core->default_sample_spec, capabilities->buffer, capabilities->size, config);
    if (config_size == 0)
        goto next;

    pa_endpoint = pa_sprintf_malloc("%s/%s", is_a2dp_sink ? A2DP_SOURCE_ENDPOINT : A2DP_SINK_ENDPOINT, a2dp_codec->name);

    pa_assert_se(m = dbus_message_new_method_call(BLUEZ_SERVICE, endpoint, BLUEZ_MEDIA_ENDPOINT_INTERFACE, "SetConfiguration"));

    dbus_message_iter_init_append(m, &iter);
    pa_assert_se(dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &pa_endpoint));
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING DBUS_TYPE_STRING_AS_STRING
                                         DBUS_TYPE_VARIANT_AS_STRING DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);
    pa_dbus_append_basic_array_variant_dict_entry(&dict, "Capabilities", DBUS_TYPE_BYTE, &config, config_size);
    dbus_message_iter_close_container(&iter, &dict);

    device->change_a2dp_profile_in_progress = true;

    pa_log_debug("Changing a2dp profile for %s to %s via endpoint %s with codec %s using local endpoint %s", device->path, pa_bluetooth_profile_to_string(profile), endpoint, a2dp_codec->name, pa_endpoint);

    data = pa_xnew0(struct change_a2dp_profile_data, 1);
    data->pa_endpoint = pa_endpoint;
    data->device = device;
    data->profile = profile;
    data->codec_endpoints = codec_endpoints;
    data->codec_endpoints_i = codec_endpoints_i;
    data->codec_endpoints_count = codec_endpoints_count;
    data->cb = cb;
    data->userdata = userdata;
    send_and_add_to_pending(device->discovery, m, change_a2dp_profile_reply, data);
    return true;
}

bool pa_bluetooth_device_change_a2dp_profile(pa_bluetooth_device *device, pa_bluetooth_profile_t profile, void (*cb)(bool, void *), void *userdata) {
    const pa_a2dp_codec *a2dp_codec;
    bool is_a2dp_sink;
    size_t codec_endpoints_count;
    const char **codec_endpoints;

    if (device->change_a2dp_profile_in_progress) {
        pa_log_error("Changing a2dp profile for %s to %s failed: Operation already in progress", device->path, pa_bluetooth_profile_to_string(profile));
        return false;
    }

    a2dp_codec = pa_bluetooth_profile_to_a2dp_codec(profile);
    is_a2dp_sink = pa_bluetooth_profile_is_a2dp_sink(profile);

    codec_endpoints_count = pa_bluetooth_device_find_a2dp_endpoints_for_codec(device, a2dp_codec, is_a2dp_sink, NULL, 0);
    if (!codec_endpoints_count) {
        pa_log_error("Changing a2dp profile for %s to %s failed: No endpoint for codec %s", device->path, pa_bluetooth_profile_to_string(profile), a2dp_codec->name);
        return false;
    }

    codec_endpoints = pa_xnew0(const char *, codec_endpoints_count);
    pa_assert_se(pa_bluetooth_device_find_a2dp_endpoints_for_codec(device, a2dp_codec, is_a2dp_sink, codec_endpoints, codec_endpoints_count) == codec_endpoints_count);
    return change_a2dp_profile_next(device, profile, codec_endpoints, 0, codec_endpoints_count, false, cb, userdata);
}

unsigned pa_bluetooth_profile_count(void) {
    return PA_BLUETOOTH_PROFILE_A2DP_START_INDEX + 2 * pa_bluetooth_a2dp_codec_count();
}

bool pa_bluetooth_profile_is_a2dp_source(pa_bluetooth_profile_t profile) {
    unsigned source_start_index = PA_BLUETOOTH_PROFILE_A2DP_START_INDEX;
    unsigned sink_start_index = PA_BLUETOOTH_PROFILE_A2DP_START_INDEX + pa_bluetooth_a2dp_codec_count();

    pa_assert(profile < pa_bluetooth_profile_count());

    return profile >= source_start_index && profile < sink_start_index;
}

bool pa_bluetooth_profile_is_a2dp_sink(pa_bluetooth_profile_t profile) {
    unsigned sink_start_index = PA_BLUETOOTH_PROFILE_A2DP_START_INDEX + pa_bluetooth_a2dp_codec_count();

    pa_assert(profile < pa_bluetooth_profile_count());

    return profile >= sink_start_index;
}

const pa_a2dp_codec *pa_bluetooth_profile_to_a2dp_codec(pa_bluetooth_profile_t profile) {
    unsigned source_start_index = PA_BLUETOOTH_PROFILE_A2DP_START_INDEX;
    unsigned sink_start_index = PA_BLUETOOTH_PROFILE_A2DP_START_INDEX + pa_bluetooth_a2dp_codec_count();

    pa_assert(profile >= source_start_index && profile < pa_bluetooth_profile_count());

    if (profile < sink_start_index)
        return pa_bluetooth_a2dp_codec_iter(profile - source_start_index);
    else
        return pa_bluetooth_a2dp_codec_iter(profile - sink_start_index);
}

pa_bluetooth_profile_t pa_bluetooth_profile_for_a2dp_codec(const char *codec_name, bool is_a2dp_sink) {
    unsigned source_start_index = PA_BLUETOOTH_PROFILE_A2DP_START_INDEX;
    unsigned sink_start_index = PA_BLUETOOTH_PROFILE_A2DP_START_INDEX + pa_bluetooth_a2dp_codec_count();
    unsigned count = pa_bluetooth_a2dp_codec_count();
    const pa_a2dp_codec *a2dp_codec;
    unsigned i;

    for (i = 0; i < count; i++) {
        a2dp_codec = pa_bluetooth_a2dp_codec_iter(i);
        if (pa_streq(a2dp_codec->name, codec_name))
            return i + (is_a2dp_sink ? sink_start_index : source_start_index);
    }

    return PA_BLUETOOTH_PROFILE_OFF;
}

const char *pa_bluetooth_profile_to_string(pa_bluetooth_profile_t profile) {
    static __thread char profile_string[128];
    const pa_a2dp_codec *a2dp_codec;
    bool is_a2dp_sink;

    switch(profile) {
        case PA_BLUETOOTH_PROFILE_HSP_HEAD_UNIT:
            return "headset_head_unit"; /* For backward compatibility do not change this name */
        case PA_BLUETOOTH_PROFILE_HFP_HEAD_UNIT:
            return "hfp_head_unit";
        case PA_BLUETOOTH_PROFILE_HSP_AUDIO_GATEWAY:
            return "headset_audio_gateway"; /* For backward compatibility do not change this name */
        case PA_BLUETOOTH_PROFILE_HFP_AUDIO_GATEWAY:
            return "hfp_audio_gateway"; /* For backward compatibility do not change this name */
        case PA_BLUETOOTH_PROFILE_OFF:
            return "off";
        default:
            break;
    }

    a2dp_codec = pa_bluetooth_profile_to_a2dp_codec(profile);
    is_a2dp_sink = pa_bluetooth_profile_is_a2dp_sink(profile);

    /* backward compatible profile names for SBC codec */
    if (pa_streq(a2dp_codec->name, "sbc"))
        return is_a2dp_sink ? "a2dp_sink" : "a2dp_source";

    pa_snprintf(profile_string, sizeof(profile_string), "a2dp_%s_%s", is_a2dp_sink ? "sink" : "source", a2dp_codec->name);
    return profile_string;
}

static pa_bluetooth_profile_t a2dp_endpoint_to_bluetooth_profile(const char *endpoint) {
    const char *codec_name;
    bool is_a2dp_sink;

    if (pa_startswith(endpoint, A2DP_SINK_ENDPOINT "/")) {
        codec_name = endpoint + strlen(A2DP_SINK_ENDPOINT "/");
        is_a2dp_sink = false;
    } else if (pa_startswith(endpoint, A2DP_SOURCE_ENDPOINT "/")) {
        codec_name = endpoint + strlen(A2DP_SOURCE_ENDPOINT "/");
        is_a2dp_sink = true;
    } else {
        return PA_BLUETOOTH_PROFILE_OFF;
    }

    return pa_bluetooth_profile_for_a2dp_codec(codec_name, is_a2dp_sink);
}

static const pa_a2dp_codec *a2dp_endpoint_to_a2dp_codec(const char *endpoint) {
    const char *codec_name;

    if (pa_startswith(endpoint, A2DP_SINK_ENDPOINT "/"))
        codec_name = endpoint + strlen(A2DP_SINK_ENDPOINT "/");
    else if (pa_startswith(endpoint, A2DP_SOURCE_ENDPOINT "/"))
        codec_name = endpoint + strlen(A2DP_SOURCE_ENDPOINT "/");
    else
        return NULL;

    return pa_bluetooth_get_a2dp_codec(codec_name);
}

static DBusMessage *endpoint_set_configuration(DBusConnection *conn, DBusMessage *m, void *userdata) {
    pa_bluetooth_discovery *y = userdata;
    pa_bluetooth_device *d;
    pa_bluetooth_transport *t;
    const pa_a2dp_codec *a2dp_codec = NULL;
    const char *sender, *path, *endpoint_path, *dev_path = NULL, *uuid = NULL;
    const uint8_t *config = NULL;
    int size = 0;
    pa_bluetooth_profile_t p = PA_BLUETOOTH_PROFILE_OFF;
    DBusMessageIter args, props;
    DBusMessage *r;

    if (!dbus_message_iter_init(m, &args) || !pa_streq(dbus_message_get_signature(m), "oa{sv}")) {
        pa_log_error("Invalid signature for method SetConfiguration()");
        goto fail2;
    }

    dbus_message_iter_get_basic(&args, &path);

    if (pa_hashmap_get(y->transports, path)) {
        pa_log_error("Endpoint SetConfiguration(): Transport %s is already configured.", path);
        goto fail2;
    }

    pa_assert_se(dbus_message_iter_next(&args));

    dbus_message_iter_recurse(&args, &props);
    if (dbus_message_iter_get_arg_type(&props) != DBUS_TYPE_DICT_ENTRY)
        goto fail;

    endpoint_path = dbus_message_get_path(m);

    /* Read transport properties */
    while (dbus_message_iter_get_arg_type(&props) == DBUS_TYPE_DICT_ENTRY) {
        const char *key;
        DBusMessageIter value, entry;
        int var;

        dbus_message_iter_recurse(&props, &entry);
        dbus_message_iter_get_basic(&entry, &key);

        dbus_message_iter_next(&entry);
        dbus_message_iter_recurse(&entry, &value);

        var = dbus_message_iter_get_arg_type(&value);

        if (pa_streq(key, "UUID")) {
            if (var != DBUS_TYPE_STRING) {
                pa_log_error("Property %s of wrong type %c", key, (char)var);
                goto fail;
            }

            dbus_message_iter_get_basic(&value, &uuid);

            p = a2dp_endpoint_to_bluetooth_profile(endpoint_path);
            if ((pa_streq(uuid, PA_BLUETOOTH_UUID_A2DP_SOURCE) && !pa_bluetooth_profile_is_a2dp_sink(p)) ||
                (pa_streq(uuid, PA_BLUETOOTH_UUID_A2DP_SINK) && !pa_bluetooth_profile_is_a2dp_source(p))) {
                pa_log_error("UUID %s of transport %s incompatible with endpoint %s", uuid, path, endpoint_path);
                goto fail;
            }
        } else if (pa_streq(key, "Device")) {
            if (var != DBUS_TYPE_OBJECT_PATH) {
                pa_log_error("Property %s of wrong type %c", key, (char)var);
                goto fail;
            }

            dbus_message_iter_get_basic(&value, &dev_path);
        } else if (pa_streq(key, "Configuration")) {
            DBusMessageIter array;

            if (var != DBUS_TYPE_ARRAY) {
                pa_log_error("Property %s of wrong type %c", key, (char)var);
                goto fail;
            }

            dbus_message_iter_recurse(&value, &array);
            var = dbus_message_iter_get_arg_type(&array);
            if (var != DBUS_TYPE_BYTE) {
                pa_log_error("%s is an array of wrong type %c", key, (char)var);
                goto fail;
            }

            dbus_message_iter_get_fixed_array(&array, &config, &size);

            a2dp_codec = a2dp_endpoint_to_a2dp_codec(endpoint_path);
            pa_assert(a2dp_codec);

            if (!a2dp_codec->is_configuration_valid(config, size))
                goto fail;
        }

        dbus_message_iter_next(&props);
    }

    if (!a2dp_codec)
        goto fail2;

    if ((d = pa_hashmap_get(y->devices, dev_path))) {
        if (!d->valid) {
            pa_log_error("Information about device %s is invalid", dev_path);
            goto fail2;
        }
    } else {
        /* InterfacesAdded signal is probably on its way, device_info_valid is kept as 0. */
        pa_log_warn("SetConfiguration() received for unknown device %s", dev_path);
        d = device_create(y, dev_path);
    }

    if (d->transports[p] != NULL) {
        pa_log_error("Cannot configure transport %s because profile %s is already used", path, pa_bluetooth_profile_to_string(p));
        goto fail2;
    }

    sender = dbus_message_get_sender(m);

    pa_assert_se(r = dbus_message_new_method_return(m));
    pa_assert_se(dbus_connection_send(pa_dbus_connection_get(y->connection), r, NULL));
    dbus_message_unref(r);

    t = pa_bluetooth_transport_new(d, sender, path, p, config, size);
    t->acquire = bluez5_transport_acquire_cb;
    t->release = bluez5_transport_release_cb;
    pa_bluetooth_transport_put(t);

    pa_log_debug("Transport %s available for profile %s", t->path, pa_bluetooth_profile_to_string(t->profile));

    return NULL;

fail:
    pa_log_error("Endpoint SetConfiguration(): invalid arguments");

fail2:
    pa_assert_se(r = dbus_message_new_error(m, "org.bluez.Error.InvalidArguments", "Unable to set configuration"));
    return r;
}

static DBusMessage *endpoint_select_configuration(DBusConnection *conn, DBusMessage *m, void *userdata) {
    pa_bluetooth_discovery *y = userdata;
    const char *endpoint_path;
    uint8_t *cap;
    int size;
    const pa_a2dp_codec *a2dp_codec;
    uint8_t config[MAX_A2DP_CAPS_SIZE];
    uint8_t *config_ptr = config;
    size_t config_size;
    DBusMessage *r;
    DBusError err;

    endpoint_path = dbus_message_get_path(m);

    dbus_error_init(&err);

    if (!dbus_message_get_args(m, &err, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &cap, &size, DBUS_TYPE_INVALID)) {
        pa_log_error("Endpoint SelectConfiguration(): %s", err.message);
        dbus_error_free(&err);
        goto fail;
    }

    a2dp_codec = a2dp_endpoint_to_a2dp_codec(endpoint_path);
    pa_assert(a2dp_codec);

    config_size = a2dp_codec->fill_preferred_configuration(&y->core->default_sample_spec, cap, size, config);
    if (config_size == 0)
        goto fail;

    pa_assert_se(r = dbus_message_new_method_return(m));
    pa_assert_se(dbus_message_append_args(r, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &config_ptr, config_size, DBUS_TYPE_INVALID));

    return r;

fail:
    pa_assert_se(r = dbus_message_new_error(m, "org.bluez.Error.InvalidArguments", "Unable to select configuration"));
    return r;
}

static DBusMessage *endpoint_clear_configuration(DBusConnection *conn, DBusMessage *m, void *userdata) {
    pa_bluetooth_discovery *y = userdata;
    pa_bluetooth_transport *t;
    DBusMessage *r;
    DBusError err;
    const char *path;

    dbus_error_init(&err);

    if (!dbus_message_get_args(m, &err, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID)) {
        pa_log_error("Endpoint ClearConfiguration(): %s", err.message);
        dbus_error_free(&err);
        goto fail;
    }

    if ((t = pa_hashmap_get(y->transports, path))) {
        pa_log_debug("Clearing transport %s profile %s", t->path, pa_bluetooth_profile_to_string(t->profile));
        pa_bluetooth_transport_free(t);
    }

    pa_assert_se(r = dbus_message_new_method_return(m));

    return r;

fail:
    pa_assert_se(r = dbus_message_new_error(m, "org.bluez.Error.InvalidArguments", "Unable to clear configuration"));
    return r;
}

static DBusMessage *endpoint_release(DBusConnection *conn, DBusMessage *m, void *userdata) {
    DBusMessage *r = NULL;

    /* From doc/media-api.txt in bluez:
     *
     *    This method gets called when the service daemon
     *    unregisters the endpoint. An endpoint can use it to do
     *    cleanup tasks. There is no need to unregister the
     *    endpoint, because when this method gets called it has
     *    already been unregistered.
     *
     * We don't have any cleanup to do. */

    /* Reply only if requested. Generally bluetoothd doesn't request a reply
     * to the Release() call. Sending replies when not requested on the system
     * bus tends to cause errors in syslog from dbus-daemon, because it
     * doesn't let unexpected replies through, so it's important to have this
     * check here. */
    if (!dbus_message_get_no_reply(m))
        pa_assert_se(r = dbus_message_new_method_return(m));

    return r;
}

static DBusHandlerResult endpoint_handler(DBusConnection *c, DBusMessage *m, void *userdata) {
    struct pa_bluetooth_discovery *y = userdata;
    DBusMessage *r = NULL;
    const char *path, *interface, *member;

    pa_assert(y);

    path = dbus_message_get_path(m);
    interface = dbus_message_get_interface(m);
    member = dbus_message_get_member(m);

    pa_log_debug("dbus: path=%s, interface=%s, member=%s", path, interface, member);

    if (!a2dp_endpoint_to_a2dp_codec(path))
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    if (dbus_message_is_method_call(m, "org.freedesktop.DBus.Introspectable", "Introspect")) {
        const char *xml = ENDPOINT_INTROSPECT_XML;

        pa_assert_se(r = dbus_message_new_method_return(m));
        pa_assert_se(dbus_message_append_args(r, DBUS_TYPE_STRING, &xml, DBUS_TYPE_INVALID));

    } else if (dbus_message_is_method_call(m, BLUEZ_MEDIA_ENDPOINT_INTERFACE, "SetConfiguration"))
        r = endpoint_set_configuration(c, m, userdata);
    else if (dbus_message_is_method_call(m, BLUEZ_MEDIA_ENDPOINT_INTERFACE, "SelectConfiguration"))
        r = endpoint_select_configuration(c, m, userdata);
    else if (dbus_message_is_method_call(m, BLUEZ_MEDIA_ENDPOINT_INTERFACE, "ClearConfiguration"))
        r = endpoint_clear_configuration(c, m, userdata);
    else if (dbus_message_is_method_call(m, BLUEZ_MEDIA_ENDPOINT_INTERFACE, "Release"))
        r = endpoint_release(c, m, userdata);
    else
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    if (r) {
        pa_assert_se(dbus_connection_send(pa_dbus_connection_get(y->connection), r, NULL));
        dbus_message_unref(r);
    }

    return DBUS_HANDLER_RESULT_HANDLED;
}

static void endpoint_init(pa_bluetooth_discovery *y, const char *endpoint) {
    static const DBusObjectPathVTable vtable_endpoint = {
        .message_function = endpoint_handler,
    };

    pa_assert(y);
    pa_assert(endpoint);

    pa_assert_se(dbus_connection_register_object_path(pa_dbus_connection_get(y->connection), endpoint,
                                                      &vtable_endpoint, y));
}

static void endpoint_done(pa_bluetooth_discovery *y, const char *endpoint) {
    pa_assert(y);
    pa_assert(endpoint);

    dbus_connection_unregister_object_path(pa_dbus_connection_get(y->connection), endpoint);
}

static void append_a2dp_object(DBusMessageIter *iter, const char *endpoint, const char *uuid, uint8_t codec_id, uint8_t *capabilities, size_t capabilities_size) {
    const char *interface_name = BLUEZ_MEDIA_ENDPOINT_INTERFACE;
    DBusMessageIter object, array, entry, dict;

    dbus_message_iter_open_container(iter, DBUS_TYPE_DICT_ENTRY, NULL, &object);
    pa_assert_se(dbus_message_iter_append_basic(&object, DBUS_TYPE_OBJECT_PATH, &endpoint));

    dbus_message_iter_open_container(&object, DBUS_TYPE_ARRAY,
                                     DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                     DBUS_TYPE_STRING_AS_STRING
                                     DBUS_TYPE_ARRAY_AS_STRING
                                     DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                     DBUS_TYPE_STRING_AS_STRING
                                     DBUS_TYPE_VARIANT_AS_STRING
                                     DBUS_DICT_ENTRY_END_CHAR_AS_STRING
                                     DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
                                     &array);

    dbus_message_iter_open_container(&array, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
    pa_assert_se(dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &interface_name));

    dbus_message_iter_open_container(&entry, DBUS_TYPE_ARRAY,
                                     DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                     DBUS_TYPE_STRING_AS_STRING
                                     DBUS_TYPE_VARIANT_AS_STRING DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
                                     &dict);

    pa_dbus_append_basic_variant_dict_entry(&dict, "UUID", DBUS_TYPE_STRING, &uuid);
    pa_dbus_append_basic_variant_dict_entry(&dict, "Codec", DBUS_TYPE_BYTE, &codec_id);
    pa_dbus_append_basic_array_variant_dict_entry(&dict, "Capabilities", DBUS_TYPE_BYTE, capabilities, capabilities_size);

    dbus_message_iter_close_container(&entry, &dict);
    dbus_message_iter_close_container(&array, &entry);
    dbus_message_iter_close_container(&object, &array);
    dbus_message_iter_close_container(iter, &object);
}

static DBusHandlerResult object_manager_handler(DBusConnection *c, DBusMessage *m, void *userdata) {
    struct pa_bluetooth_discovery *y = userdata;
    DBusMessage *r;
    const char *path, *interface, *member;

    pa_assert(y);

    path = dbus_message_get_path(m);
    interface = dbus_message_get_interface(m);
    member = dbus_message_get_member(m);

    pa_log_debug("dbus: path=%s, interface=%s, member=%s", path, interface, member);

    if (dbus_message_is_method_call(m, "org.freedesktop.DBus.Introspectable", "Introspect")) {
        const char *xml = OBJECT_MANAGER_INTROSPECT_XML;

        pa_assert_se(r = dbus_message_new_method_return(m));
        pa_assert_se(dbus_message_append_args(r, DBUS_TYPE_STRING, &xml, DBUS_TYPE_INVALID));
    } else if (dbus_message_is_method_call(m, "org.freedesktop.DBus.ObjectManager", "GetManagedObjects")) {
        DBusMessageIter iter, array;
        unsigned a2dp_codec_i;

        pa_assert_se(r = dbus_message_new_method_return(m));

        dbus_message_iter_init_append(r, &iter);
        dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
                                         DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                         DBUS_TYPE_OBJECT_PATH_AS_STRING
                                         DBUS_TYPE_ARRAY_AS_STRING
                                         DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                         DBUS_TYPE_STRING_AS_STRING
                                         DBUS_TYPE_ARRAY_AS_STRING
                                         DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                         DBUS_TYPE_STRING_AS_STRING
                                         DBUS_TYPE_VARIANT_AS_STRING
                                         DBUS_DICT_ENTRY_END_CHAR_AS_STRING
                                         DBUS_DICT_ENTRY_END_CHAR_AS_STRING
                                         DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
                                         &array);

        /* Order is important. bluez prefers endpoints registered earlier.
         * And codec with higher number has higher priority. So iterate in reverse order. */
        for (a2dp_codec_i = pa_bluetooth_a2dp_codec_count(); a2dp_codec_i > 0; a2dp_codec_i--) {
            const pa_a2dp_codec *a2dp_codec;
            uint8_t capabilities[MAX_A2DP_CAPS_SIZE];
            size_t capabilities_size;
            uint8_t codec_id;
            char *endpoint;

            a2dp_codec = pa_bluetooth_a2dp_codec_iter(a2dp_codec_i-1);
            codec_id = a2dp_codec->id.codec_id;
            capabilities_size = a2dp_codec->fill_capabilities(capabilities);
            pa_assert(capabilities_size != 0);

            endpoint = pa_sprintf_malloc("%s/%s", A2DP_SINK_ENDPOINT, a2dp_codec->name);
            append_a2dp_object(&array, endpoint, PA_BLUETOOTH_UUID_A2DP_SINK, codec_id, capabilities, capabilities_size);
            pa_xfree(endpoint);

            endpoint = pa_sprintf_malloc("%s/%s", A2DP_SOURCE_ENDPOINT, a2dp_codec->name);
            append_a2dp_object(&array, endpoint, PA_BLUETOOTH_UUID_A2DP_SOURCE, codec_id, capabilities, capabilities_size);
            pa_xfree(endpoint);
        }

        dbus_message_iter_close_container(&iter, &array);
    } else
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    pa_assert_se(dbus_connection_send(pa_dbus_connection_get(y->connection), r, NULL));
    dbus_message_unref(r);

    return DBUS_HANDLER_RESULT_HANDLED;
}

static void object_manager_init(pa_bluetooth_discovery *y) {
    static const DBusObjectPathVTable vtable = {
        .message_function = object_manager_handler,
    };

    pa_assert(y);
    pa_assert_se(dbus_connection_register_object_path(pa_dbus_connection_get(y->connection), A2DP_OBJECT_MANAGER_PATH, &vtable, y));
}

static void object_manager_done(pa_bluetooth_discovery *y) {
    pa_assert(y);
    dbus_connection_unregister_object_path(pa_dbus_connection_get(y->connection), A2DP_OBJECT_MANAGER_PATH);
}

pa_bluetooth_discovery* pa_bluetooth_discovery_get(pa_core *c, int headset_backend) {
    pa_bluetooth_discovery *y;
    DBusError err;
    DBusConnection *conn;
    unsigned i, count;
    const pa_a2dp_codec *a2dp_codec;
    char *endpoint;

    y = pa_xnew0(pa_bluetooth_discovery, 1);
    PA_REFCNT_INIT(y);
    y->core = c;
    y->headset_backend = headset_backend;
    y->adapters = pa_hashmap_new_full(pa_idxset_string_hash_func, pa_idxset_string_compare_func, NULL,
                                      (pa_free_cb_t) adapter_free);
    y->devices = pa_hashmap_new_full(pa_idxset_string_hash_func, pa_idxset_string_compare_func, NULL,
                                     (pa_free_cb_t) device_free);
    y->transports = pa_hashmap_new(pa_idxset_string_hash_func, pa_idxset_string_compare_func);
    PA_LLIST_HEAD_INIT(pa_dbus_pending, y->pending);

    for (i = 0; i < PA_BLUETOOTH_HOOK_MAX; i++)
        pa_hook_init(&y->hooks[i], y);

    pa_shared_set(c, "bluetooth-discovery", y);

    dbus_error_init(&err);

    if (!(y->connection = pa_dbus_bus_get(y->core, DBUS_BUS_SYSTEM, &err))) {
        pa_log_error("Failed to get D-Bus connection: %s", err.message);
        goto fail;
    }

    conn = pa_dbus_connection_get(y->connection);

    /* dynamic detection of bluetooth audio devices */
    if (!dbus_connection_add_filter(conn, filter_cb, y, NULL)) {
        pa_log_error("Failed to add filter function");
        goto fail;
    }
    y->filter_added = true;

    if (pa_dbus_add_matches(conn, &err,
            "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged'"
            ",arg0='" BLUEZ_SERVICE "'",
            "type='signal',sender='" BLUEZ_SERVICE "',interface='org.freedesktop.DBus.ObjectManager',member='InterfacesAdded'",
            "type='signal',sender='" BLUEZ_SERVICE "',interface='org.freedesktop.DBus.ObjectManager',"
            "member='InterfacesRemoved'",
            "type='signal',sender='" BLUEZ_SERVICE "',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged'"
            ",arg0='" BLUEZ_ADAPTER_INTERFACE "'",
            "type='signal',sender='" BLUEZ_SERVICE "',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged'"
            ",arg0='" BLUEZ_DEVICE_INTERFACE "'",
            "type='signal',sender='" BLUEZ_SERVICE "',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged'"
            ",arg0='" BLUEZ_MEDIA_ENDPOINT_INTERFACE "'",
            "type='signal',sender='" BLUEZ_SERVICE "',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged'"
            ",arg0='" BLUEZ_MEDIA_TRANSPORT_INTERFACE "'",
            NULL) < 0) {
        pa_log_error("Failed to add D-Bus matches: %s", err.message);
        goto fail;
    }
    y->matches_added = true;

    object_manager_init(y);

    count = pa_bluetooth_a2dp_codec_count();
    for (i = 0; i < count; i++) {
        a2dp_codec = pa_bluetooth_a2dp_codec_iter(i);

        endpoint = pa_sprintf_malloc("%s/%s", A2DP_SINK_ENDPOINT, a2dp_codec->name);
        endpoint_init(y, endpoint);
        pa_xfree(endpoint);

        endpoint = pa_sprintf_malloc("%s/%s", A2DP_SOURCE_ENDPOINT, a2dp_codec->name);
        endpoint_init(y, endpoint);
        pa_xfree(endpoint);
    }

    get_managed_objects(y);

    return y;

fail:
    pa_bluetooth_discovery_unref(y);
    dbus_error_free(&err);

    return NULL;
}

pa_bluetooth_discovery* pa_bluetooth_discovery_ref(pa_bluetooth_discovery *y) {
    pa_assert(y);
    pa_assert(PA_REFCNT_VALUE(y) > 0);

    PA_REFCNT_INC(y);

    return y;
}

void pa_bluetooth_discovery_unref(pa_bluetooth_discovery *y) {
    unsigned i, count;
    const pa_a2dp_codec *a2dp_codec;
    char *endpoint;

    pa_assert(y);
    pa_assert(PA_REFCNT_VALUE(y) > 0);

    if (PA_REFCNT_DEC(y) > 0)
        return;

    pa_dbus_free_pending_list(&y->pending);

    if (y->hsphfpd_backend)
        pa_bluetooth_hsphfpd_backend_free(y->hsphfpd_backend);

    if (y->legacy_hsp_backend)
        pa_bluetooth_legacy_hsp_backend_free(y->legacy_hsp_backend);

    if (y->adapters)
        pa_hashmap_free(y->adapters);

    if (y->devices)
        pa_hashmap_free(y->devices);

    if (y->transports) {
        pa_assert(pa_hashmap_isempty(y->transports));
        pa_hashmap_free(y->transports);
    }

    if (y->connection) {

        if (y->matches_added)
            pa_dbus_remove_matches(pa_dbus_connection_get(y->connection),
                "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged',"
                "arg0='" BLUEZ_SERVICE "'",
                "type='signal',sender='" BLUEZ_SERVICE "',interface='org.freedesktop.DBus.ObjectManager',"
                "member='InterfacesAdded'",
                "type='signal',sender='" BLUEZ_SERVICE "',interface='org.freedesktop.DBus.ObjectManager',"
                "member='InterfacesRemoved'",
                "type='signal',sender='" BLUEZ_SERVICE "',interface='org.freedesktop.DBus.Properties',"
                "member='PropertiesChanged',arg0='" BLUEZ_ADAPTER_INTERFACE "'",
                "type='signal',sender='" BLUEZ_SERVICE "',interface='org.freedesktop.DBus.Properties',"
                "member='PropertiesChanged',arg0='" BLUEZ_DEVICE_INTERFACE "'",
                "type='signal',sender='" BLUEZ_SERVICE "',interface='org.freedesktop.DBus.Properties',"
                "member='PropertiesChanged',arg0='" BLUEZ_MEDIA_ENDPOINT_INTERFACE "'",
                "type='signal',sender='" BLUEZ_SERVICE "',interface='org.freedesktop.DBus.Properties',"
                "member='PropertiesChanged',arg0='" BLUEZ_MEDIA_TRANSPORT_INTERFACE "'",
                NULL);

        if (y->filter_added)
            dbus_connection_remove_filter(pa_dbus_connection_get(y->connection), filter_cb, y);

        object_manager_done(y);

        count = pa_bluetooth_a2dp_codec_count();
        for (i = 0; i < count; i++) {
            a2dp_codec = pa_bluetooth_a2dp_codec_iter(i);

            endpoint = pa_sprintf_malloc("%s/%s", A2DP_SINK_ENDPOINT, a2dp_codec->name);
            endpoint_done(y, endpoint);
            pa_xfree(endpoint);

            endpoint = pa_sprintf_malloc("%s/%s", A2DP_SOURCE_ENDPOINT, a2dp_codec->name);
            endpoint_done(y, endpoint);
            pa_xfree(endpoint);
        }

        pa_dbus_connection_unref(y->connection);
    }

    pa_shared_remove(y->core, "bluetooth-discovery");
    pa_xfree(y);
}
