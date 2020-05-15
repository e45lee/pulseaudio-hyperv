/***
  This file is part of PulseAudio.

  Copyright 2020 Pali Rohár <pali.rohar@gmail.com>

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

#include <errno.h>

#include <pulsecore/shared.h>
#include <pulsecore/core-error.h>
#include <pulsecore/core-util.h>
#include <pulsecore/dbus-shared.h>
#include <pulsecore/log.h>

#include "bluez5-util.h"
#include "hsphfpd-util.h"
#include "legacy-hsp.h"

#define DBUS_INTERFACE_OBJECTMANAGER DBUS_SERVICE_DBUS ".ObjectManager"

#define HSPHFPD_SERVICE "org.hsphfpd"
#define HSPHFPD_APPLICATION_MANAGER_INTERFACE HSPHFPD_SERVICE ".ApplicationManager"
#define HSPHFPD_ENDPOINT_INTERFACE HSPHFPD_SERVICE ".Endpoint"
#define HSPHFPD_AUDIO_TRANSPORT_INTERFACE HSPHFPD_SERVICE ".AudioTransport"
#define HSPHFPD_AUDIO_AGENT_INTERFACE HSPHFPD_SERVICE ".AudioAgent"

#define APPLICATION_OBJECT_MANAGER_PATH "/SCOEndpoint"
#define AUDIO_AGENT_ENDPOINT_PCM_S16LE_8KHZ APPLICATION_OBJECT_MANAGER_PATH "/PCM_s16le_8kHz"
#define AUDIO_AGENT_ENDPOINT_MSBC APPLICATION_OBJECT_MANAGER_PATH "/mSBC"

#define APPLICATION_OBJECT_MANAGER_INTROSPECT_XML                              \
    DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                                  \
    "<node>\n"                                                                 \
    " <interface name=\"" DBUS_INTERFACE_OBJECTMANAGER "\">\n"                 \
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
    " <interface name=\"" DBUS_INTERFACE_INTROSPECTABLE "\">\n"                \
    "  <method name=\"Introspect\">\n"                                         \
    "   <arg name=\"data\" direction=\"out\" type=\"s\"/>\n"                   \
    "  </method>\n"                                                            \
    " </interface>\n"                                                          \
    "</node>\n"

#define AUDIO_AGENT_ENDPOINT_INTROSPECT_XML                                    \
    DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                                  \
    "<node>\n"                                                                 \
    " <interface name=\"" HSPHFPD_AUDIO_AGENT_INTERFACE "\">\n"                \
    "  <method name=\"NewConnection\">\n"                                      \
    "   <arg name=\"audio_transport\" direction=\"in\" type=\"o\"/>\n"         \
    "   <arg name=\"sco\" direction=\"in\" type=\"h\"/>\n"                     \
    "   <arg name=\"properties\" direction=\"in\" type=\"a{sv}\"/>\n"          \
    "  </method>\n"                                                            \
    "  <property name=\"AgentCodec\" type=\"s\" access=\"read\"/>\n"           \
    " </interface>\n"                                                          \
    " <interface name=\"" DBUS_INTERFACE_INTROSPECTABLE "\">\n"                \
    "  <method name=\"Introspect\">\n"                                         \
    "   <arg name=\"data\" direction=\"out\" type=\"s\"/>\n"                   \
    "  </method>\n"                                                            \
    " </interface>\n"                                                          \
    " <interface name=\"" DBUS_INTERFACE_PROPERTIES "\">\n"                    \
    "  <method name=\"Get\">\n"                                                \
    "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"               \
    "   <arg name=\"name\" direction=\"in\" type=\"s\"/>\n"                    \
    "   <arg name=\"value\" direction=\"out\" type=\"v\"/>\n"                  \
    "  </method>\n"                                                            \
    "  <method name=\"GetAll\">\n"                                             \
    "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"               \
    "   <arg name=\"properties\" direction=\"out\" type=\"a{sv}\"/>\n"         \
    "  </method>\n"                                                            \
    " </interface>\n"                                                          \
    "</node>\n"

enum hsphfpd_volume_control {
    HSPHFPD_VOLUME_CONTROL_NONE = 1,
    HSPHFPD_VOLUME_CONTROL_LOCAL,
    HSPHFPD_VOLUME_CONTROL_REMOTE,
};

enum hsphfpd_profile {
    HSPHFPD_PROFILE_HEADSET = 1,
    HSPHFPD_PROFILE_HANDSFREE,
};

enum hsphfpd_role {
    HSPHFPD_ROLE_CLIENT = 1,
    HSPHFPD_ROLE_GATEWAY,
};

struct hsphfpd_transport_data {
    pa_bluetooth_hsphfpd *hsphfpd;
    int sco_fd;
    char *transport_path;
    char *agent_codec;
    char *air_codec;
    enum hsphfpd_volume_control rx_volume_control;
    enum hsphfpd_volume_control tx_volume_control;
    uint16_t mtu;
};

struct hsphfpd_endpoint {
    char *path;
    bool valid;
    bool connected;
    char *remote_address;
    char *local_address;
    enum hsphfpd_profile profile;
    enum hsphfpd_role role;
};

struct pa_bluetooth_hsphfpd {
    pa_core *core;
    pa_bluetooth_legacy_hsp *legacy_hsp;
    pa_bluetooth_discovery *discovery;
    pa_dbus_connection *connection;
    pa_hashmap *endpoints;
    bool endpoints_listed;
    char *hsphfpd_service_id;

    PA_LLIST_HEAD(pa_dbus_pending, pending);
};

static void hsphfpd_endpoint_free(struct hsphfpd_endpoint *endpoint) {
    pa_assert(endpoint);

    pa_xfree(endpoint->path);
    pa_xfree(endpoint->remote_address);
    pa_xfree(endpoint->local_address);
    pa_xfree(endpoint);
}

static pa_dbus_pending *send_and_add_to_pending(pa_bluetooth_hsphfpd *hsphfpd, DBusMessage *m, DBusPendingCallNotifyFunction func, void *call_data) {
    pa_dbus_pending *p;
    DBusPendingCall *call;

    pa_assert(hsphfpd);
    pa_assert(m);

    pa_assert_se(dbus_connection_send_with_reply(pa_dbus_connection_get(hsphfpd->connection), m, &call, -1));

    p = pa_dbus_pending_new(pa_dbus_connection_get(hsphfpd->connection), m, call, hsphfpd, call_data);
    PA_LLIST_PREPEND(pa_dbus_pending, hsphfpd->pending, p);
    dbus_pending_call_set_notify(call, func, p, NULL);

    return p;
}

static void set_dbus_property_reply(DBusPendingCall *pending, void *userdata) {
    DBusMessage *r;
    pa_dbus_pending *p;
    pa_bluetooth_hsphfpd *hsphfpd;
    char *error_message;

    pa_assert(pending);
    pa_assert_se(p = userdata);
    pa_assert_se(hsphfpd = p->context_data);
    pa_assert_se(error_message = p->call_data);
    pa_assert_se(r = dbus_pending_call_steal_reply(pending));

    if (dbus_message_get_type(r) == DBUS_MESSAGE_TYPE_ERROR)
        pa_log_error("%s: %s: %s", error_message, dbus_message_get_error_name(r), pa_dbus_get_error_message(r));

    pa_xfree(error_message);

    dbus_message_unref(r);

    PA_LLIST_REMOVE(pa_dbus_pending, hsphfpd->pending, p);
    pa_dbus_pending_free(p);
}

static void set_dbus_property(pa_bluetooth_hsphfpd *hsphfpd, const char *service, const char *path, const char *interface, const char *property, int type, void *value, char *error_message) {
    DBusMessage *m;
    DBusMessageIter iter;
    pa_assert_se(m = dbus_message_new_method_call(service, path, DBUS_INTERFACE_PROPERTIES, "Set"));
    pa_assert_se(dbus_message_append_args(m, DBUS_TYPE_STRING, &interface, DBUS_TYPE_STRING, &property, DBUS_TYPE_INVALID));
    dbus_message_iter_init_append(m, &iter);
    pa_dbus_append_basic_variant(&iter, type, value);
    send_and_add_to_pending(hsphfpd, m, set_dbus_property_reply, error_message);
}

static inline void set_rx_volume_gain_property(const struct hsphfpd_transport_data *transport_data, uint16_t gain) {
    if (transport_data->sco_fd < 0 || transport_data->rx_volume_control <= HSPHFPD_VOLUME_CONTROL_NONE)
        return;
    set_dbus_property(transport_data->hsphfpd, HSPHFPD_SERVICE, transport_data->transport_path, HSPHFPD_AUDIO_TRANSPORT_INTERFACE, "RxVolumeGain", DBUS_TYPE_UINT16, &gain, pa_sprintf_malloc("Changing rx volume gain to %u for transport %s failed", (unsigned)gain, transport_data->transport_path));
}

static inline void set_tx_volume_gain_property(const struct hsphfpd_transport_data *transport_data, uint16_t gain) {
    if (transport_data->sco_fd < 0 || transport_data->tx_volume_control <= HSPHFPD_VOLUME_CONTROL_NONE)
        return;
    set_dbus_property(transport_data->hsphfpd, HSPHFPD_SERVICE, transport_data->transport_path, HSPHFPD_AUDIO_TRANSPORT_INTERFACE, "TxVolumeGain", DBUS_TYPE_UINT16, &gain, pa_sprintf_malloc("Changing tx volume gain to %u for transport %s failed", (unsigned)gain, transport_data->transport_path));
}

static void hsphfpd_transport_connect_audio_reply(DBusPendingCall *pending, void *userdata) {
    DBusMessage *r;
    DBusError error;
    pa_dbus_pending *p;
    pa_bluetooth_hsphfpd *hsphfpd;
    pa_bluetooth_transport *transport;
    const char *error_name;
    char *endpoint_path;
    const char *transport_path;
    const char *service_id;
    const char *agent_path;

    pa_assert(pending);
    pa_assert_se(p = userdata);
    pa_assert_se(hsphfpd = p->context_data);
    pa_assert_se(endpoint_path = p->call_data);
    pa_assert_se(r = dbus_pending_call_steal_reply(pending));

    dbus_error_init(&error);

    if (dbus_message_get_type(r) == DBUS_MESSAGE_TYPE_ERROR) {
        error_name = dbus_message_get_error_name(r);
        if (pa_safe_streq(error_name, HSPHFPD_SERVICE ".AlreadyConnected"))
            goto success;
        if (pa_safe_streq(error_name, HSPHFPD_SERVICE ".InProgress"))
            goto finish; /* Another ConnectAudio() call is in progress, so do not touch transport state */
        pa_log_warn(HSPHFPD_ENDPOINT_INTERFACE ".ConnectAudio() failed: %s: %s", error_name, pa_dbus_get_error_message(r));
        goto failed;
    }

    if (!pa_safe_streq(dbus_message_get_sender(r), hsphfpd->hsphfpd_service_id)) {
        pa_log_error("Reply for " HSPHFPD_ENDPOINT_INTERFACE ".ConnectAudio() from invalid sender");
        goto failed;
    }

    if (!pa_streq(dbus_message_get_signature(r), "oso")) {
        pa_log_error("Invalid reply signature for " HSPHFPD_ENDPOINT_INTERFACE ".ConnectAudio()");
        goto failed;
    }

    if (!dbus_message_get_args(r, &error, DBUS_TYPE_OBJECT_PATH, &transport_path, DBUS_TYPE_STRING, &service_id, DBUS_TYPE_OBJECT_PATH, &agent_path, DBUS_TYPE_INVALID) || dbus_error_is_set(&error)) {
        pa_log_error("Failed to parse " HSPHFPD_ENDPOINT_INTERFACE ".ConnectAudio() reply: %s", error.message);
        goto failed;
    }

    if (!pa_safe_streq(service_id, dbus_bus_get_unique_name(pa_dbus_connection_get(hsphfpd->connection)))) {
        pa_log_warn(HSPHFPD_ENDPOINT_INTERFACE ".ConnectAudio() failed: Other audio application took audio socket");
        goto failed;
    }

success:
    /* On success hsphfpd daemon asynchronously should have called NewConnection() method
     * prior sending reply for ConnectAudio() method. Our callback for NewConnection()
     * changes transport state to playing on success, so check it if connection is really
     * successfully established. */
    transport = pa_bluetooth_transport_get(hsphfpd->discovery, endpoint_path);
    if (transport && transport->state == PA_BLUETOOTH_TRANSPORT_STATE_PLAYING)
        goto finish;

failed:
    /* If transport state is idle switch it to disconnected state and then back to idle state
     * so sinks and sources are properly released and connection attempt is marked as failed,
     * this also trigger profile change to off */
    transport = pa_bluetooth_transport_get(hsphfpd->discovery, endpoint_path);
    if (transport && transport->state == PA_BLUETOOTH_TRANSPORT_STATE_IDLE) {
        pa_bluetooth_transport_set_state(transport, PA_BLUETOOTH_TRANSPORT_STATE_DISCONNECTED);
        pa_bluetooth_transport_set_state(transport, PA_BLUETOOTH_TRANSPORT_STATE_IDLE);
    }

finish:
    pa_xfree(endpoint_path);

    dbus_error_free(&error);
    dbus_message_unref(r);

    PA_LLIST_REMOVE(pa_dbus_pending, hsphfpd->pending, p);
    pa_dbus_pending_free(p);
}

static void hsphfpd_connect_audio(pa_bluetooth_hsphfpd *hsphfpd, const char *endpoint_path) {
    /* TODO: support for choosing codec is not implemented yet */
    const char *air_codec = "CVSD";
    const char *agent_codec = "PCM_s16le_8kHz";
    DBusMessage *m;

    pa_assert_se(m = dbus_message_new_method_call(HSPHFPD_SERVICE, endpoint_path, HSPHFPD_ENDPOINT_INTERFACE, "ConnectAudio"));
    pa_assert_se(dbus_message_append_args(m, DBUS_TYPE_STRING, &air_codec, DBUS_TYPE_STRING, &agent_codec, DBUS_TYPE_INVALID));
    send_and_add_to_pending(hsphfpd, m, hsphfpd_transport_connect_audio_reply, pa_xstrdup(endpoint_path));
}

static int hsphfpd_transport_acquire(pa_bluetooth_transport *transport, size_t *imtu, size_t *omtu) {
    struct hsphfpd_transport_data *transport_data = transport->userdata;

    if (transport_data->sco_fd < 0) {
        hsphfpd_connect_audio(transport_data->hsphfpd, transport->path);
        return -EAGAIN;
    }

    if (imtu) *imtu = transport_data->mtu;
    if (omtu) *omtu = transport_data->mtu;
    return transport_data->sco_fd;
}

static void hsphfpd_transport_release(pa_bluetooth_transport *transport) {
    struct hsphfpd_transport_data *transport_data = transport->userdata;

    if (transport_data->sco_fd < 0) {
        pa_log_info("Transport for endpoint %s already released", transport->path);
        return;
    }

    shutdown(transport_data->sco_fd, SHUT_RDWR);
    transport_data->sco_fd = -1;
    /* file descriptor is closed by teardown_stream() */

    pa_xfree(transport_data->transport_path);
    transport_data->transport_path = NULL;

    pa_xfree(transport_data->agent_codec);
    transport_data->agent_codec = NULL;

    pa_xfree(transport_data->air_codec);
    transport_data->air_codec = NULL;

    transport_data->mtu = 0;
}

static void hsphfpd_transport_destroy(pa_bluetooth_transport *transport) {
    struct hsphfpd_transport_data *transport_data = transport->userdata;

    pa_xfree(transport_data->transport_path);
    pa_xfree(transport_data->agent_codec);
    pa_xfree(transport_data->air_codec);
    pa_xfree(transport_data);
}

static void hsphfpd_transport_set_tx_volume_gain(pa_bluetooth_transport *transport, uint16_t gain) {
    struct hsphfpd_transport_data *transport_data = transport->userdata;

    if (transport->tx_volume_gain == gain)
        return;

    set_tx_volume_gain_property(transport_data, gain);
    transport->tx_volume_gain = gain;
}

static void hsphfpd_transport_set_rx_volume_gain(pa_bluetooth_transport *transport, uint16_t gain) {
    struct hsphfpd_transport_data *transport_data = transport->userdata;

    if (transport->rx_volume_gain == gain)
        return;

    set_rx_volume_gain_property(transport_data, gain);
    transport->rx_volume_gain = gain;
}

static void parse_transport_properties_values(pa_bluetooth_hsphfpd *hsphfpd, const char *transport_path, DBusMessageIter *i, const char **endpoint_path, const char **air_codec, enum hsphfpd_volume_control *rx_volume_control, enum hsphfpd_volume_control *tx_volume_control, uint16_t *rx_volume_gain, uint16_t *tx_volume_gain, uint16_t *mtu) {
    DBusMessageIter element_i;

    pa_assert(i);

    dbus_message_iter_recurse(i, &element_i);

    while (dbus_message_iter_get_arg_type(&element_i) == DBUS_TYPE_DICT_ENTRY) {
        DBusMessageIter dict_i, variant_i;
        const char *key;

        dbus_message_iter_recurse(&element_i, &dict_i);

        if (dbus_message_iter_get_arg_type(&dict_i) != DBUS_TYPE_STRING) {
            pa_log_error("Received invalid property for transport %s", transport_path);
            return;
        }

        dbus_message_iter_get_basic(&dict_i, &key);

        if (!dbus_message_iter_next(&dict_i)) {
            pa_log_error("Received invalid property for transport %s", transport_path);
            return;
        }

        if (dbus_message_iter_get_arg_type(&dict_i) != DBUS_TYPE_VARIANT) {
            pa_log_error("Received invalid property for transport %s", transport_path);
            return;
        }

        dbus_message_iter_recurse(&dict_i, &variant_i);

        switch (dbus_message_iter_get_arg_type(&variant_i)) {
            case DBUS_TYPE_STRING:
                if (pa_streq(key, "RxVolumeControl") || pa_streq(key, "TxVolumeControl")) {
                    const char *value;
                    enum hsphfpd_volume_control volume_control;

                    dbus_message_iter_get_basic(&variant_i, &value);
                    if (pa_streq(value, "none"))
                        volume_control = HSPHFPD_VOLUME_CONTROL_NONE;
                    else if (pa_streq(value, "local"))
                        volume_control = HSPHFPD_VOLUME_CONTROL_LOCAL;
                    else if (pa_streq(value, "remote"))
                        volume_control = HSPHFPD_VOLUME_CONTROL_REMOTE;
                    else
                        volume_control = 0;

                    if (!volume_control)
                        pa_log_warn("Transport %s received invalid '%s' property value '%s', ignoring", transport_path, key, value);
                    else if (pa_streq(key, "RxVolumeControl"))
                        *rx_volume_control = volume_control;
                    else if (pa_streq(key, "TxVolumeControl"))
                        *tx_volume_control = volume_control;
                } else if (pa_streq(key, "AirCodec"))
                    dbus_message_iter_get_basic(&variant_i, air_codec);
                break;

            case DBUS_TYPE_UINT16:
                if (pa_streq(key, "MTU"))
                    dbus_message_iter_get_basic(&variant_i, mtu);
                else if (pa_streq(key, "RxVolumeGain"))
                    dbus_message_iter_get_basic(&variant_i, rx_volume_gain);
                else if (pa_streq(key, "TxVolumeGain"))
                    dbus_message_iter_get_basic(&variant_i, tx_volume_gain);
                break;

            case DBUS_TYPE_OBJECT_PATH:
                if (pa_streq(key, "Endpoint"))
                    dbus_message_iter_get_basic(&variant_i, endpoint_path);
                break;
        }

        dbus_message_iter_next(&element_i);
    }
}

static void parse_transport_properties(pa_bluetooth_transport *transport, DBusMessageIter *i) {
    struct hsphfpd_transport_data *transport_data = transport->userdata;
    bool rx_volume_gain_changed = false;
    bool tx_volume_gain_changed = false;
    bool rx_volume_control_changed = false;
    bool tx_volume_control_changed = false;
    bool rx_soft_volume_changed = false;
    bool tx_soft_volume_changed = false;
    const char *endpoint_path = NULL;
    const char *air_codec = NULL;
    enum hsphfpd_volume_control rx_volume_control = 0;
    enum hsphfpd_volume_control tx_volume_control = 0;
    uint16_t rx_volume_gain = -1;
    uint16_t tx_volume_gain = -1;
    uint16_t mtu = 0;

    parse_transport_properties_values(transport_data->hsphfpd, transport_data->transport_path, i, &endpoint_path, &air_codec, &rx_volume_control, &tx_volume_control, &rx_volume_gain, &tx_volume_gain, &mtu);

    if (endpoint_path)
        pa_log_warn("Transport %s received a duplicate '%s' property, ignoring", transport_data->transport_path, "Endpoint");

    if (air_codec)
        pa_log_warn("Transport %s received a duplicate '%s' property, ignoring", transport_data->transport_path, "AirCodec");

    if (mtu)
        pa_log_warn("Transport %s received a duplicate '%s' property, ignoring", transport_data->transport_path, "MTU");

    if (rx_volume_control) {
        if (!!transport->rx_soft_volume != !!(rx_volume_control != HSPHFPD_VOLUME_CONTROL_REMOTE)) {
            pa_log_info("Transport %s changed rx soft volume from %s to %s", transport_data->transport_path, pa_yes_no(transport->rx_soft_volume), pa_yes_no(rx_volume_control != HSPHFPD_VOLUME_CONTROL_REMOTE));
            transport->rx_soft_volume = (rx_volume_control != HSPHFPD_VOLUME_CONTROL_REMOTE);
            rx_soft_volume_changed = true;
        }
        if (transport_data->rx_volume_control != rx_volume_control) {
            transport_data->rx_volume_control = rx_volume_control;
            rx_volume_control_changed = true;
        }
    }

    if (tx_volume_control) {
        if (!!transport->tx_soft_volume != !!(rx_volume_control != HSPHFPD_VOLUME_CONTROL_REMOTE)) {
            pa_log_info("Transport %s changed tx soft volume from %s to %s", transport_data->transport_path, pa_yes_no(transport->rx_soft_volume), pa_yes_no(rx_volume_control != HSPHFPD_VOLUME_CONTROL_REMOTE));
            transport->tx_soft_volume = (rx_volume_control != HSPHFPD_VOLUME_CONTROL_REMOTE);
            tx_soft_volume_changed = true;
        }
        if (transport_data->rx_volume_control != rx_volume_control) {
            transport_data->rx_volume_control = rx_volume_control;
            rx_volume_control_changed = true;
        }
    }

    if (rx_volume_gain != (uint16_t)-1) {
        if (transport->rx_volume_gain != rx_volume_gain) {
            pa_log_info("Transport %s changed rx volume gain from %u to %u", transport_data->transport_path, (unsigned)transport->rx_volume_gain, (unsigned)rx_volume_gain);
            transport->rx_volume_gain = rx_volume_gain;
            rx_volume_gain_changed = true;
        }
    }

    if (tx_volume_gain != (uint16_t)-1) {
        if (transport->tx_volume_gain != tx_volume_gain) {
            pa_log_info("Transport %s changed tx volume gain from %u to %u", transport_data->transport_path, (unsigned)transport->tx_volume_gain, (unsigned)tx_volume_gain);
            transport->tx_volume_gain = tx_volume_gain;
            tx_volume_gain_changed = true;
        }
    }

    if (rx_volume_gain_changed || rx_soft_volume_changed)
        pa_hook_fire(pa_bluetooth_discovery_hook(transport_data->hsphfpd->discovery, PA_BLUETOOTH_HOOK_TRANSPORT_RX_VOLUME_GAIN_CHANGED), transport);

    if (tx_volume_gain_changed || tx_soft_volume_changed)
        pa_hook_fire(pa_bluetooth_discovery_hook(transport_data->hsphfpd->discovery, PA_BLUETOOTH_HOOK_TRANSPORT_TX_VOLUME_GAIN_CHANGED), transport);

    if (rx_volume_control_changed)
        set_rx_volume_gain_property(transport_data, transport->rx_volume_gain);

    if (tx_volume_control_changed)
        set_tx_volume_gain_property(transport_data, transport->tx_volume_gain);
}

static void parse_endpoint_properties(pa_bluetooth_hsphfpd *hsphfpd, struct hsphfpd_endpoint *endpoint, DBusMessageIter *i) {
    DBusMessageIter element_i;

    pa_assert(i);

    dbus_message_iter_recurse(i, &element_i);

    while (dbus_message_iter_get_arg_type(&element_i) == DBUS_TYPE_DICT_ENTRY) {
        DBusMessageIter dict_i, variant_i;
        const char *key;

        dbus_message_iter_recurse(&element_i, &dict_i);

        if (dbus_message_iter_get_arg_type(&dict_i) != DBUS_TYPE_STRING) {
            pa_log_error("Received invalid property for endpoint %s", endpoint->path);
            return;
        }

        dbus_message_iter_get_basic(&dict_i, &key);

        if (!dbus_message_iter_next(&dict_i)) {
            pa_log_error("Received invalid property for endpoint %s", endpoint->path);
            return;
        }

        if (dbus_message_iter_get_arg_type(&dict_i) != DBUS_TYPE_VARIANT) {
            pa_log_error("Received invalid property for endpoint %s", endpoint->path);
            return;
        }

        dbus_message_iter_recurse(&dict_i, &variant_i);

        switch (dbus_message_iter_get_arg_type(&variant_i)) {
            case DBUS_TYPE_STRING: {
                const char *value;
                dbus_message_iter_get_basic(&variant_i, &value);
                if (pa_streq(key, "LocalAddress")) {
                    if (endpoint->local_address)
                        pa_log_warn("Endpoint %s received a duplicate '%s' property, ignoring", endpoint->path, key);
                    else
                        endpoint->local_address = pa_xstrdup(value);
                } else if (pa_streq(key, "RemoteAddress")) {
                    if (endpoint->remote_address)
                        pa_log_warn("Endpoint %s received a duplicate '%s' property, ignoring", endpoint->path, key);
                    else
                        endpoint->remote_address = pa_xstrdup(value);
                } else if (pa_streq(key, "Profile")) {
                    if (endpoint->profile)
                        pa_log_warn("Endpoint %s received a duplicate '%s' property, ignoring", endpoint->path, key);
                    else if (pa_streq(value, "headset"))
                        endpoint->profile = HSPHFPD_PROFILE_HEADSET;
                    else if (pa_streq(value, "handsfree"))
                        endpoint->profile = HSPHFPD_PROFILE_HANDSFREE;
                    else
                        pa_log_warn("Endpoint %s received invalid '%s' property value '%s', ignoring", endpoint->path, key, value);
                } else if (pa_streq(key, "Role")) {
                    if (endpoint->role)
                        pa_log_warn("Endpoint %s received a duplicate '%s' property, ignoring", endpoint->path, key);
                    else if (pa_streq(value, "client"))
                        endpoint->role = HSPHFPD_ROLE_CLIENT;
                    else if (pa_streq(value, "gateway"))
                        endpoint->role = HSPHFPD_ROLE_GATEWAY;
                    else
                        pa_log_warn("Endpoint %s received invalid '%s' property value '%s', ignoring", endpoint->path, key, value);
                }
                break;
            }

            case DBUS_TYPE_BOOLEAN: {
                bool value;
                dbus_message_iter_get_basic(&variant_i, &value);
                if (pa_streq(key, "Connected") && endpoint->connected != value) {
                    endpoint->connected = value;
                    if (!endpoint->connected) {
                        pa_bluetooth_transport *transport = pa_bluetooth_transport_get(hsphfpd->discovery, endpoint->path);
                        if (transport)
                            pa_bluetooth_transport_free(transport);
                    }
                }
                break;
            }
        }

        dbus_message_iter_next(&element_i);
    }

    if (!endpoint->valid && endpoint->local_address && endpoint->remote_address && endpoint->profile && endpoint->role)
        endpoint->valid = true;

    if (endpoint->valid && endpoint->connected && !pa_bluetooth_transport_get(hsphfpd->discovery, endpoint->path)) {
        struct hsphfpd_transport_data *transport_data;
        pa_bluetooth_transport *transport;
        pa_bluetooth_profile_t profile;
        pa_bluetooth_device *device = pa_bluetooth_discovery_get_device_by_address(hsphfpd->discovery, endpoint->remote_address, endpoint->local_address);
        if (!device) {
            pa_log_error("Device does not exist for endpoint %s (remote addresses %s, local address %s)", endpoint->path, endpoint->remote_address, endpoint->local_address);
        } else {
            pa_log_debug("Creating a new transport for endpoint %s", endpoint->path);

            if (endpoint->profile == HSPHFPD_PROFILE_HEADSET) {
                if (endpoint->role == HSPHFPD_ROLE_CLIENT)
                    profile = PA_BLUETOOTH_PROFILE_HSP_HEAD_UNIT;
                else
                    profile = PA_BLUETOOTH_PROFILE_HSP_AUDIO_GATEWAY;
            } else {
                if (endpoint->role == HSPHFPD_ROLE_CLIENT)
                    profile = PA_BLUETOOTH_PROFILE_HFP_HEAD_UNIT;
                else
                    profile = PA_BLUETOOTH_PROFILE_HFP_AUDIO_GATEWAY;
            }

            transport_data = pa_xnew0(struct hsphfpd_transport_data, 1);
            transport_data->hsphfpd = hsphfpd;
            transport_data->sco_fd = -1;

            /* By default we do not know if remote device supports hw volume control
             * So use local softvol filter until remote device announce volume control support */
            transport = pa_bluetooth_transport_new(device, hsphfpd->hsphfpd_service_id, endpoint->path, profile, NULL, 0);
            transport->rx_soft_volume = true;
            transport->tx_soft_volume = true;
            transport->max_rx_volume_gain = 15;
            transport->max_tx_volume_gain = 15;
            transport->acquire = hsphfpd_transport_acquire;
            transport->release = hsphfpd_transport_release;
            transport->destroy = hsphfpd_transport_destroy;
            transport->set_rx_volume_gain = hsphfpd_transport_set_rx_volume_gain;
            transport->set_tx_volume_gain = hsphfpd_transport_set_tx_volume_gain;
            transport->userdata = transport_data;

            pa_bluetooth_transport_put(transport);
        }
    }
}

static void parse_interfaces(pa_bluetooth_hsphfpd *hsphfpd, DBusMessageIter *dict_i) {
    DBusMessageIter element_i;
    const char *path;

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

        if (pa_streq(interface, HSPHFPD_ENDPOINT_INTERFACE)) {
            struct hsphfpd_endpoint *endpoint;

            endpoint = pa_hashmap_get(hsphfpd->endpoints, path);
            if (!endpoint) {
                endpoint = pa_xnew0(struct hsphfpd_endpoint, 1);
                endpoint->path = pa_xstrdup(path);
                pa_hashmap_put(hsphfpd->endpoints, endpoint->path, endpoint);
                pa_log_debug("Found endpoint %s", path);
            }

            parse_endpoint_properties(hsphfpd, endpoint, &iface_i);
        } else
            pa_log_debug("Unknown interface %s found, skipping", interface);

        dbus_message_iter_next(&element_i);
    }
}

static void hsphfpd_get_endpoints_reply(DBusPendingCall *pending, void *userdata) {
    pa_dbus_pending *p;
    pa_bluetooth_hsphfpd *hsphfpd;
    DBusMessage *r;
    DBusMessageIter arg_i, element_i;

    pa_assert(pending);
    pa_assert_se(p = userdata);
    pa_assert_se(hsphfpd = p->context_data);
    pa_assert_se(r = dbus_pending_call_steal_reply(pending));

    if (dbus_message_get_type(r) == DBUS_MESSAGE_TYPE_ERROR) {
        pa_log_error("GetManagedObjects() failed: %s: %s", dbus_message_get_error_name(r), pa_dbus_get_error_message(r));
        goto finish;
    }

    if (!pa_safe_streq(dbus_message_get_sender(r), hsphfpd->hsphfpd_service_id)) {
        pa_log_error("Reply for GetManagedObjects() from invalid sender");
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

        parse_interfaces(hsphfpd, &dict_i);

        dbus_message_iter_next(&element_i);
    }

    hsphfpd->endpoints_listed = true;

finish:
    dbus_message_unref(r);

    PA_LLIST_REMOVE(pa_dbus_pending, hsphfpd->pending, p);
    pa_dbus_pending_free(p);
}

static void hsphfpd_get_endpoints(pa_bluetooth_hsphfpd *hsphfpd) {
    DBusMessage *m;

    pa_assert(hsphfpd);

    pa_assert_se(m = dbus_message_new_method_call(HSPHFPD_SERVICE, "/", DBUS_INTERFACE_OBJECTMANAGER, "GetManagedObjects"));
    send_and_add_to_pending(hsphfpd, m, hsphfpd_get_endpoints_reply, NULL);
}

static void hsphfpd_register_application_reply(DBusPendingCall *pending, void *userdata) {
    DBusMessage *r;
    pa_dbus_pending *p;
    pa_bluetooth_hsphfpd *hsphfpd;

    pa_assert(pending);
    pa_assert_se(p = userdata);
    pa_assert_se(hsphfpd = p->context_data);
    pa_assert_se(r = dbus_pending_call_steal_reply(pending));

    if (dbus_message_get_type(r) == DBUS_MESSAGE_TYPE_ERROR) {
        pa_log_warn(HSPHFPD_APPLICATION_MANAGER_INTERFACE ".RegisterApplication() failed: %s: %s",
                    dbus_message_get_error_name(r), pa_dbus_get_error_message(r));
        if (dbus_message_is_error(r, DBUS_ERROR_SERVICE_UNKNOWN)) {
            pa_log_warn("hsphfpd daemon is not running!");
            pa_log_warn("It is needed for HSP and HFP profile support");
            if (!hsphfpd->legacy_hsp)
                hsphfpd->legacy_hsp = pa_bluetooth_legacy_hsp_register(hsphfpd->core, hsphfpd->discovery);
        }
        goto finish;
    }

    pa_log_info("hsphfpd is now running and pulseaudio was registered");

    hsphfpd->hsphfpd_service_id = pa_xstrdup(dbus_message_get_sender(r));

    hsphfpd_get_endpoints(hsphfpd);

finish:
    dbus_message_unref(r);

    PA_LLIST_REMOVE(pa_dbus_pending, hsphfpd->pending, p);
    pa_dbus_pending_free(p);
}

static void hsphfpd_register_application(pa_bluetooth_hsphfpd *hsphfpd) {
    DBusMessage *m;
    const char *path = APPLICATION_OBJECT_MANAGER_PATH;

    pa_assert(hsphfpd);

    pa_assert_se(m = dbus_message_new_method_call(HSPHFPD_SERVICE, "/", HSPHFPD_APPLICATION_MANAGER_INTERFACE, "RegisterApplication"));
    pa_assert_se(dbus_message_append_args(m, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID));

    send_and_add_to_pending(hsphfpd, m, hsphfpd_register_application_reply, NULL);
}

static void hsphfpd_unregister_application(pa_bluetooth_hsphfpd *hsphfpd) {
    DBusMessage *m;
    const char *path = APPLICATION_OBJECT_MANAGER_PATH;

    pa_assert(hsphfpd);
    pa_assert(hsphfpd->connection);

    pa_assert_se(m = dbus_message_new_method_call(HSPHFPD_SERVICE, "/", HSPHFPD_APPLICATION_MANAGER_INTERFACE, "UnregisterApplication"));
    pa_assert_se(dbus_message_append_args(m, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID));
    pa_assert_se(dbus_connection_send(pa_dbus_connection_get(hsphfpd->connection), m, NULL));

    pa_xfree(hsphfpd->hsphfpd_service_id);
    hsphfpd->hsphfpd_service_id = NULL;
    hsphfpd->endpoints_listed = false;
    pa_hashmap_remove_all(hsphfpd->endpoints);
}

static DBusMessage *hsphfpd_new_connection(pa_bluetooth_hsphfpd *hsphfpd, DBusMessage *m) {
    const char *agent_path;
    const char *transport_path;
    const char *endpoint_path = NULL;
    const char *air_codec = NULL;
    enum hsphfpd_volume_control rx_volume_control = 0;
    enum hsphfpd_volume_control tx_volume_control = 0;
    uint16_t rx_volume_gain = -1;
    uint16_t tx_volume_gain = -1;
    uint16_t mtu = 0;
    const char *sender;
    pa_bluetooth_transport *transport;
    struct hsphfpd_endpoint *endpoint;
    struct hsphfpd_transport_data *transport_data;
    int sco_fd;
    DBusMessage *r;
    DBusMessageIter arg_i;

    if (!dbus_message_iter_init(m, &arg_i) || !pa_streq(dbus_message_get_signature(m), "oha{sv}")) {
        pa_log_error("Invalid signature for method NewConnection()");
        return NULL;
    }

    agent_path = dbus_message_get_path(m);
    if (!pa_streq(agent_path, AUDIO_AGENT_ENDPOINT_PCM_S16LE_8KHZ)) {
        pa_log_error("Invalid handler for method NewConnection()");
        return NULL;
    }

    pa_assert(dbus_message_iter_get_arg_type(&arg_i) == DBUS_TYPE_OBJECT_PATH);
    dbus_message_iter_get_basic(&arg_i, &transport_path);

    pa_assert_se(dbus_message_iter_next(&arg_i));

    pa_assert(dbus_message_iter_get_arg_type(&arg_i) == DBUS_TYPE_UNIX_FD);
    dbus_message_iter_get_basic(&arg_i, &sco_fd);

    pa_log_debug("NewConnection path=%s, sco_fd=%d", transport_path, sco_fd);

    sender = dbus_message_get_sender(m);
    if (!pa_safe_streq(sender, hsphfpd->hsphfpd_service_id)) {
        close(sco_fd);
        pa_log_error("Sender '%s' is not authorized", sender);
        pa_assert_se(r = dbus_message_new_error_printf(m, "org.hsphfpd.Error.Rejected", "Sender '%s' is not authorized", sender));
        return r;
    }

    pa_assert_se(dbus_message_iter_next(&arg_i));
    pa_assert(dbus_message_iter_get_arg_type(&arg_i) == DBUS_TYPE_ARRAY);
    parse_transport_properties_values(hsphfpd, transport_path, &arg_i, &endpoint_path, &air_codec, &rx_volume_control, &tx_volume_control, &rx_volume_gain, &tx_volume_gain, &mtu);

    if (!endpoint_path) {
        close(sco_fd);
        pa_log_error("Endpoint property was not specified");
        pa_assert_se(r = dbus_message_new_error(m, "org.hsphfpd.Error.Rejected", "Endpoint property was not specified"));
        return r;
    }

    if (!air_codec) {
        close(sco_fd);
        pa_log_error("AirCodec property was not specified");
        pa_assert_se(r = dbus_message_new_error(m, "org.hsphfpd.Error.Rejected", "AirCodec property was not specified"));
        return r;
    }

    if (!rx_volume_control) {
        close(sco_fd);
        pa_log_error("RxVolumeControl property was not specified");
        pa_assert_se(r = dbus_message_new_error(m, "org.hsphfpd.Error.Rejected", "RxVolumeControl property was not specified"));
        return r;
    }

    if (!tx_volume_control) {
        close(sco_fd);
        pa_log_error("TxVolumeControl property was not specified");
        pa_assert_se(r = dbus_message_new_error(m, "org.hsphfpd.Error.Rejected", "TxVolumeControl property was not specified"));
        return r;
    }

    if (rx_volume_control != HSPHFPD_VOLUME_CONTROL_NONE) {
        if (rx_volume_gain == (uint16_t)-1) {
            close(sco_fd);
            pa_log_error("RxVolumeGain property was not specified, but VolumeControl is not none");
            pa_assert_se(r = dbus_message_new_error(m, "org.hsphfpd.Error.Rejected", "RxVolumeGain property was not specified, but VolumeControl is not none"));
            return r;
        }
    } else {
        rx_volume_gain = 15; /* No volume control, so set maximal value */
    }

    if (tx_volume_control != HSPHFPD_VOLUME_CONTROL_NONE) {
        if (tx_volume_gain == (uint16_t)-1) {
            close(sco_fd);
            pa_log_error("TxVolumeGain property was not specified, but VolumeControl is not none");
            pa_assert_se(r = dbus_message_new_error(m, "org.hsphfpd.Error.Rejected", "TxVolumeGain property was not specified, but VolumeControl is not none"));
            return r;
        }
    } else {
        tx_volume_gain = 15; /* No volume control, so set maximal value */
    }

    if (!mtu) {
        close(sco_fd);
        pa_log_error("MTU property was not specified");
        pa_assert_se(r = dbus_message_new_error(m, "org.hsphfpd.Error.Rejected", "MTU property was not specified"));
        return r;
    }

    endpoint = pa_hashmap_get(hsphfpd->endpoints, endpoint_path);
    if (!endpoint) {
        close(sco_fd);
        pa_log_error("Endpoint %s does not exist", endpoint_path);
        pa_assert_se(r = dbus_message_new_error_printf(m, "org.hsphfpd.Error.Rejected", "Endpoint %s does not exist", endpoint_path));
        return r;
    }

    if (!endpoint->valid) {
        close(sco_fd);
        pa_log_error("Endpoint %s is not valid", endpoint_path);
        pa_assert_se(r = dbus_message_new_error_printf(m, "org.hsphfpd.Error.Rejected", "Endpoint %s is not valid", endpoint_path));
        return r;
    }

    transport = pa_bluetooth_transport_get(hsphfpd->discovery, endpoint_path);
    if (!transport) {
        close(sco_fd);
        pa_log_error("Endpoint %s is not connected", endpoint_path);
        pa_assert_se(r = dbus_message_new_error_printf(m, "org.hsphfpd.Error.Rejected", "Endpoint %s is not connected", endpoint_path));
        return r;
    }

    transport_data = transport->userdata;
    if (transport_data->sco_fd >= 0) {
        close(sco_fd);
        pa_log_error("Endpoint %s has already active transport", endpoint_path);
        pa_assert_se(r = dbus_message_new_error_printf(m, "org.hsphfpd.Error.Rejected", "Endpoint %s has already active transport", endpoint_path));
        return r;
    }

    transport->rx_soft_volume = (rx_volume_control != HSPHFPD_VOLUME_CONTROL_REMOTE);
    transport->tx_soft_volume = (tx_volume_control != HSPHFPD_VOLUME_CONTROL_REMOTE);
    transport->rx_volume_gain = rx_volume_gain;
    transport->tx_volume_gain = tx_volume_gain;

    pa_hook_fire(pa_bluetooth_discovery_hook(hsphfpd->discovery, PA_BLUETOOTH_HOOK_TRANSPORT_RX_VOLUME_GAIN_CHANGED), transport);
    pa_hook_fire(pa_bluetooth_discovery_hook(hsphfpd->discovery, PA_BLUETOOTH_HOOK_TRANSPORT_TX_VOLUME_GAIN_CHANGED), transport);

    transport_data->transport_path = pa_xstrdup(transport_path);
    transport_data->agent_codec = pa_xstrdup("PCM_s16le_8kHz");
    transport_data->air_codec = pa_xstrdup(air_codec);
    transport_data->rx_volume_control = rx_volume_control;
    transport_data->tx_volume_control = tx_volume_control;
    transport_data->mtu = mtu;
    transport_data->sco_fd = sco_fd;

    pa_bluetooth_transport_set_state(transport, PA_BLUETOOTH_TRANSPORT_STATE_PLAYING);

    pa_log_debug("Transport %s with agent codec %s and air codec %s is active for profile %s on endpoint %s", transport_data->transport_path, transport_data->agent_codec, transport_data->air_codec, pa_bluetooth_profile_to_string(transport->profile), endpoint_path);

    pa_assert_se(r = dbus_message_new_method_return(m));
    return r;
}

static DBusHandlerResult filter_cb(DBusConnection *bus, DBusMessage *m, void *data) {
    const char *sender;
    DBusError err;
    pa_bluetooth_hsphfpd *hsphfpd = data;

    pa_assert(bus);
    pa_assert(m);
    pa_assert(hsphfpd);

    dbus_error_init(&err);

    sender = dbus_message_get_sender(m);

    if (pa_streq(sender, DBUS_SERVICE_DBUS)) {

        if (dbus_message_is_signal(m, DBUS_SERVICE_DBUS, "NameOwnerChanged")) {
            const char *name, *old_owner, *new_owner;

            if (!dbus_message_get_args(m, &err,
                                       DBUS_TYPE_STRING, &name,
                                       DBUS_TYPE_STRING, &old_owner,
                                       DBUS_TYPE_STRING, &new_owner,
                                       DBUS_TYPE_INVALID)
                  || dbus_error_is_set(&err)) {
                pa_log_error("Failed to parse NameOwnerChanged: %s", err.message);
                goto finish;
            }

            if (pa_streq(name, HSPHFPD_SERVICE)) {
                if (old_owner && *old_owner) {
                    pa_log_debug("hsphfpd disappeared");
                    pa_xfree(hsphfpd->hsphfpd_service_id);
                    hsphfpd->hsphfpd_service_id = NULL;
                    hsphfpd->endpoints_listed = false;
                    pa_hashmap_remove_all(hsphfpd->endpoints);
                    if (!hsphfpd->legacy_hsp)
                        hsphfpd->legacy_hsp = pa_bluetooth_legacy_hsp_register(hsphfpd->core, hsphfpd->discovery);
                }

                if (new_owner && *new_owner) {
                    pa_log_debug("hsphfpd appeared");
                    if (hsphfpd->legacy_hsp) {
                        pa_bluetooth_legacy_hsp_unregister(hsphfpd->legacy_hsp);
                        hsphfpd->legacy_hsp = NULL;
                    }
                    hsphfpd_register_application(hsphfpd);
                }
            }
        }

    } else if (pa_safe_streq(sender, hsphfpd->hsphfpd_service_id)) {

        DBusMessageIter arg_i;

        if (dbus_message_is_signal(m, DBUS_INTERFACE_OBJECTMANAGER, "InterfacesAdded")) {
            if (!hsphfpd->endpoints_listed)
                goto finish;

            if (!dbus_message_iter_init(m, &arg_i) || !pa_streq(dbus_message_get_signature(m), "oa{sa{sv}}")) {
                pa_log_error("Invalid signature found in InterfacesAdded");
                goto finish;
            }

            parse_interfaces(hsphfpd, &arg_i);
        } else if (dbus_message_is_signal(m, DBUS_INTERFACE_OBJECTMANAGER, "InterfacesRemoved")) {
            const char *path;
            DBusMessageIter element_i;

            if (!hsphfpd->endpoints_listed)
                goto finish;

            if (!dbus_message_iter_init(m, &arg_i) || !pa_streq(dbus_message_get_signature(m), "oas")) {
                pa_log_error("Invalid signature found in InterfacesRemoved");
                goto finish;
            }

            dbus_message_iter_get_basic(&arg_i, &path);

            pa_assert_se(dbus_message_iter_next(&arg_i));
            pa_assert(dbus_message_iter_get_arg_type(&arg_i) == DBUS_TYPE_ARRAY);

            dbus_message_iter_recurse(&arg_i, &element_i);

            while (dbus_message_iter_get_arg_type(&element_i) == DBUS_TYPE_STRING) {
                const char *iface;

                dbus_message_iter_get_basic(&element_i, &iface);

                if (pa_streq(iface, HSPHFPD_ENDPOINT_INTERFACE)) {
                    pa_bluetooth_transport *transport = pa_bluetooth_transport_get(hsphfpd->discovery, path);
                    if (transport)
                        pa_bluetooth_transport_free(transport);
                    pa_log_debug("Remove endpoint %s", path);
                    pa_hashmap_remove(hsphfpd->endpoints, path);
                }

                dbus_message_iter_next(&element_i);
            }
        } else if (dbus_message_is_signal(m, DBUS_INTERFACE_PROPERTIES, "PropertiesChanged")) {
            const char *iface;
            const char *path;

            if (!hsphfpd->endpoints_listed)
                goto finish;

            if (!dbus_message_iter_init(m, &arg_i) || !pa_streq(dbus_message_get_signature(m), "sa{sv}as")) {
                pa_log_error("Invalid signature found in PropertiesChanged");
                goto finish;
            }

            dbus_message_iter_get_basic(&arg_i, &iface);

            pa_assert_se(dbus_message_iter_next(&arg_i));
            pa_assert(dbus_message_iter_get_arg_type(&arg_i) == DBUS_TYPE_ARRAY);

            path = dbus_message_get_path(m);

            if (pa_streq(iface, HSPHFPD_ENDPOINT_INTERFACE)) {
                struct hsphfpd_endpoint *endpoint = pa_hashmap_get(hsphfpd->endpoints, path);
                if (!endpoint) {
                    pa_log_warn("Properties changed on unknown endpoint %s", path);
                    goto finish;
                }
                pa_log_debug("Properties changed on endpoint %s", path);
                parse_endpoint_properties(hsphfpd, endpoint, &arg_i);
            } else if (pa_streq(iface, HSPHFPD_AUDIO_TRANSPORT_INTERFACE)) {
                pa_hashmap *transports = pa_bluetooth_transport_get_all(hsphfpd->discovery);
                pa_bluetooth_transport *transport;
                struct hsphfpd_transport_data *transport_data;
                void *state;

                /* Find pa_bluetooth_transport which belongs to hsphfpd transport path
                 * pa_hashmap_get() search transports by hsphfpd endpoint path and
                 * not by hsphfpd transport path, so do search routine manually */
                PA_HASHMAP_FOREACH(transport, transports, state) {
                    if (!transport->owner || !pa_safe_streq(transport->owner, hsphfpd->hsphfpd_service_id))
                        continue;
                    transport_data = transport->userdata;
                    if (transport_data->sco_fd <= 0 || !pa_safe_streq(transport_data->transport_path, path))
                        continue;
                    break;
                }

                if (!transport) {
                    pa_log_warn("Properties changed on unknown transport %s", path);
                    goto finish;
                }

                pa_log_debug("Properties changed on transport %s", path);
                parse_transport_properties(transport, &arg_i);
            }
        }

    }

finish:
    dbus_error_free(&err);
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void append_audio_agent_object(DBusMessageIter *iter, const char *endpoint, const char *agent_codec) {
    const char *interface_name = HSPHFPD_AUDIO_AGENT_INTERFACE;
    DBusMessageIter object, array, entry, dict;

    dbus_message_iter_open_container(iter, DBUS_TYPE_DICT_ENTRY, NULL, &object);
    pa_assert_se(dbus_message_iter_append_basic(&object, DBUS_TYPE_OBJECT_PATH, &endpoint));

    dbus_message_iter_open_container(&object, DBUS_TYPE_ARRAY, "{sa{sv}}", &array);

    dbus_message_iter_open_container(&array, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
    pa_assert_se(dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &interface_name));

    dbus_message_iter_open_container(&entry, DBUS_TYPE_ARRAY, "{sv}", &dict);

    pa_dbus_append_basic_variant_dict_entry(&dict, "AgentCodec", DBUS_TYPE_STRING, &agent_codec);

    dbus_message_iter_close_container(&entry, &dict);
    dbus_message_iter_close_container(&array, &entry);
    dbus_message_iter_close_container(&object, &array);
    dbus_message_iter_close_container(iter, &object);
}

static DBusHandlerResult application_object_manager_handler(DBusConnection *c, DBusMessage *m, void *userdata) {
    struct pa_bluetooth_hsphfpd *hsphfpd = userdata;
    DBusMessage *r;
    const char *path, *interface, *member;

    pa_assert(hsphfpd);

    path = dbus_message_get_path(m);
    interface = dbus_message_get_interface(m);
    member = dbus_message_get_member(m);

    pa_log_debug("dbus: path=%s, interface=%s, member=%s", path, interface, member);

    if (dbus_message_is_method_call(m, DBUS_INTERFACE_INTROSPECTABLE, "Introspect")) {
        const char *xml = APPLICATION_OBJECT_MANAGER_INTROSPECT_XML;

        pa_assert_se(r = dbus_message_new_method_return(m));
        pa_assert_se(dbus_message_append_args(r, DBUS_TYPE_STRING, &xml, DBUS_TYPE_INVALID));
    } else if (dbus_message_is_method_call(m, DBUS_INTERFACE_OBJECTMANAGER, "GetManagedObjects")) {
        DBusMessageIter iter, array;

        pa_assert_se(r = dbus_message_new_method_return(m));

        dbus_message_iter_init_append(r, &iter);
        dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{oa{sa{sv}}}", &array);

        append_audio_agent_object(&array, AUDIO_AGENT_ENDPOINT_PCM_S16LE_8KHZ, "PCM_s16le_8kHz");

        dbus_message_iter_close_container(&iter, &array);
    } else
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    pa_assert_se(dbus_connection_send(pa_dbus_connection_get(hsphfpd->connection), r, NULL));
    dbus_message_unref(r);

    return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult audio_agent_endpoint_pcm_s16le_8khz_handler(DBusConnection *c, DBusMessage *m, void *userdata) {
    pa_bluetooth_hsphfpd *hsphfpd = userdata;
    DBusMessage *r = NULL;

    pa_assert(hsphfpd);

    pa_log_debug("dbus: path=%s, interface=%s, member=%s", dbus_message_get_path(m), dbus_message_get_interface(m), dbus_message_get_member(m));

    if (!pa_streq(dbus_message_get_path(m), AUDIO_AGENT_ENDPOINT_PCM_S16LE_8KHZ))
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    if (dbus_message_is_method_call(m, DBUS_INTERFACE_INTROSPECTABLE, "Introspect")) {
        const char *xml = AUDIO_AGENT_ENDPOINT_INTROSPECT_XML;

        pa_assert_se(r = dbus_message_new_method_return(m));
        pa_assert_se(dbus_message_append_args(r, DBUS_TYPE_STRING, &xml, DBUS_TYPE_INVALID));
    } else if (dbus_message_is_method_call(m, DBUS_INTERFACE_PROPERTIES, "Get")) {
        const char *interface;
        const char *property;
        DBusError error;

        if (!pa_streq(dbus_message_get_signature(m), "ss")) {
            pa_log_error("Invalid signature for method Get()");
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }

        dbus_error_init(&error);
        if (!dbus_message_get_args(m, &error, DBUS_TYPE_STRING, &interface, DBUS_TYPE_STRING, &property, DBUS_TYPE_INVALID) || dbus_error_is_set(&error)) {
            dbus_error_free(&error);
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }
        dbus_error_free(&error);

        if (!pa_streq(interface, HSPHFPD_AUDIO_AGENT_INTERFACE))
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

        if (pa_streq(property, "AgentCodec")) {
            const char *agent_codec = "PCM_s16le_8kHz";
            pa_assert_se(r = dbus_message_new_method_return(m));
            pa_assert_se(dbus_message_append_args(r, DBUS_TYPE_STRING, &agent_codec, DBUS_TYPE_INVALID));
        } else
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    } else if (dbus_message_is_method_call(m, DBUS_INTERFACE_PROPERTIES, "GetAll")) {
        DBusError error;
        DBusMessageIter iter, dict;
        const char *interface;
        const char *agent_codec = "PCM_s16le_8kHz";

        if (!pa_streq(dbus_message_get_signature(m), "s")) {
            pa_log_error("Invalid signature for method GetAll()");
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }

        dbus_error_init(&error);
        if (!dbus_message_get_args(m, &error, DBUS_TYPE_STRING, &interface, DBUS_TYPE_INVALID) || dbus_error_is_set(&error)) {
            dbus_error_free(&error);
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }
        dbus_error_free(&error);

        if (!pa_streq(interface, HSPHFPD_AUDIO_AGENT_INTERFACE))
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

        pa_assert_se(r = dbus_message_new_method_return(m));
        dbus_message_iter_init_append(r, &iter);
        pa_assert_se(dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &dict));
        pa_dbus_append_basic_variant_dict_entry(&dict, "AgentCodec", DBUS_TYPE_STRING, &agent_codec);
        pa_assert_se(dbus_message_iter_close_container(&iter, &dict));
    } else if (dbus_message_is_method_call(m, HSPHFPD_AUDIO_AGENT_INTERFACE, "NewConnection")) {
        r = hsphfpd_new_connection(hsphfpd, m);
        if (!r)
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    } else
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    pa_assert(r);
    pa_assert_se(dbus_connection_send(pa_dbus_connection_get(hsphfpd->connection), r, NULL));
    dbus_message_unref(r);
    return DBUS_HANDLER_RESULT_HANDLED;
}

pa_bluetooth_hsphfpd *pa_bluetooth_hsphfpd_new(pa_core *core, pa_bluetooth_discovery *discovery) {
    pa_bluetooth_hsphfpd *hsphfpd;
    DBusError err;
    static const DBusObjectPathVTable vtable_application_object_manager = {
        .message_function = application_object_manager_handler,
    };
    static const DBusObjectPathVTable vtable_audio_agent_endpoint_pcm_s16le_8khz = {
        .message_function = audio_agent_endpoint_pcm_s16le_8khz_handler,
    };

    pa_assert(core);
    pa_assert(discovery);

    hsphfpd = pa_xnew0(pa_bluetooth_hsphfpd, 1);
    hsphfpd->core = core;
    hsphfpd->discovery = discovery;
    hsphfpd->endpoints_listed = false;
    hsphfpd->endpoints = pa_hashmap_new_full(pa_idxset_string_hash_func, pa_idxset_string_compare_func, NULL, (pa_free_cb_t) hsphfpd_endpoint_free);

    dbus_error_init(&err);

    if (!(hsphfpd->connection = pa_dbus_bus_get(core, DBUS_BUS_SYSTEM, &err))) {
        pa_log_error("Failed to get D-Bus connection: %s", err.message);
        dbus_error_free(&err);
        pa_xfree(hsphfpd);
        return NULL;
    }

    if (!dbus_connection_add_filter(pa_dbus_connection_get(hsphfpd->connection), filter_cb, hsphfpd, NULL)) {
        pa_log_error("Failed to add filter function");
        pa_dbus_connection_unref(hsphfpd->connection);
        pa_xfree(hsphfpd);
        return NULL;
    }

    if (pa_dbus_add_matches(pa_dbus_connection_get(hsphfpd->connection), &err,
            "type='signal',sender='" DBUS_SERVICE_DBUS "',interface='" DBUS_SERVICE_DBUS "',member='NameOwnerChanged',arg0='" HSPHFPD_SERVICE "'",
            "type='signal',interface='" DBUS_INTERFACE_OBJECTMANAGER "',member='InterfacesAdded'",
            "type='signal',interface='" DBUS_INTERFACE_OBJECTMANAGER "',member='InterfacesRemoved'",
            "type='signal',interface='" DBUS_INTERFACE_PROPERTIES "',member='PropertiesChanged',arg0='" HSPHFPD_ENDPOINT_INTERFACE "'",
            "type='signal',interface='" DBUS_INTERFACE_PROPERTIES "',member='PropertiesChanged',arg0='" HSPHFPD_AUDIO_TRANSPORT_INTERFACE "'",
            NULL) < 0) {
        pa_log_error("Failed to add hsphfpd D-Bus matches: %s", err.message);
        dbus_connection_remove_filter(pa_dbus_connection_get(hsphfpd->connection), filter_cb, hsphfpd);
        pa_dbus_connection_unref(hsphfpd->connection);
        pa_xfree(hsphfpd);
        return NULL;
    }

    pa_assert_se(dbus_connection_register_object_path(pa_dbus_connection_get(hsphfpd->connection), APPLICATION_OBJECT_MANAGER_PATH, &vtable_application_object_manager, hsphfpd));
    pa_assert_se(dbus_connection_register_object_path(pa_dbus_connection_get(hsphfpd->connection), AUDIO_AGENT_ENDPOINT_PCM_S16LE_8KHZ, &vtable_audio_agent_endpoint_pcm_s16le_8khz, hsphfpd));

    hsphfpd_register_application(hsphfpd);

    return hsphfpd;
}

void pa_bluetooth_hsphfpd_free(pa_bluetooth_hsphfpd *hsphfpd) {
    pa_assert(hsphfpd);

    pa_dbus_free_pending_list(&hsphfpd->pending);

    hsphfpd_unregister_application(hsphfpd);

    dbus_connection_unregister_object_path(pa_dbus_connection_get(hsphfpd->connection), APPLICATION_OBJECT_MANAGER_PATH);
    dbus_connection_unregister_object_path(pa_dbus_connection_get(hsphfpd->connection), AUDIO_AGENT_ENDPOINT_PCM_S16LE_8KHZ);

    pa_dbus_remove_matches(pa_dbus_connection_get(hsphfpd->connection),
            "type='signal',sender='" DBUS_SERVICE_DBUS "',interface='" DBUS_SERVICE_DBUS "',member='NameOwnerChanged',arg0='" HSPHFPD_SERVICE "'",
            "type='signal',interface='" DBUS_INTERFACE_OBJECTMANAGER "',member='InterfacesAdded'",
            "type='signal',interface='" DBUS_INTERFACE_OBJECTMANAGER "',member='InterfacesRemoved'",
            "type='signal',interface='" DBUS_INTERFACE_PROPERTIES "',member='PropertiesChanged',arg0='" HSPHFPD_ENDPOINT_INTERFACE "'",
            "type='signal',interface='" DBUS_INTERFACE_PROPERTIES "',member='PropertiesChanged',arg0='" HSPHFPD_AUDIO_TRANSPORT_INTERFACE "'",
            NULL);

    dbus_connection_remove_filter(pa_dbus_connection_get(hsphfpd->connection), filter_cb, hsphfpd);

    pa_dbus_connection_unref(hsphfpd->connection);

    pa_hashmap_free(hsphfpd->endpoints);

    if (hsphfpd->legacy_hsp)
        pa_bluetooth_legacy_hsp_unregister(hsphfpd->legacy_hsp);

    pa_xfree(hsphfpd);
}
