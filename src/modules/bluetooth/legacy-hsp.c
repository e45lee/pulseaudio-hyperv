/***
  This file is part of PulseAudio.

  Copyright 2014 Wim Taymans <wim.taymans at gmail.com>

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

#include <pulsecore/shared.h>
#include <pulsecore/core-error.h>
#include <pulsecore/core-util.h>
#include <pulsecore/dbus-shared.h>
#include <pulsecore/log.h>

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sco.h>

#include "bluez5-util.h"
#include "legacy-hsp.h"

struct pa_bluetooth_legacy_hsp {
  pa_core *core;
  pa_dbus_connection *connection;
  pa_bluetooth_discovery *discovery;
  char *service_id;

  PA_LLIST_HEAD(pa_dbus_pending, pending);
};

struct transport_data {
    int rfcomm_fd;
    pa_io_event *rfcomm_io;
    int sco_fd;
    pa_io_event *sco_connect_io;
    pa_mainloop_api *mainloop;
};

#define BLUEZ_SERVICE "org.bluez"
#define BLUEZ_MEDIA_TRANSPORT_INTERFACE BLUEZ_SERVICE ".MediaTransport1"

#define BLUEZ_ERROR_NOT_SUPPORTED "org.bluez.Error.NotSupported"

#define BLUEZ_PROFILE_MANAGER_INTERFACE BLUEZ_SERVICE ".ProfileManager1"
#define BLUEZ_PROFILE_INTERFACE BLUEZ_SERVICE ".Profile1"

#define HSP_AG_PROFILE "/Profile/HSPAGProfile"

#define PROFILE_INTROSPECT_XML                                          \
    DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                           \
    "<node>"                                                            \
    " <interface name=\"" BLUEZ_PROFILE_INTERFACE "\">"                 \
    "  <method name=\"Release\">"                                       \
    "  </method>"                                                       \
    "  <method name=\"RequestDisconnection\">"                          \
    "   <arg name=\"device\" direction=\"in\" type=\"o\"/>"             \
    "  </method>"                                                       \
    "  <method name=\"NewConnection\">"                                 \
    "   <arg name=\"device\" direction=\"in\" type=\"o\"/>"             \
    "   <arg name=\"fd\" direction=\"in\" type=\"h\"/>"                 \
    "   <arg name=\"opts\" direction=\"in\" type=\"a{sv}\"/>"           \
    "  </method>"                                                       \
    " </interface>"                                                     \
    " <interface name=\"org.freedesktop.DBus.Introspectable\">"         \
    "  <method name=\"Introspect\">"                                    \
    "   <arg name=\"data\" type=\"s\" direction=\"out\"/>"              \
    "  </method>"                                                       \
    " </interface>"                                                     \
    "</node>"

static pa_dbus_pending* send_and_add_to_pending(pa_bluetooth_legacy_hsp *hsp, DBusMessage *m,
        DBusPendingCallNotifyFunction func, void *call_data) {

    pa_dbus_pending *p;
    DBusPendingCall *call;

    pa_assert(hsp);
    pa_assert(m);

    pa_assert_se(dbus_connection_send_with_reply(pa_dbus_connection_get(hsp->connection), m, &call, -1));

    p = pa_dbus_pending_new(pa_dbus_connection_get(hsp->connection), m, call, hsp, call_data);
    PA_LLIST_PREPEND(pa_dbus_pending, hsp->pending, p);
    dbus_pending_call_set_notify(call, func, p, NULL);

    return p;
}

static void sco_connect_callback(pa_mainloop_api *mainloop, pa_io_event *sco_connect_io, int sco_fd, pa_io_event_flags_t events, void *userdata) {
    pa_bluetooth_transport *t = userdata;
    struct transport_data *trd = t->userdata;
    socklen_t len;
    int error;

    trd->mainloop->io_free(trd->sco_connect_io);
    trd->sco_connect_io = NULL;

    if (events & (PA_IO_EVENT_HANGUP|PA_IO_EVENT_ERROR)) {
        error = errno;
        pa_log_error("connect() to %s failed: %s", t->device->address, pa_cstrerror(error));
        goto failed;
    }

    error = 0;
    len = sizeof(error);
    if (getsockopt(trd->sco_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || len != sizeof(error)) {
        error = errno;
        pa_log_error("getsockopt() failed: %s", pa_cstrerror(error));
        goto failed;
    }

    if (error) {
        pa_log_error("connect() to %s failed: %s", t->device->address, pa_cstrerror(error));
        goto failed;
    }

    pa_log_info("connect() to %s successful", t->device->address);
    pa_bluetooth_transport_set_state(t, PA_BLUETOOTH_TRANSPORT_STATE_PLAYING);
    return;

failed:
    close(trd->sco_fd);
    trd->sco_fd = -error;

    /* If transport state is idle switch it to disconnected state and then back to idle state
     * so sinks and sources are properly released and connection attempt is marked as failed,
     * this also trigger profile change to off */
    if (t->state == PA_BLUETOOTH_TRANSPORT_STATE_IDLE) {
        pa_bluetooth_transport_set_state(t, PA_BLUETOOTH_TRANSPORT_STATE_DISCONNECTED);
        pa_bluetooth_transport_set_state(t, PA_BLUETOOTH_TRANSPORT_STATE_IDLE);
    }
}

static int sco_do_connect(pa_bluetooth_transport *t) {
    struct transport_data *trd = t->userdata;
    pa_bluetooth_device *d = t->device;
    struct sockaddr_sco addr;
    socklen_t len;
    int err, i;
    int sock;
    bdaddr_t src;
    bdaddr_t dst;
    const char *src_addr, *dst_addr;

    src_addr = d->adapter->address;
    dst_addr = d->address;

    /* don't use ba2str to avoid -lbluetooth */
    for (i = 5; i >= 0; i--, src_addr += 3)
        src.b[i] = strtol(src_addr, NULL, 16);
    for (i = 5; i >= 0; i--, dst_addr += 3)
        dst.b[i] = strtol(dst_addr, NULL, 16);

    sock = socket(PF_BLUETOOTH, SOCK_SEQPACKET | SOCK_NONBLOCK, BTPROTO_SCO);
    if (sock < 0) {
        pa_log_error("socket(SEQPACKET, SCO) %s", pa_cstrerror(errno));
        return -1;
    }

    len = sizeof(addr);
    memset(&addr, 0, len);
    addr.sco_family = AF_BLUETOOTH;
    bacpy(&addr.sco_bdaddr, &src);

    if (bind(sock, (struct sockaddr *) &addr, len) < 0) {
        pa_log_error("bind(): %s", pa_cstrerror(errno));
        goto fail_close;
    }

    memset(&addr, 0, len);
    addr.sco_family = AF_BLUETOOTH;
    bacpy(&addr.sco_bdaddr, &dst);

    pa_log_info("calling connect() to %s", d->address);
    do {
        err = connect(sock, (struct sockaddr *) &addr, len);
    } while (err < 0 && errno == EINTR);
    if (err < 0 && errno != EINPROGRESS) {
        pa_log_error("connect(): %s", pa_cstrerror(errno));
        goto fail_close;
    }

    trd->sco_fd = sock;
    trd->sco_connect_io = trd->mainloop->io_new(trd->mainloop, trd->sco_fd, PA_IO_EVENT_OUTPUT, sco_connect_callback, t);
    return 0;

fail_close:
    close(sock);
    return -1;
}

static int sco_acquire_cb(pa_bluetooth_transport *t, size_t *imtu, size_t *omtu) {
    struct transport_data *trd = t->userdata;
    int ret;

    if (trd->sco_connect_io)
        return -EAGAIN;

    if (trd->sco_fd < 0) {
        if (trd->sco_fd == -EAGAIN) {
            ret = sco_do_connect(t);
            if (ret == 0)
                ret = -EAGAIN;
        } else {
            ret = trd->sco_fd;
            trd->sco_fd = -EAGAIN;
        }
        return ret;
    }

    /* Legacy HSP profile implementation supports only CVSD air codec with
     * PCM s16le 8kHz local codec which requies 48 bytes length packet size */
    if (imtu) *imtu = 48;
    if (omtu) *omtu = 48;

    return trd->sco_fd;
}

static void sco_release_cb(pa_bluetooth_transport *t) {
    struct transport_data *trd = t->userdata;

    pa_log_info("Transport %s released", t->path);

    shutdown(trd->sco_fd, SHUT_RDWR);
    trd->sco_fd = -EAGAIN;
    /* device will close the SCO socket for us */
}

static void register_profile_reply(DBusPendingCall *pending, void *userdata) {
    DBusMessage *r;
    pa_dbus_pending *p;
    pa_bluetooth_legacy_hsp *hsp;

    pa_assert(pending);
    pa_assert_se(p = userdata);
    pa_assert_se(hsp = p->context_data);
    pa_assert_se(r = dbus_pending_call_steal_reply(pending));

    if (dbus_message_is_error(r, BLUEZ_ERROR_NOT_SUPPORTED)) {
        pa_log_info("Couldn't register HSP profile because it is disabled in BlueZ");
        goto finish;
    }

    if (dbus_message_get_type(r) == DBUS_MESSAGE_TYPE_ERROR) {
        pa_log_error(BLUEZ_PROFILE_MANAGER_INTERFACE ".RegisterProfile() failed: %s: %s", dbus_message_get_error_name(r),
                     pa_dbus_get_error_message(r));
        goto finish;
    }

    hsp->service_id = pa_xstrdup(dbus_message_get_sender(r));

finish:
    dbus_message_unref(r);

    PA_LLIST_REMOVE(pa_dbus_pending, hsp->pending, p);
    pa_dbus_pending_free(p);
}

static void register_profile(pa_bluetooth_legacy_hsp *hsp) {
    DBusMessage *m;
    DBusMessageIter i, d;
    const char *object = HSP_AG_PROFILE;
    const char *uuid = PA_BLUETOOTH_UUID_HSP_AG; /* Remote headset role connects to local audio gateway role */

    pa_log_debug("Registering HSP profile to BlueZ");

    pa_assert_se(m = dbus_message_new_method_call(BLUEZ_SERVICE, "/org/bluez", BLUEZ_PROFILE_MANAGER_INTERFACE, "RegisterProfile"));

    dbus_message_iter_init_append(m, &i);
    pa_assert_se(dbus_message_iter_append_basic(&i, DBUS_TYPE_OBJECT_PATH, &object));
    pa_assert_se(dbus_message_iter_append_basic(&i, DBUS_TYPE_STRING, &uuid));
    dbus_message_iter_open_container(&i, DBUS_TYPE_ARRAY, DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING DBUS_TYPE_STRING_AS_STRING
            DBUS_TYPE_VARIANT_AS_STRING DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &d);
    dbus_message_iter_close_container(&i, &d);

    send_and_add_to_pending(hsp, m, register_profile_reply, NULL);
}

static void unregister_profile(pa_bluetooth_legacy_hsp *hsp) {
    DBusMessage *m;
    const char *object = HSP_AG_PROFILE;
    pa_hashmap *transports;
    pa_bluetooth_transport *t;
    void *state;

    pa_log_debug("Unregistering HSP profile from BlueZ");

    pa_assert_se(m = dbus_message_new_method_call(BLUEZ_SERVICE, "/org/bluez", BLUEZ_PROFILE_MANAGER_INTERFACE, "UnregisterProfile"));
    pa_assert_se(dbus_message_append_args(m, DBUS_TYPE_OBJECT_PATH, &object, DBUS_TYPE_INVALID));
    pa_assert_se(dbus_connection_send(pa_dbus_connection_get(hsp->connection), m, NULL));

    pa_assert_se(transports = pa_bluetooth_transport_get_all(hsp->discovery));
    PA_HASHMAP_FOREACH(t, transports, state) {
        /* owner for legacy HSP and A2DP is same bluez, so we need to check also for provide */
        if (!t->owner || !pa_safe_streq(t->owner, hsp->service_id) || t->profile != PA_BLUETOOTH_PROFILE_HSP_HEAD_UNIT)
            continue;
        /* Function pa_bluetooth_transport_free() is safe as it just calls pa_hashmap_remove()
         * on current iterator entry and this is by pulseaudio hashmap structure allowed */
        pa_bluetooth_transport_free(t);
    }
}

static void rfcomm_io_callback(pa_mainloop_api *io, pa_io_event *e, int fd, pa_io_event_flags_t events, void *userdata) {
    pa_bluetooth_transport *t = userdata;

    pa_assert(io);
    pa_assert(t);

    if (events & (PA_IO_EVENT_HANGUP|PA_IO_EVENT_ERROR)) {
        pa_log_info("Lost RFCOMM connection.");
        goto fail;
    }

    if (events & PA_IO_EVENT_INPUT) {
        char buf[512];
        ssize_t len;
        int gain;
        bool success;

        len = pa_read(fd, buf, sizeof(buf)-1, NULL);
        if (len < 0) {
            pa_log_error("RFCOMM read error: %s", pa_cstrerror(errno));
            goto fail;
        }
        buf[len] = 0;
        pa_log_debug("RFCOMM << %s", buf);

        /* There are only four HSP AT commands:
         * AT+VGS=value: value between 0 and 15, sent by the HS to AG to set the speaker gain.
         * +VGS=value is sent by AG to HS as a response to an AT+VGS command or when the gain
         * is changed on the AG side. Some buggy headsets sent it instead of AT+VGS.
         * AT+VGM=value: value between 0 and 15, sent by the HS to AG to set the microphone gain.
         * +VGM=value is sent by AG to HS as a response to an AT+VGM command or when the gain
         * is changed on the AG side. Some buggy headsets sent it instead of AT+VGM.
         * AT+CKPD=200: Sent by HS when headset button is pressed.
         * RING: Sent by AG to HS to notify of an incoming call. It can safely be ignored because
         * it does not expect a reply.
         * We support only local AG role and only microphone and speaker gain commands.
         * Leading space in sscanf format matches any amount of whitespace characters including none */
        if (sscanf(buf, " AT+VGS=%d", &gain) == 1 || sscanf(buf, " +VGS=%d", &gain) == 1) {
            t->tx_volume_gain = gain;
            pa_hook_fire(pa_bluetooth_discovery_hook(t->device->discovery, PA_BLUETOOTH_HOOK_TRANSPORT_TX_VOLUME_GAIN_CHANGED), t);
            success = true;
        } else if (sscanf(buf, " AT+VGM=%d", &gain) == 1 || sscanf(buf, " +VGM=%d", &gain) == 1) {
            t->rx_volume_gain = gain;
            pa_hook_fire(pa_bluetooth_discovery_hook(t->device->discovery, PA_BLUETOOTH_HOOK_TRANSPORT_RX_VOLUME_GAIN_CHANGED), t);
            success = true;
        } else {
            success = false;
        }

        if (success) {
            pa_log_debug("RFCOMM >> OK");
            len = write(fd, "\r\nOK\r\n", 6);
        } else if (!strstr(buf, "ERROR")) {
            /* Do not reply to ERROR command as some buggy headsets sent it for ERROR response */
            pa_log_debug("RFCOMM >> ERROR");
            len = write(fd, "\r\nERROR\r\n", 9);
        } else {
            len = 0;
        }

        /* we ignore any errors, it's not critical and real errors should
         * be caught with the HANGUP and ERROR events handled above */
        if (len < 0)
            pa_log_error("RFCOMM write error: %s", pa_cstrerror(errno));
    }

    return;

fail:
    pa_bluetooth_transport_free(t);
}

static void transport_destroy(pa_bluetooth_transport *t) {
    struct transport_data *trd = t->userdata;

    if (trd->sco_connect_io) {
        trd->mainloop->io_free(trd->sco_connect_io);
        shutdown(trd->sco_fd, SHUT_RDWR);
        close(trd->sco_fd);
    }

    trd->mainloop->io_free(trd->rfcomm_io);
    shutdown(trd->rfcomm_fd, SHUT_RDWR);
    close (trd->rfcomm_fd);

    pa_xfree(trd);
}

static void set_tx_volume_gain(pa_bluetooth_transport *t, uint16_t gain) {
    struct transport_data *trd = t->userdata;
    char buf[512];
    ssize_t len, written;

    if (t->tx_volume_gain == gain)
      return;

    t->tx_volume_gain = gain;

    len = sprintf(buf, "\r\n+VGS=%d\r\n", gain);
    pa_log_debug("RFCOMM >> +VGS=%d", gain);

    written = write(trd->rfcomm_fd, buf, len);

    if (written != len)
        pa_log_error("RFCOMM write error: %s", pa_cstrerror(errno));
}

static void set_rx_volume_gain(pa_bluetooth_transport *t, uint16_t gain) {
    struct transport_data *trd = t->userdata;
    char buf[512];
    ssize_t len, written;

    if (t->rx_volume_gain == gain)
      return;

    t->rx_volume_gain = gain;

    len = sprintf(buf, "\r\n+VGM=%d\r\n", gain);
    pa_log_debug("RFCOMM >> +VGM=%d", gain);

    written = write (trd->rfcomm_fd, buf, len);

    if (written != len)
        pa_log_error("RFCOMM write error: %s", pa_cstrerror(errno));
}

static DBusMessage *profile_new_connection(DBusConnection *conn, DBusMessage *m, void *userdata) {
    pa_bluetooth_legacy_hsp *hsp = userdata;
    pa_bluetooth_device *d;
    pa_bluetooth_transport *t;
    DBusMessage *r;
    int fd;
    const char *sender, *path, PA_UNUSED *handler;
    DBusMessageIter arg_i;
    struct transport_data *trd;

    if (!dbus_message_iter_init(m, &arg_i) || !pa_streq(dbus_message_get_signature(m), "oha{sv}")) {
        pa_log_error("Invalid signature found in NewConnection");
        pa_assert_se(r = dbus_message_new_error(m, "org.bluez.Error.InvalidArguments", "Invalid signature"));
        return r;
    }

    handler = dbus_message_get_path(m);
    if (!pa_streq(handler, HSP_AG_PROFILE)) {
        pa_log_error("Invalid handler");
        pa_assert_se(r = dbus_message_new_error(m, "org.bluez.Error.InvalidArguments", "Invalid handler"));
        return r;
    }

    pa_assert(dbus_message_iter_get_arg_type(&arg_i) == DBUS_TYPE_OBJECT_PATH);
    dbus_message_iter_get_basic(&arg_i, &path);

    d = pa_bluetooth_discovery_get_device_by_path(hsp->discovery, path);
    if (d == NULL) {
        pa_log_error("Device doesnt exist for %s", path);
        pa_assert_se(r = dbus_message_new_error_printf(m, "org.bluez.Error.InvalidArguments", "Device doesnt exist for %s", path));
        return r;
    }

    pa_assert_se(dbus_message_iter_next(&arg_i));

    pa_assert(dbus_message_iter_get_arg_type(&arg_i) == DBUS_TYPE_UNIX_FD);
    dbus_message_iter_get_basic(&arg_i, &fd);

    pa_log_debug("dbus: NewConnection path=%s, fd=%d", path, fd);

    sender = dbus_message_get_sender(m);

    t = pa_bluetooth_transport_new(d, sender, path, PA_BLUETOOTH_PROFILE_HSP_HEAD_UNIT, NULL, 0);

    /* Expects that remote HSP headset supports volume control and we do not need to use local softvol */
    t->rx_soft_volume = false;
    t->tx_soft_volume = false;
    t->max_rx_volume_gain = 15;
    t->max_tx_volume_gain = 15;

    t->acquire = sco_acquire_cb;
    t->release = sco_release_cb;
    t->destroy = transport_destroy;
    t->set_rx_volume_gain = set_rx_volume_gain;
    t->set_tx_volume_gain = set_tx_volume_gain;

    trd = pa_xnew0(struct transport_data, 1);
    trd->rfcomm_fd = fd;
    trd->mainloop = hsp->core->mainloop;
    trd->rfcomm_io = trd->mainloop->io_new(hsp->core->mainloop, fd, PA_IO_EVENT_INPUT,
        rfcomm_io_callback, t);
    trd->sco_fd = -EAGAIN;
    t->userdata =  trd;

    pa_bluetooth_transport_put(t);

    pa_log_debug("Transport %s available for profile %s", t->path, pa_bluetooth_profile_to_string(t->profile));

    pa_assert_se(r = dbus_message_new_method_return(m));
    return r;
}

static DBusMessage *profile_request_disconnection(DBusConnection *conn, DBusMessage *m, void *userdata) {
    pa_bluetooth_legacy_hsp *hsp = userdata;
    DBusMessage *r;
    DBusError error;
    const char *path;
    pa_bluetooth_transport *t;

    dbus_error_init(&error);

    if (!dbus_message_get_args(m, &error, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID) || dbus_error_is_set(&error)) {
        pa_log_error("Invalid parameters found in RequestDisconnection: %s", error.message);
        pa_assert_se(r = dbus_message_new_error_printf(m, "org.bluez.Error.InvalidArguments", "Invalid parameters: %s", error.message));
        dbus_error_free(&error);
        return r;
    }

    dbus_error_free(&error);

    pa_log_debug("dbus: RequestDisconnection path=%s", path);

    t = pa_bluetooth_transport_get(hsp->discovery, path);
    if (!t || !pa_safe_streq(dbus_message_get_sender(m), t->owner) || t->profile != PA_BLUETOOTH_PROFILE_HSP_HEAD_UNIT) {
        pa_log_error("RequestDisconnection failed: Endpoint %s is not connected", path);
        pa_assert_se(r = dbus_message_new_error_printf(m, "org.bluez.Error.InvalidArguments", "Endpoint %s is not connected", path));
        return r;
    }

    pa_bluetooth_transport_free(t);

    pa_assert_se(r = dbus_message_new_method_return(m));
    return r;
}

static DBusHandlerResult profile_handler(DBusConnection *c, DBusMessage *m, void *userdata) {
    pa_bluetooth_legacy_hsp *hsp = userdata;
    DBusMessage *r = NULL;
    const char *path, *interface, *member;

    pa_assert(hsp);

    path = dbus_message_get_path(m);
    interface = dbus_message_get_interface(m);
    member = dbus_message_get_member(m);

    pa_log_debug("dbus: path=%s, interface=%s, member=%s", path, interface, member);

    if (!pa_streq(path, HSP_AG_PROFILE))
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    if (dbus_message_is_method_call(m, "org.freedesktop.DBus.Introspectable", "Introspect")) {
        const char *xml = PROFILE_INTROSPECT_XML;

        pa_assert_se(r = dbus_message_new_method_return(m));
        pa_assert_se(dbus_message_append_args(r, DBUS_TYPE_STRING, &xml, DBUS_TYPE_INVALID));

    } else if (dbus_message_is_method_call(m, BLUEZ_PROFILE_INTERFACE, "Release")) {
        pa_log_debug("Release not handled");
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    } else if (dbus_message_is_method_call(m, BLUEZ_PROFILE_INTERFACE, "RequestDisconnection")) {
        r = profile_request_disconnection(c, m, userdata);
    } else if (dbus_message_is_method_call(m, BLUEZ_PROFILE_INTERFACE, "NewConnection"))
        r = profile_new_connection(c, m, userdata);
    else
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    if (r) {
        pa_assert_se(dbus_connection_send(pa_dbus_connection_get(hsp->connection), r, NULL));
        dbus_message_unref(r);
    }

    return DBUS_HANDLER_RESULT_HANDLED;
}

pa_bluetooth_legacy_hsp *pa_bluetooth_legacy_hsp_register(pa_core *c, pa_bluetooth_discovery *y) {
    static const DBusObjectPathVTable vtable_profile = {
        .message_function = profile_handler,
    };

    pa_bluetooth_legacy_hsp *hsp;
    DBusError err;

    pa_log_warn("Enabling legacy HSP profile");

    hsp = pa_xnew0(pa_bluetooth_legacy_hsp, 1);
    hsp->core = c;

    dbus_error_init(&err);
    if (!(hsp->connection = pa_dbus_bus_get(c, DBUS_BUS_SYSTEM, &err))) {
        pa_log("Failed to get D-Bus connection: %s", err.message);
        dbus_error_free(&err);
        pa_xfree(hsp);
        return NULL;
    }

    hsp->discovery = y;

    pa_assert_se(dbus_connection_register_object_path(pa_dbus_connection_get(hsp->connection), HSP_AG_PROFILE, &vtable_profile, hsp));
    register_profile(hsp);
    return hsp;
}

void pa_bluetooth_legacy_hsp_unregister(pa_bluetooth_legacy_hsp *hsp) {
    pa_assert(hsp);

    pa_log_warn("Disabling legacy HSP profile");

    pa_dbus_free_pending_list(&hsp->pending);

    unregister_profile(hsp);
    dbus_connection_unregister_object_path(pa_dbus_connection_get(hsp->connection), HSP_AG_PROFILE);
    pa_dbus_connection_unref(hsp->connection);

    pa_xfree(hsp->service_id);
    pa_xfree(hsp);
}
