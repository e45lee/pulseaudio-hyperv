/***
  This file is part of PulseAudio.

  Copyright 2008-2013 João Paulo Rechi Vita

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
#include <pulsecore/macro.h>
#include <pulsecore/module.h>
#include <pulsecore/modargs.h>
#include <pulsecore/shared.h>

#include "bluez5-util.h"

PA_MODULE_AUTHOR("João Paulo Rechi Vita");
PA_MODULE_DESCRIPTION("Detect available BlueZ 5 Bluetooth audio devices and load BlueZ 5 Bluetooth audio drivers");
PA_MODULE_VERSION(PACKAGE_VERSION);
PA_MODULE_LOAD_ONCE(true);
PA_MODULE_USAGE(
    "headset=ofono|native|auto"
    "autodetect_mtu=<boolean>"
);

static const char* const valid_modargs[] = {
    "headset",
    "autodetect_mtu",
    NULL
};

struct userdata {
    pa_module *module;
    pa_core *core;
    pa_hashmap *loaded_device_modules;
    pa_hook_slot *device_connection_changed_slot;
    pa_hook_slot *user_active_changed_slot;
    pa_bluetooth_discovery *discovery;
    int headset_backend;
    bool autodetect_mtu;
};

static pa_hook_result_t device_connection_changed_cb(pa_bluetooth_discovery *y, const pa_bluetooth_device *d, struct userdata *u) {
    bool module_loaded;

    pa_assert(d);
    pa_assert(u);

    module_loaded = pa_hashmap_get(u->loaded_device_modules, d->path) ? true : false;

    if (module_loaded && !pa_bluetooth_device_any_transport_connected(d)) {
        /* disconnection, the module unloads itself */
        pa_log_debug("Unregistering module for %s", d->path);
        pa_hashmap_remove(u->loaded_device_modules, d->path);
        return PA_HOOK_OK;
    }

    if (!module_loaded && pa_bluetooth_device_any_transport_connected(d)) {
        /* a new device has been connected */
        pa_module *m;
        char *args = pa_sprintf_malloc("path=%s autodetect_mtu=%i", d->path, (int)u->autodetect_mtu);

        pa_log_debug("Loading module-bluez5-device %s", args);
        pa_module_load(&m, u->module->core, "module-bluez5-device", args);
        pa_xfree(args);

        if (m)
            /* No need to duplicate the path here since the device object will
             * exist for the whole hashmap entry lifespan */
            pa_hashmap_put(u->loaded_device_modules, d->path, m);
        else
            pa_log_warn("Failed to load module for device %s", d->path);

        return PA_HOOK_OK;
    }

    return PA_HOOK_OK;
}

static int enable_discovery(struct userdata *u) {
    pa_assert(u->discovery == NULL);
    u->discovery = pa_bluetooth_discovery_get(u->core, u->headset_backend);
    if (!u->discovery)
        return -1;

    pa_assert(u->device_connection_changed_slot == NULL);
    u->device_connection_changed_slot =
        pa_hook_connect(pa_bluetooth_discovery_hook(u->discovery, PA_BLUETOOTH_HOOK_DEVICE_CONNECTION_CHANGED),
                        PA_HOOK_NORMAL, (pa_hook_cb_t) device_connection_changed_cb, u);

    return 0;
}

static void disable_discovery(struct userdata *u) {
    if (u->device_connection_changed_slot) {
        pa_hook_slot_free(u->device_connection_changed_slot);
        u->device_connection_changed_slot = 0;
    }

    if (u->discovery) {
        pa_bluetooth_discovery_unref(u->discovery);
        u->discovery = NULL;
    }

    if (u->loaded_device_modules) {
        pa_module *m;
        void *state;

        PA_HASHMAP_FOREACH(m, u->loaded_device_modules, state)
            pa_module_unload(m, true);

        pa_hashmap_remove_all(u->loaded_device_modules);
    }
}

static pa_hook_result_t user_active_changed_cb(pa_core *c, bool *activeptr, struct userdata *u) {
    bool active;

    pa_assert(activeptr);
    pa_assert(u);

    active = *activeptr;
    if (active)
        enable_discovery(u);
    else
        disable_discovery(u);

    return PA_HOOK_OK;
}

#ifdef HAVE_BLUEZ_5_NATIVE_HEADSET
const char *default_headset_backend = "auto";
#else
const char *default_headset_backend = "ofono";
#endif

int pa__init(pa_module *m) {
    struct userdata *u;
    pa_modargs *ma;
    const char *headset_str;
    int headset_backend;
    bool autodetect_mtu;

    pa_assert(m);

    if (!(ma = pa_modargs_new(m->argument, valid_modargs))) {
        pa_log("failed to parse module arguments.");
        goto fail;
    }

    pa_assert_se(headset_str = pa_modargs_get_value(ma, "headset", default_headset_backend));
    if (pa_streq(headset_str, "ofono"))
        headset_backend = HEADSET_BACKEND_OFONO;
    else if (pa_streq(headset_str, "native"))
        headset_backend = HEADSET_BACKEND_NATIVE;
    else if (pa_streq(headset_str, "auto"))
        headset_backend = HEADSET_BACKEND_AUTO;
    else {
        pa_log("headset parameter must be either ofono, native or auto (found %s)", headset_str);
        goto fail;
    }

    autodetect_mtu = false;
    if (pa_modargs_get_value_boolean(ma, "autodetect_mtu", &autodetect_mtu) < 0) {
        pa_log("Invalid boolean value for autodetect_mtu parameter");
        goto fail;
    }

    m->userdata = u = pa_xnew0(struct userdata, 1);
    u->module = m;
    u->core = m->core;
    u->headset_backend = headset_backend;
    u->autodetect_mtu = autodetect_mtu;
    u->loaded_device_modules = pa_hashmap_new(pa_idxset_string_hash_func, pa_idxset_string_compare_func);

    u->user_active_changed_slot =
        pa_hook_connect(&u->core->hooks[PA_CORE_HOOK_USER_ACTIVE_CHANGED],
                        PA_HOOK_NORMAL, (pa_hook_cb_t) user_active_changed_cb, u);

    if (u->core->user_active)
        if (enable_discovery(u) != 0)
            goto fail;

    pa_modargs_free(ma);
    return 0;

fail:
    if (ma)
        pa_modargs_free(ma);
    pa__done(m);
    return -1;
}

void pa__done(pa_module *m) {
    struct userdata *u;

    pa_assert(m);

    if (!(u = m->userdata))
        return;

    if (u->user_active_changed_slot)
        pa_hook_slot_free(u->user_active_changed_slot);

    disable_discovery(u);

    if (u->loaded_device_modules)
        pa_hashmap_free(u->loaded_device_modules);

    pa_xfree(u);
}
