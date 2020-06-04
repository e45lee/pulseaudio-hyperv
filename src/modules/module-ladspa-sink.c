/***
  This file is part of PulseAudio.

  Copyright 2004-2008 Lennart Poettering

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

/* TODO: Some plugins cause latency, and some even report it by using a control
   out port. We don't currently use the latency information. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <modules/virtual-sink-common.h>

#include <math.h>

#include <pulse/xmalloc.h>

#include <pulsecore/i18n.h>
#include <pulsecore/namereg.h>
#include <pulsecore/module.h>
#include <pulsecore/core-util.h>
#include <pulsecore/log.h>
#include <pulsecore/rtpoll.h>
#include <pulsecore/sample-util.h>
#include <pulsecore/ltdl-helper.h>

#ifdef HAVE_DBUS
#include <pulsecore/protocol-dbus.h>
#include <pulsecore/dbus-util.h>
#endif

#include "ladspa.h"

PA_MODULE_AUTHOR("Lennart Poettering");
PA_MODULE_DESCRIPTION(_("Virtual LADSPA sink"));
PA_MODULE_VERSION(PACKAGE_VERSION);
PA_MODULE_LOAD_ONCE(false);
PA_MODULE_USAGE(
    _("sink_name=<name for the sink> "
      "sink_properties=<properties for the sink> "
      "sink_input_properties=<properties for the sink input> "
      "master=<name of sink to filter> "
      "sink_master=<name of sink to filter> "
      "format=<sample format> "
      "rate=<sample rate> "
      "channels=<number of channels> "
      "channel_map=<input channel map> "
      "plugin=<ladspa plugin name> "
      "label=<ladspa plugin label> "
      "control=<comma separated list of input control values> "
      "input_ladspaport_map=<comma separated list of input LADSPA port names> "
      "output_ladspaport_map=<comma separated list of output LADSPA port names> "
      "autoloaded=<set if this module is being loaded automatically> "));

#define MEMBLOCKQ_MAXLENGTH (16*1024*1024)
#define DEFAULT_AUTOLOADED false

/* PLEASE NOTICE: The PortAudio ports and the LADSPA ports are two different concepts.
They are not related and where possible the names of the LADSPA port variables contains "ladspa" to avoid confusion */

struct userdata {
    pa_module *module;

    pa_vsink *vsink;

    const LADSPA_Descriptor *descriptor;
    LADSPA_Handle handle[PA_CHANNELS_MAX];
    unsigned long max_ladspaport_count, input_count, output_count, channels;
    LADSPA_Data **input, **output;
    size_t block_size;
    LADSPA_Data *control;
    long unsigned n_control;

    /* This is a dummy buffer. Every port must be connected, but we don't care
    about control out ports. We connect them all to this single buffer. */
    LADSPA_Data control_out;

    bool *use_default;
    pa_sample_spec ss;

#ifdef HAVE_DBUS
    pa_dbus_protocol *dbus_protocol;
    char *dbus_path;
#endif
};

static const char* const valid_modargs[] = {
    "sink_name",
    "sink_properties",
    "sink_input_properties",
    "master",  /* Will be deprecated. */
    "sink_master",
    "format",
    "rate",
    "channels",
    "channel_map",
    "plugin",
    "label",
    "control",
    "input_ladspaport_map",
    "output_ladspaport_map",
    "autoloaded",
    NULL
};

static int write_control_parameters(struct userdata *u, double *control_values, bool *use_default);

#ifdef HAVE_DBUS

#define LADSPA_IFACE "org.PulseAudio.Ext.Ladspa1"
#define LADSPA_ALGORITHM_PARAMETERS "AlgorithmParameters"

/* TODO: add a PropertyChanged signal to tell that the algorithm parameters have been changed */

enum ladspa_handler_index {
    LADSPA_HANDLER_ALGORITHM_PARAMETERS,
    LADSPA_HANDLER_MAX
};

static void get_algorithm_parameters(DBusConnection *conn, DBusMessage *msg, void *_u) {
    struct userdata *u;
    DBusMessage *reply = NULL;
    DBusMessageIter msg_iter, struct_iter;
    unsigned long i;
    double *control;
    dbus_bool_t *use_default;

    pa_assert(conn);
    pa_assert(msg);
    pa_assert_se(u = _u);

    pa_assert_se((reply = dbus_message_new_method_return(msg)));
    dbus_message_iter_init_append(reply, &msg_iter);

    dbus_message_iter_open_container(&msg_iter, DBUS_TYPE_STRUCT, NULL, &struct_iter);

    /* copying because of the D-Bus type mapping */
    control = pa_xnew(double, u->n_control);
    use_default = pa_xnew(dbus_bool_t, u->n_control);

    for (i = 0; i < u->n_control; i++) {
        control[i] = (double) u->control[i];
        use_default[i] = u->use_default[i];
    }

    pa_dbus_append_basic_array(&struct_iter, DBUS_TYPE_DOUBLE, control, u->n_control);
    pa_dbus_append_basic_array(&struct_iter, DBUS_TYPE_BOOLEAN, use_default, u->n_control);

    pa_assert_se(dbus_message_iter_close_container(&msg_iter, &struct_iter));

    pa_assert_se(dbus_connection_send(conn, reply, NULL));

    dbus_message_unref(reply);
    pa_xfree(control);
    pa_xfree(use_default);
}

static void set_algorithm_parameters(DBusConnection *conn, DBusMessage *msg, DBusMessageIter *iter, void *_u) {
    struct userdata *u;
    DBusMessageIter array_iter, struct_iter;
    int n_control = 0, n_use_default;
    unsigned n_dbus_control, n_dbus_use_default;
    double *read_values = NULL;
    dbus_bool_t *read_defaults = NULL;
    bool *use_defaults = NULL;
    unsigned long i;

    pa_assert(conn);
    pa_assert(msg);
    pa_assert_se(u = _u);

    /* The property we are expecting has signature (adab), meaning that it's a
       struct of two arrays, the first containing doubles and the second containing
       booleans. The first array has the algorithm configuration values and the
       second array has booleans indicating whether the matching algorithm
       configuration value should use (or try to use) the default value provided by
       the algorithm module. The PulseAudio D-Bus infrastructure will take care of
       checking the argument types for us. */

    dbus_message_iter_recurse(iter, &struct_iter);

    dbus_message_iter_recurse(&struct_iter, &array_iter);
    dbus_message_iter_get_fixed_array(&array_iter, &read_values, &n_control);

    dbus_message_iter_next(&struct_iter);
    dbus_message_iter_recurse(&struct_iter, &array_iter);
    dbus_message_iter_get_fixed_array(&array_iter, &read_defaults, &n_use_default);

    n_dbus_control = n_control; /* handle the unsignedness */
    n_dbus_use_default = n_use_default;

    if (n_dbus_control != u->n_control || n_dbus_use_default != u->n_control) {
        pa_dbus_send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, "Wrong number of array values (expected %lu)", u->n_control);
        return;
    }

    use_defaults = pa_xnew(bool, n_control);
    for (i = 0; i < u->n_control; i++)
        use_defaults[i] = read_defaults[i];

    if (write_control_parameters(u, read_values, use_defaults) < 0) {
        pa_log_warn("Failed writing control parameters");
        goto error;
    }

    pa_virtual_sink_request_parameter_update(u->vsink, NULL);

    pa_dbus_send_empty_reply(conn, msg);

    pa_xfree(use_defaults);
    return;

error:
    pa_xfree(use_defaults);
    pa_dbus_send_error(conn, msg, DBUS_ERROR_FAILED, "Internal error");
}

static pa_dbus_property_handler ladspa_property_handlers[LADSPA_HANDLER_MAX] = {
    [LADSPA_HANDLER_ALGORITHM_PARAMETERS] = {
        .property_name = LADSPA_ALGORITHM_PARAMETERS,
        .type = "(adab)",
        .get_cb = get_algorithm_parameters,
        .set_cb = set_algorithm_parameters
    }
};

static void ladspa_get_all(DBusConnection *conn, DBusMessage *msg, void *_u) {
    struct userdata *u;
    DBusMessage *reply = NULL;
    DBusMessageIter msg_iter, dict_iter, dict_entry_iter, variant_iter, struct_iter;
    const char *key = LADSPA_ALGORITHM_PARAMETERS;
    double *control;
    dbus_bool_t *use_default;
    long unsigned i;

    pa_assert(conn);
    pa_assert(msg);
    pa_assert_se(u = _u);

    pa_assert_se((reply = dbus_message_new_method_return(msg)));

    /* Currently, on this interface, only a single property is returned. */

    dbus_message_iter_init_append(reply, &msg_iter);
    pa_assert_se(dbus_message_iter_open_container(&msg_iter, DBUS_TYPE_ARRAY, "{sv}", &dict_iter));
    pa_assert_se(dbus_message_iter_open_container(&dict_iter, DBUS_TYPE_DICT_ENTRY, NULL, &dict_entry_iter));
    pa_assert_se(dbus_message_iter_append_basic(&dict_entry_iter, DBUS_TYPE_STRING, &key));

    pa_assert_se(dbus_message_iter_open_container(&dict_entry_iter, DBUS_TYPE_VARIANT, "(adab)", &variant_iter));
    pa_assert_se(dbus_message_iter_open_container(&variant_iter, DBUS_TYPE_STRUCT, NULL, &struct_iter));

    control = pa_xnew(double, u->n_control);
    use_default = pa_xnew(dbus_bool_t, u->n_control);

    for (i = 0; i < u->n_control; i++) {
        control[i] = (double) u->control[i];
        use_default[i] = u->use_default[i];
    }

    pa_dbus_append_basic_array(&struct_iter, DBUS_TYPE_DOUBLE, control, u->n_control);
    pa_dbus_append_basic_array(&struct_iter, DBUS_TYPE_BOOLEAN, use_default, u->n_control);

    pa_assert_se(dbus_message_iter_close_container(&variant_iter, &struct_iter));
    pa_assert_se(dbus_message_iter_close_container(&dict_entry_iter, &variant_iter));
    pa_assert_se(dbus_message_iter_close_container(&dict_iter, &dict_entry_iter));
    pa_assert_se(dbus_message_iter_close_container(&msg_iter, &dict_iter));

    pa_assert_se(dbus_connection_send(conn, reply, NULL));
    dbus_message_unref(reply);
    pa_xfree(control);
    pa_xfree(use_default);
}

static pa_dbus_interface_info ladspa_info = {
    .name = LADSPA_IFACE,
    .method_handlers = NULL,
    .n_method_handlers = 0,
    .property_handlers = ladspa_property_handlers,
    .n_property_handlers = LADSPA_HANDLER_MAX,
    .get_all_properties_cb = ladspa_get_all,
    .signals = NULL,
    .n_signals = 0
};

static void dbus_init(struct userdata *u) {
    pa_assert_se(u);

    u->dbus_protocol = pa_dbus_protocol_get(u->vsink->sink->core);
    u->dbus_path = pa_sprintf_malloc("/org/pulseaudio/core1/sink%d", u->vsink->sink->index);

    pa_dbus_protocol_add_interface(u->dbus_protocol, u->dbus_path, &ladspa_info, u);
}

static void dbus_done(struct userdata *u) {
    pa_assert_se(u);

    if (!u->dbus_protocol) {
        pa_assert(!u->dbus_path);
        return;
    }

    pa_dbus_protocol_remove_interface(u->dbus_protocol, u->dbus_path, ladspa_info.name);
    pa_xfree(u->dbus_path);
    pa_dbus_protocol_unref(u->dbus_protocol);

    u->dbus_path = NULL;
    u->dbus_protocol = NULL;
}

#endif /* HAVE_DBUS */

/* Called from I/O thread context */
static void filter_process_chunk(float *src, float *dst, unsigned in_count, unsigned out_count, void *userdata) {
    struct userdata *u;
    unsigned h, c;

    pa_assert_se(u = userdata);
    pa_assert(in_count == out_count);

    for (h = 0; h < (u->channels / u->max_ladspaport_count); h++) {
        for (c = 0; c < u->input_count; c++)
            pa_sample_clamp(PA_SAMPLE_FLOAT32NE, u->input[c], sizeof(float), src+ h*u->max_ladspaport_count + c, u->channels*sizeof(float), in_count);
        u->descriptor->run(u->handle[h], in_count);
        for (c = 0; c < u->output_count; c++)
            pa_sample_clamp(PA_SAMPLE_FLOAT32NE, dst + h*u->max_ladspaport_count + c, u->channels*sizeof(float), u->output[c], sizeof(float), in_count);
    }
}

/* Called from I/O thread context */
static void reset_filter(pa_sink *s, size_t amount) {
    struct userdata *u;
    unsigned c;

    pa_assert_se(u = s->userdata);

    pa_log_debug("Resetting plugin");

    /* Reset the plugin */
    if (u->descriptor->deactivate)
        for (c = 0; c < (u->channels / u->max_ladspaport_count); c++)
            u->descriptor->deactivate(u->handle[c]);
    if (u->descriptor->activate)
        for (c = 0; c < (u->channels / u->max_ladspaport_count); c++)
            u->descriptor->activate(u->handle[c]);
}

static int parse_control_parameters(struct userdata *u, const char *cdata, double *read_values, bool *use_default) {
    unsigned long p = 0;
    const char *state = NULL;
    char *k;

    pa_assert(read_values);
    pa_assert(use_default);
    pa_assert(u);

    pa_log_debug("Trying to read %lu control values", u->n_control);

    if (!cdata || u->n_control == 0)
        return -1;

    pa_log_debug("cdata: '%s'", cdata);

    while ((k = pa_split(cdata, ",", &state)) && p < u->n_control) {
        double f;

        if (*k == 0) {
            pa_log_debug("Read empty config value (p=%lu)", p);
            use_default[p++] = true;
            pa_xfree(k);
            continue;
        }

        if (pa_atod(k, &f) < 0) {
            pa_log_debug("Failed to parse control value '%s' (p=%lu)", k, p);
            pa_xfree(k);
            goto fail;
        }

        pa_xfree(k);

        pa_log_debug("Read config value %f (p=%lu)", f, p);

        use_default[p] = false;
        read_values[p++] = f;
    }

    /* The previous loop doesn't take the last control value into account
       if it is left empty, so we do it here. */
    if (*cdata == 0 || cdata[strlen(cdata) - 1] == ',') {
        if (p < u->n_control)
            use_default[p] = true;
        p++;
    }

    if (p > u->n_control || k) {
        pa_log("Too many control values passed, %lu expected.", u->n_control);
        pa_xfree(k);
        goto fail;
    }

    if (p < u->n_control) {
        pa_log("Not enough control values passed, %lu expected, %lu passed.", u->n_control, p);
        goto fail;
    }

    return 0;

fail:
    return -1;
}

static void connect_control_ports(void *parameters, void *userdata) {
    struct userdata *u;
    unsigned long p = 0, h = 0, c;
    const LADSPA_Descriptor *d;

    pa_assert(u = userdata);
    pa_assert_se(d = u->descriptor);

    for (p = 0; p < d->PortCount; p++) {
        if (!LADSPA_IS_PORT_CONTROL(d->PortDescriptors[p]))
            continue;

        if (LADSPA_IS_PORT_OUTPUT(d->PortDescriptors[p])) {
            for (c = 0; c < (u->channels / u->max_ladspaport_count); c++)
                d->connect_port(u->handle[c], p, &u->control_out);
            continue;
        }

        /* input control port */

        pa_log_debug("Binding %f to port %s", u->control[h], d->PortNames[p]);

        for (c = 0; c < (u->channels / u->max_ladspaport_count); c++)
            d->connect_port(u->handle[c], p, &u->control[h]);

        h++;
    }
}

static int validate_control_parameters(struct userdata *u, double *control_values, bool *use_default) {
    unsigned long p = 0, h = 0;
    const LADSPA_Descriptor *d;
    pa_sample_spec ss;

    pa_assert(control_values);
    pa_assert(use_default);
    pa_assert(u);
    pa_assert_se(d = u->descriptor);

    ss = u->ss;

    /* Iterate over all ports. Check for every control port that 1) it
     * supports default values if a default value is provided and 2) the
     * provided value is within the limits specified in the plugin. */

    for (p = 0; p < d->PortCount; p++) {
        LADSPA_PortRangeHintDescriptor hint = d->PortRangeHints[p].HintDescriptor;

        if (!LADSPA_IS_PORT_CONTROL(d->PortDescriptors[p]))
            continue;

        if (LADSPA_IS_PORT_OUTPUT(d->PortDescriptors[p]))
            continue;

        if (use_default[h]) {
            /* User wants to use default value. Check if the plugin
             * provides it. */
            if (!LADSPA_IS_HINT_HAS_DEFAULT(hint)) {
                pa_log_warn("Control port value left empty but plugin defines no default.");
                return -1;
            }
        }
        else {
            /* Check if the user-provided value is within the bounds. */
            LADSPA_Data lower = d->PortRangeHints[p].LowerBound;
            LADSPA_Data upper = d->PortRangeHints[p].UpperBound;

            if (LADSPA_IS_HINT_SAMPLE_RATE(hint)) {
                upper *= (LADSPA_Data) ss.rate;
                lower *= (LADSPA_Data) ss.rate;
            }

            if (LADSPA_IS_HINT_BOUNDED_ABOVE(hint)) {
                if (control_values[h] > upper) {
                    pa_log_warn("Control value %lu over upper bound: %f (upper bound: %f)", h, control_values[h], upper);
                    return -1;
                }
            }
            if (LADSPA_IS_HINT_BOUNDED_BELOW(hint)) {
                if (control_values[h] < lower) {
                    pa_log_warn("Control value %lu below lower bound: %f (lower bound: %f)", h, control_values[h], lower);
                    return -1;
                }
            }
        }

        h++;
    }

    return 0;
}

static int write_control_parameters(struct userdata *u, double *control_values, bool *use_default) {
    unsigned long p = 0, h = 0, c;
    const LADSPA_Descriptor *d;
    pa_sample_spec ss;

    pa_assert(control_values);
    pa_assert(use_default);
    pa_assert(u);
    pa_assert_se(d = u->descriptor);

    ss = u->ss;

    if (validate_control_parameters(u, control_values, use_default) < 0)
        return -1;

    /* p iterates over all ports, h is the control port iterator */

    for (p = 0; p < d->PortCount; p++) {
        LADSPA_PortRangeHintDescriptor hint = d->PortRangeHints[p].HintDescriptor;

        if (!LADSPA_IS_PORT_CONTROL(d->PortDescriptors[p]))
            continue;

        if (LADSPA_IS_PORT_OUTPUT(d->PortDescriptors[p])) {
            for (c = 0; c < (u->channels / u->max_ladspaport_count); c++)
                d->connect_port(u->handle[c], p, &u->control_out);
            continue;
        }

        if (use_default[h]) {

            LADSPA_Data lower, upper;

            lower = d->PortRangeHints[p].LowerBound;
            upper = d->PortRangeHints[p].UpperBound;

            if (LADSPA_IS_HINT_SAMPLE_RATE(hint)) {
                lower *= (LADSPA_Data) ss.rate;
                upper *= (LADSPA_Data) ss.rate;
            }

            switch (hint & LADSPA_HINT_DEFAULT_MASK) {

            case LADSPA_HINT_DEFAULT_MINIMUM:
                u->control[h] = lower;
                break;

            case LADSPA_HINT_DEFAULT_MAXIMUM:
                u->control[h] = upper;
                break;

            case LADSPA_HINT_DEFAULT_LOW:
                if (LADSPA_IS_HINT_LOGARITHMIC(hint))
                    u->control[h] = (LADSPA_Data) exp(log(lower) * 0.75 + log(upper) * 0.25);
                else
                    u->control[h] = (LADSPA_Data) (lower * 0.75 + upper * 0.25);
                break;

            case LADSPA_HINT_DEFAULT_MIDDLE:
                if (LADSPA_IS_HINT_LOGARITHMIC(hint))
                    u->control[h] = (LADSPA_Data) exp(log(lower) * 0.5 + log(upper) * 0.5);
                else
                    u->control[h] = (LADSPA_Data) (lower * 0.5 + upper * 0.5);
                break;

            case LADSPA_HINT_DEFAULT_HIGH:
                if (LADSPA_IS_HINT_LOGARITHMIC(hint))
                    u->control[h] = (LADSPA_Data) exp(log(lower) * 0.25 + log(upper) * 0.75);
                else
                    u->control[h] = (LADSPA_Data) (lower * 0.25 + upper * 0.75);
                break;

            case LADSPA_HINT_DEFAULT_0:
                u->control[h] = 0;
                break;

            case LADSPA_HINT_DEFAULT_1:
                u->control[h] = 1;
                break;

            case LADSPA_HINT_DEFAULT_100:
                u->control[h] = 100;
                break;

            case LADSPA_HINT_DEFAULT_440:
                u->control[h] = 440;
                break;

            default:
                pa_assert_not_reached();
            }
        }
        else {
            if (LADSPA_IS_HINT_INTEGER(hint)) {
                u->control[h] = roundf(control_values[h]);
            }
            else {
                u->control[h] = control_values[h];
            }
        }

        h++;
    }

    /* set the use_default array to the user data */
    memcpy(u->use_default, use_default, u->n_control * sizeof(u->use_default[0]));

    return 0;
}

int pa__init(pa_module*m) {
    struct userdata *u;
    pa_sample_spec ss;
    pa_channel_map map;
    pa_modargs *ma;
    char *t;
    const char *master_name;
    pa_sink *master;
    const char *plugin, *label, *input_ladspaport_map, *output_ladspaport_map;
    LADSPA_Descriptor_Function descriptor_func;
    unsigned long input_ladspaport[PA_CHANNELS_MAX], output_ladspaport[PA_CHANNELS_MAX];
    const char *e, *cdata;
    const LADSPA_Descriptor *d;
    unsigned long p, h, j, n_control, c;

    pa_assert(m);

    pa_assert_cc(sizeof(LADSPA_Data) == sizeof(float));

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

    ss = master->sample_spec;
    ss.format = PA_SAMPLE_FLOAT32;
    map = master->channel_map;
    if (pa_modargs_get_sample_spec_and_channel_map(ma, &ss, &map, PA_CHANNEL_MAP_DEFAULT) < 0) {
        pa_log("Invalid sample format specification or channel map");
        goto fail;
    }

    if (ss.format != PA_SAMPLE_FLOAT32) {
        pa_log("LADSPA accepts float format only");
        goto fail;
    }

    if (!(plugin = pa_modargs_get_value(ma, "plugin", NULL))) {
        pa_log("Missing LADSPA plugin name");
        goto fail;
    }

    if (!(label = pa_modargs_get_value(ma, "label", NULL))) {
        pa_log("Missing LADSPA plugin label");
        goto fail;
    }

    if (!(input_ladspaport_map = pa_modargs_get_value(ma, "input_ladspaport_map", NULL)))
        pa_log_debug("Using default input ladspa port mapping");

    if (!(output_ladspaport_map = pa_modargs_get_value(ma, "output_ladspaport_map", NULL)))
        pa_log_debug("Using default output ladspa port mapping");

    cdata = pa_modargs_get_value(ma, "control", NULL);

    u = pa_xnew0(struct userdata, 1);
    u->module = m;
    m->userdata = u;
    u->max_ladspaport_count = 1; /*to avoid division by zero etc. in pa__done when failing before this value has been set*/
    u->channels = 0;
    u->input = NULL;
    u->output = NULL;
    u->ss = ss;

    if (!(e = getenv("LADSPA_PATH")))
        /* The LADSPA_PATH preprocessor macro isn't a string literal (i.e. it
         * doesn't contain quotes), because otherwise the build system would
         * have an extra burden of getting the escaping right (Windows paths
         * are especially tricky). PA_EXPAND_AND_STRINGIZE does the necessary
         * escaping. */
        e = PA_EXPAND_AND_STRINGIZE(LADSPA_PATH);

    /* FIXME: This is not exactly thread safe */
    t = pa_xstrdup(lt_dlgetsearchpath());
    lt_dlsetsearchpath(e);
    m->dl = lt_dlopenext(plugin);
    lt_dlsetsearchpath(t);
    pa_xfree(t);

    if (!m->dl) {
        pa_log("Failed to load LADSPA plugin: %s", lt_dlerror());
        goto fail;
    }

    if (!(descriptor_func = (LADSPA_Descriptor_Function) pa_load_sym(m->dl, NULL, "ladspa_descriptor"))) {
        pa_log("LADSPA module lacks ladspa_descriptor() symbol.");
        goto fail;
    }

    for (j = 0;; j++) {

        if (!(d = descriptor_func(j))) {
            pa_log("Failed to find plugin label '%s' in plugin '%s'.", label, plugin);
            goto fail;
        }

        if (pa_streq(d->Label, label))
            break;
    }

    u->descriptor = d;

    pa_log_debug("Module: %s", plugin);
    pa_log_debug("Label: %s", d->Label);
    pa_log_debug("Unique ID: %lu", d->UniqueID);
    pa_log_debug("Name: %s", d->Name);
    pa_log_debug("Maker: %s", d->Maker);
    pa_log_debug("Copyright: %s", d->Copyright);

    n_control = 0;
    u->channels = ss.channels;

    /*
    * Enumerate ladspa ports
    * Default mapping is in order given by the plugin
    */
    for (p = 0; p < d->PortCount; p++) {
        if (LADSPA_IS_PORT_AUDIO(d->PortDescriptors[p])) {
            if (LADSPA_IS_PORT_INPUT(d->PortDescriptors[p])) {
                pa_log_debug("Port %lu is input: %s", p, d->PortNames[p]);
                input_ladspaport[u->input_count] = p;
                u->input_count++;
            } else if (LADSPA_IS_PORT_OUTPUT(d->PortDescriptors[p])) {
                pa_log_debug("Port %lu is output: %s", p, d->PortNames[p]);
                output_ladspaport[u->output_count] = p;
                u->output_count++;
            }
        } else if (LADSPA_IS_PORT_CONTROL(d->PortDescriptors[p]) && LADSPA_IS_PORT_INPUT(d->PortDescriptors[p])) {
            pa_log_debug("Port %lu is control: %s", p, d->PortNames[p]);
            n_control++;
        } else
            pa_log_debug("Ignored port %s", d->PortNames[p]);
        /* XXX: Has anyone ever seen an in-place plugin with non-equal number of input and output ports? */
        /* Could be if the plugin is for up-mixing stereo to 5.1 channels */
        /* Or if the plugin is down-mixing 5.1 to two channel stereo or binaural encoded signal */
        if (u->input_count > u->max_ladspaport_count)
            u->max_ladspaport_count = u->input_count;
        else
            u->max_ladspaport_count = u->output_count;
    }

    if (u->channels % u->max_ladspaport_count) {
        pa_log("Cannot handle non-integral number of plugins required for given number of channels");
        goto fail;
    }

    pa_log_debug("Will run %lu plugin instances", u->channels / u->max_ladspaport_count);

    /* Parse data for input ladspa port map */
    if (input_ladspaport_map) {
        const char *state = NULL;
        char *pname;
        c = 0;
        while ((pname = pa_split(input_ladspaport_map, ",", &state))) {
            if (c == u->input_count) {
                pa_log("Too many ports in input ladspa port map");
                pa_xfree(pname);
                goto fail;
            }

            for (p = 0; p < d->PortCount; p++) {
                if (pa_streq(d->PortNames[p], pname)) {
                    if (LADSPA_IS_PORT_AUDIO(d->PortDescriptors[p]) && LADSPA_IS_PORT_INPUT(d->PortDescriptors[p])) {
                        input_ladspaport[c] = p;
                    } else {
                        pa_log("Port %s is not an audio input ladspa port", pname);
                        pa_xfree(pname);
                        goto fail;
                    }
                }
            }
            c++;
            pa_xfree(pname);
        }
    }

    /* Parse data for output port map */
    if (output_ladspaport_map) {
        const char *state = NULL;
        char *pname;
        c = 0;
        while ((pname = pa_split(output_ladspaport_map, ",", &state))) {
            if (c == u->output_count) {
                pa_log("Too many ports in output ladspa port map");
                pa_xfree(pname);
                goto fail;
            }
            for (p = 0; p < d->PortCount; p++) {
                if (pa_streq(d->PortNames[p], pname)) {
                    if (LADSPA_IS_PORT_AUDIO(d->PortDescriptors[p]) && LADSPA_IS_PORT_OUTPUT(d->PortDescriptors[p])) {
                        output_ladspaport[c] = p;
                    } else {
                        pa_log("Port %s is not an output ladspa port", pname);
                        pa_xfree(pname);
                        goto fail;
                    }
                }
            }
            c++;
            pa_xfree(pname);
        }
    }

    u->block_size = pa_frame_align(pa_mempool_block_size_max(m->core->mempool), &ss);

    /* Create buffers */
    if (LADSPA_IS_INPLACE_BROKEN(d->Properties)) {
        u->input = (LADSPA_Data**) pa_xnew(LADSPA_Data*, (unsigned) u->input_count);
        for (c = 0; c < u->input_count; c++)
            u->input[c] = (LADSPA_Data*) pa_xnew(uint8_t, (unsigned) u->block_size);
        u->output = (LADSPA_Data**) pa_xnew(LADSPA_Data*, (unsigned) u->output_count);
        for (c = 0; c < u->output_count; c++)
            u->output[c] = (LADSPA_Data*) pa_xnew(uint8_t, (unsigned) u->block_size);
    } else {
        u->input = (LADSPA_Data**) pa_xnew(LADSPA_Data*, (unsigned) u->max_ladspaport_count);
        for (c = 0; c < u->max_ladspaport_count; c++)
            u->input[c] = (LADSPA_Data*) pa_xnew(uint8_t, (unsigned) u->block_size);
        u->output = u->input;
    }
    /* Initialize plugin instances */
    for (h = 0; h < (u->channels / u->max_ladspaport_count); h++) {
        if (!(u->handle[h] = d->instantiate(d, ss.rate))) {
            pa_log("Failed to instantiate plugin %s with label %s", plugin, d->Label);
            goto fail;
        }

        for (c = 0; c < u->input_count; c++)
            d->connect_port(u->handle[h], input_ladspaport[c], u->input[c]);
        for (c = 0; c < u->output_count; c++)
            d->connect_port(u->handle[h], output_ladspaport[c], u->output[c]);
    }

    u->n_control = n_control;

    if (u->n_control > 0) {
        double *control_values;
        bool *use_default;

        /* temporary storage for parser */
        control_values = pa_xnew(double, (unsigned) u->n_control);
        use_default = pa_xnew(bool, (unsigned) u->n_control);

        /* real storage */
        u->control = pa_xnew(LADSPA_Data, (unsigned) u->n_control);
        u->use_default = pa_xnew(bool, (unsigned) u->n_control);

        if ((parse_control_parameters(u, cdata, control_values, use_default) < 0) ||
            (write_control_parameters(u, control_values, use_default) < 0)) {
            pa_xfree(control_values);
            pa_xfree(use_default);

            pa_log("Failed to parse, validate or set control parameters");

            goto fail;
        }
        connect_control_ports(NULL, u);
        pa_xfree(control_values);
        pa_xfree(use_default);
    }

    if (d->activate)
        for (c = 0; c < (u->channels / u->max_ladspaport_count); c++)
            d->activate(u->handle[c]);

    /* Create virtual sink */
    if (!(u->vsink = pa_virtual_sink_create(master, "ladspa", "LADSPA Sink", &ss, &map,
                                             &ss, &map, m, u, ma, true, true, 0)))
        goto fail;

    u->vsink->process_chunk = filter_process_chunk;
    u->vsink->rewind_filter = reset_filter;
    u->vsink->update_filter_parameters = connect_control_ports;
    u->vsink->max_chunk_size = u->block_size;

    pa_proplist_sets(u->vsink->sink->proplist, "device.ladspa.module", plugin);
    pa_proplist_sets(u->vsink->sink->proplist, "device.ladspa.label", d->Label);
    pa_proplist_sets(u->vsink->sink->proplist, "device.ladspa.name", d->Name);
    pa_proplist_sets(u->vsink->sink->proplist, "device.ladspa.maker", d->Maker);
    pa_proplist_sets(u->vsink->sink->proplist, "device.ladspa.copyright", d->Copyright);
    pa_proplist_setf(u->vsink->sink->proplist, "device.ladspa.unique_id", "%lu", (unsigned long) d->UniqueID);

    if (pa_virtual_sink_activate(u->vsink) < 0)
        goto fail;

#ifdef HAVE_DBUS
    dbus_init(u);
#endif

    pa_modargs_free(ma);

    return 0;

fail:
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
    unsigned c;

    pa_assert(m);

    if (!(u = m->userdata))
        return;

#ifdef HAVE_DBUS
    dbus_done(u);
#endif

    if (u->vsink)
        pa_virtual_sink_destroy(u->vsink);

    for (c = 0; c < (u->channels / u->max_ladspaport_count); c++) {
        if (u->handle[c]) {
            if (u->descriptor->deactivate)
                u->descriptor->deactivate(u->handle[c]);
            u->descriptor->cleanup(u->handle[c]);
        }
    }

    if (u->output == u->input) {
        if (u->input != NULL) {
            for (c = 0; c < u->max_ladspaport_count; c++)
                pa_xfree(u->input[c]);
            pa_xfree(u->input);
        }
    } else {
        if (u->input != NULL) {
            for (c = 0; c < u->input_count; c++)
                pa_xfree(u->input[c]);
            pa_xfree(u->input);
        }
        if (u->output != NULL) {
            for (c = 0; c < u->output_count; c++)
                pa_xfree(u->output[c]);
            pa_xfree(u->output);
        }
    }

    pa_xfree(u->control);
    pa_xfree(u->use_default);
    pa_xfree(u);
}
