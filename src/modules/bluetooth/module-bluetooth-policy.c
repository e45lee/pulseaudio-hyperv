/***
  This file is part of PulseAudio.

  Copyright 2006 Lennart Poettering
  Copyright 2009 Canonical Ltd
  Copyright (C) 2012 Intel Corporation

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

#include <pulse/xmalloc.h>

#include <pulsecore/core.h>
#include <pulsecore/modargs.h>
#include <pulsecore/source-output.h>
#include <pulsecore/source.h>
#include <pulsecore/core-util.h>

PA_MODULE_AUTHOR("Frédéric Dalleau, Pali Rohár");
PA_MODULE_DESCRIPTION("Policy module to make using bluetooth devices out-of-the-box easier");
PA_MODULE_VERSION(PACKAGE_VERSION);
PA_MODULE_LOAD_ONCE(true);
PA_MODULE_USAGE(
        "auto_switch=<Switch between head unit and a2dp sink card profiles? (0 - never, 1 - media.role=phone, 2 - heuristic> "
        "a2dp_source=<Handle a2dp source card profiles?> "
        "ag=<Handle audio gateway card profiles?> ");

static const char* const valid_modargs[] = {
    "auto_switch",
    "a2dp_source",
    "ag",
    "hfgw",
    NULL
};

struct userdata {
    uint32_t auto_switch;
    bool enable_a2dp_source;
    bool enable_ag;
    pa_hook_slot *source_put_slot;
    pa_hook_slot *sink_put_slot;
    pa_hook_slot *source_output_put_slot;
    pa_hook_slot *source_output_unlink_slot;
    pa_hook_slot *card_init_profile_slot;
    pa_hook_slot *card_unlink_slot;
    pa_hook_slot *profile_available_changed_slot;
    pa_hashmap *profile_switch_map;
};

struct profile_switch {
    const char *from_profile;
    const char *to_profile;
};

/* When a source is created, loopback it to default sink */
static pa_hook_result_t source_put_hook_callback(pa_core *c, pa_source *source, void *userdata) {
    struct userdata *u = userdata;
    const char *s;
    const char *role;
    char *args;
    pa_module *m = NULL;

    pa_assert(c);
    pa_assert(source);

    /* Only consider bluetooth sinks and sources */
    s = pa_proplist_gets(source->proplist, PA_PROP_DEVICE_BUS);
    if (!s)
        return PA_HOOK_OK;

    if (!pa_streq(s, "bluetooth"))
        return PA_HOOK_OK;

    s = pa_proplist_gets(source->proplist, "bluetooth.protocol");
    if (!s)
        return PA_HOOK_OK;

    if (u->enable_a2dp_source && pa_startswith(s, "a2dp_source"))
        role = "music";
    else if (u->enable_ag && (pa_streq(s, "headset_audio_gateway") || pa_streq(s, "handsfree_audio_gateway")))
        role = "phone";
    else {
        pa_log_debug("Profile %s cannot be selected for loopback", s);
        return PA_HOOK_OK;
    }

    /* Load module-loopback */
    args = pa_sprintf_malloc("source=\"%s\" source_dont_move=\"true\" sink_input_properties=\"media.role=%s\"", source->name,
                             role);
    (void) pa_module_load(&m, c, "module-loopback", args);
    pa_xfree(args);

    return PA_HOOK_OK;
}

/* When a sink is created, loopback it to default source */
static pa_hook_result_t sink_put_hook_callback(pa_core *c, pa_sink *sink, void *userdata) {
    struct userdata *u = userdata;
    const char *s;
    const char *role;
    char *args;
    pa_module *m = NULL;

    pa_assert(c);
    pa_assert(sink);

    /* Only consider bluetooth sinks and sources */
    s = pa_proplist_gets(sink->proplist, PA_PROP_DEVICE_BUS);
    if (!s)
        return PA_HOOK_OK;

    if (!pa_streq(s, "bluetooth"))
        return PA_HOOK_OK;

    s = pa_proplist_gets(sink->proplist, "bluetooth.protocol");
    if (!s)
        return PA_HOOK_OK;

    if (u->enable_a2dp_source && pa_startswith(s, "a2dp_source")) /* A2DP source with microphone backchannel */
        role = "music";
    else if (u->enable_ag && (pa_streq(s, "headset_audio_gateway") || pa_streq(s, "handsfree_audio_gateway")))
        role = "phone";
    else {
        pa_log_debug("Profile %s cannot be selected for loopback", s);
        return PA_HOOK_OK;
    }

    /* Load module-loopback */
    args = pa_sprintf_malloc("sink=\"%s\" sink_dont_move=\"true\" source_output_properties=\"media.role=%s\"", sink->name,
                             role);
    (void) pa_module_load(&m, c, "module-loopback", args);
    pa_xfree(args);

    return PA_HOOK_OK;
}

static void card_set_profile(struct userdata *u, pa_card *card, const char *revert_to_profile_name) {
    pa_card_profile *iter_profile;
    pa_card_profile *profile;
    struct profile_switch *ps;
    char *old_profile_name;
    void *state;

    if (revert_to_profile_name) {
        profile = pa_hashmap_get(card->profiles, revert_to_profile_name);
    } else {
        /* Find highest priority profile with both sink and source */
        profile = NULL;
        PA_HASHMAP_FOREACH(iter_profile, card->profiles, state) {
            if (iter_profile->available == PA_AVAILABLE_NO)
                continue;
            if (iter_profile->n_sources == 0 || iter_profile->n_sinks == 0)
                continue;
            if (!profile || profile->priority < iter_profile->priority)
                profile = iter_profile;
        }
    }

    if (!profile) {
        pa_log_warn("Could not find any suitable profile for card '%s'", card->name);
        return;
    }

    old_profile_name = card->active_profile->name;

    pa_log_debug("Setting card '%s' from profile '%s' to profile '%s'", card->name, old_profile_name, profile->name);

    pa_card_set_profile(card, profile, false);

    /* When not reverting, store data for future reverting */
    if (!revert_to_profile_name) {
        ps = pa_xnew0(struct profile_switch, 1);
        ps->from_profile = old_profile_name;
        ps->to_profile = profile->name;
        pa_hashmap_put(u->profile_switch_map, card, ps);
    }
}

/* Switch profile for one card */
static void switch_profile(pa_card *card, bool revert, void *userdata) {
    struct userdata *u = userdata;
    struct profile_switch *ps;
    const char *from_profile;
    const char *to_profile;
    const char *s;

    /* Only consider bluetooth cards */
    s = pa_proplist_gets(card->proplist, PA_PROP_DEVICE_BUS);
    if (!s || !pa_streq(s, "bluetooth"))
        return;

    s = pa_proplist_gets(card->proplist, "bluetooth.protocol");
    if (!s)
        return;

    /* Skip card if is already managed by loopback module loaded from source_put_hook_callback() */
    if ((u->enable_a2dp_source && pa_startswith(s, "a2dp_source")) || /* A2DP source with microphone backchannel */
        (u->enable_ag && (pa_streq(s, "headset_audio_gateway") || pa_streq(s, "handsfree_audio_gateway"))))
        return;

    if (revert) {
        /* In revert phase only consider cards which switched profile */
        if (!(ps = pa_hashmap_remove(u->profile_switch_map, card)))
            return;

        from_profile = ps->from_profile;
        to_profile = ps->to_profile;
        pa_xfree(ps);

        /* Skip card if does not have active profile to which was switched */
        if (!pa_streq(card->active_profile->name, to_profile))
            return;
    } else {
        /* Skip card if already has both sink and source */
        if (card->active_profile->n_sources > 0 && card->active_profile->n_sinks > 0)
            return;
    }

    card_set_profile(u, card, revert ? from_profile : NULL);
}

/* Return true if we should ignore this source output */
static bool ignore_output(pa_source_output *source_output, void *userdata) {
    struct userdata *u = userdata;
    const char *s;

    /* New applications could set media.role for identifying streams */
    /* We are interested only in media.role=phone */
    s = pa_proplist_gets(source_output->proplist, PA_PROP_MEDIA_ROLE);
    if (s)
        return !pa_streq(s, "phone");

    /* If media.role is not set use some heuristic (if enabled) */
    if (u->auto_switch != 2)
        return true;

    /* Ignore if resample method is peaks (used by desktop volume programs) */
    if (pa_source_output_get_resample_method(source_output) == PA_RESAMPLER_PEAKS)
        return true;

    /* Ignore if there is no client/application assigned (used by virtual stream) */
    if (!source_output->client)
        return true;

    /* Ignore if recording from monitor of sink */
    if (source_output->direct_on_input)

    /* Ignore if source output is not movable */
    if (source_output->flags & PA_SOURCE_OUTPUT_DONT_MOVE)
        return true;

    return false;
}

static unsigned source_output_count(pa_core *c, void *userdata) {
    pa_source_output *source_output;
    uint32_t idx;
    unsigned count = 0;

    PA_IDXSET_FOREACH(source_output, c->source_outputs, idx)
        if (!ignore_output(source_output, userdata))
            ++count;

    pa_log_debug("source_output_count=%u", count);

    return count;
}

/* Switch profile for all cards */
static void switch_profile_all(pa_idxset *cards, bool revert, void *userdata) {
    pa_card *card;
    uint32_t idx;

    PA_IDXSET_FOREACH(card, cards, idx)
        switch_profile(card, revert, userdata);
}

/* When the first source output is created, switch profile to some which has both sink and source */
static pa_hook_result_t source_output_put_hook_callback(pa_core *c, pa_source_output *source_output, void *userdata) {
    pa_assert(c);
    pa_assert(source_output);

    pa_log_debug("source_output_put_hook_callback called");

    if (ignore_output(source_output, userdata))
        return PA_HOOK_OK;

    /* If there already were source outputs do nothing */
    if (source_output_count(c, userdata) > 1)
        return PA_HOOK_OK;

    switch_profile_all(c->cards, false, userdata);
    return PA_HOOK_OK;
}

/* When all source outputs are unlinked, switch to previous profile */
static pa_hook_result_t source_output_unlink_hook_callback(pa_core *c, pa_source_output *source_output, void *userdata) {
    pa_assert(c);
    pa_assert(source_output);

    pa_log_debug("source_output_unlink_hook_callback called");

    if (ignore_output(source_output, userdata))
        return PA_HOOK_OK;

    /* If there are still some source outputs do nothing. */
    if (source_output_count(c, userdata) > 0)
        return PA_HOOK_OK;

    switch_profile_all(c->cards, true, userdata);
    return PA_HOOK_OK;
}

static pa_hook_result_t card_init_profile_hook_callback(pa_core *c, pa_card *card, void *userdata) {
    pa_assert(c);
    pa_assert(card);

    /* If there are no source outputs do nothing */
    if (source_output_count(c, userdata) == 0)
        return PA_HOOK_OK;

    /* Set initial profile to some with source */
    switch_profile(card, false, userdata);

    return PA_HOOK_OK;
}

static pa_hook_result_t card_unlink_hook_callback(pa_core *c, pa_card *card, void *userdata) {
    pa_assert(c);
    pa_assert(card);
    switch_profile(card, true, userdata);
    return PA_HOOK_OK;
}

static pa_card_profile *find_best_profile(pa_card *card) {
    void *state;
    pa_card_profile *profile;
    pa_card_profile *result = card->active_profile;

    PA_HASHMAP_FOREACH(profile, card->profiles, state) {
        if (profile->available == PA_AVAILABLE_NO)
            continue;

        if (result == NULL ||
            (profile->available == PA_AVAILABLE_YES && result->available == PA_AVAILABLE_UNKNOWN) ||
            (profile->available == result->available && profile->priority > result->priority))
            result = profile;
    }

    return result;
}

static pa_hook_result_t profile_available_hook_callback(pa_core *c, pa_card_profile *profile, void *userdata) {
    pa_card *card;
    const char *s;
    bool is_active_profile;
    pa_card_profile *selected_profile;

    pa_assert(c);
    pa_assert(profile);
    pa_assert_se((card = profile->card));

    /* Only consider bluetooth cards */
    s = pa_proplist_gets(card->proplist, PA_PROP_DEVICE_BUS);
    if (!s || !pa_streq(s, "bluetooth"))
        return PA_HOOK_OK;

    /* Only consider A2DP sources and auto gateways */
    if (!pa_startswith(profile->name, "a2dp_source") && !pa_streq(s, "headset_audio_gateway") && !pa_streq(s, "handsfree_audio_gateway"))
        return PA_HOOK_OK;

    is_active_profile = card->active_profile == profile;

    if (profile->available == PA_AVAILABLE_YES) {
        if (is_active_profile)
            return PA_HOOK_OK;

        if (card->active_profile->available == PA_AVAILABLE_YES && card->active_profile->priority >= profile->priority)
            return PA_HOOK_OK;

        selected_profile = profile;
    } else {
        if (!is_active_profile)
            return PA_HOOK_OK;

        pa_assert_se((selected_profile = find_best_profile(card)));

        if (selected_profile == card->active_profile)
            return PA_HOOK_OK;
    }

    pa_log_debug("Setting card '%s' to profile '%s'", card->name, selected_profile->name);

    pa_card_set_profile(card, selected_profile, false);

    return PA_HOOK_OK;
}

static void handle_all_profiles(pa_core *core) {
    pa_card *card;
    uint32_t state;

    PA_IDXSET_FOREACH(card, core->cards, state) {
        pa_card_profile *profile;
        void *state2;

        PA_HASHMAP_FOREACH(profile, card->profiles, state2)
            profile_available_hook_callback(core, profile, NULL);
    }
}

int pa__init(pa_module *m) {
    pa_modargs *ma;
    struct userdata *u;

    pa_assert(m);

    if (!(ma = pa_modargs_new(m->argument, valid_modargs))) {
        pa_log_error("Failed to parse module arguments");
        goto fail;
    }

    m->userdata = u = pa_xnew0(struct userdata, 1);

    u->auto_switch = 1;

    if (pa_modargs_get_value(ma, "auto_switch", NULL)) {
        bool auto_switch_bool;

        /* auto_switch originally took a boolean value, let's keep
         * compatibility with configuration files that still pass a boolean. */
        if (pa_modargs_get_value_boolean(ma, "auto_switch", &auto_switch_bool) >= 0) {
            if (auto_switch_bool)
                u->auto_switch = 1;
            else
                u->auto_switch = 0;

        } else if (pa_modargs_get_value_u32(ma, "auto_switch", &u->auto_switch) < 0) {
            pa_log("Failed to parse auto_switch argument.");
            goto fail;
        }
    }

    u->enable_a2dp_source = true;
    if (pa_modargs_get_value_boolean(ma, "a2dp_source", &u->enable_a2dp_source) < 0) {
        pa_log("Failed to parse a2dp_source argument.");
        goto fail;
    }

    u->enable_ag = true;
    if (pa_modargs_get_value_boolean(ma, "ag", &u->enable_ag) < 0) {
        pa_log("Failed to parse ag argument.");
        goto fail;
    }

    u->profile_switch_map = pa_hashmap_new(pa_idxset_trivial_hash_func, pa_idxset_trivial_compare_func);

    u->source_put_slot = pa_hook_connect(&m->core->hooks[PA_CORE_HOOK_SOURCE_PUT], PA_HOOK_NORMAL,
                                         (pa_hook_cb_t) source_put_hook_callback, u);

    u->sink_put_slot = pa_hook_connect(&m->core->hooks[PA_CORE_HOOK_SINK_PUT], PA_HOOK_NORMAL,
                                       (pa_hook_cb_t) sink_put_hook_callback, u);

    if (u->auto_switch) {
        u->source_output_put_slot = pa_hook_connect(&m->core->hooks[PA_CORE_HOOK_SOURCE_OUTPUT_PUT], PA_HOOK_NORMAL,
                                                    (pa_hook_cb_t) source_output_put_hook_callback, u);

        u->source_output_unlink_slot = pa_hook_connect(&m->core->hooks[PA_CORE_HOOK_SOURCE_OUTPUT_UNLINK_POST], PA_HOOK_NORMAL,
                                                       (pa_hook_cb_t) source_output_unlink_hook_callback, u);

        u->card_init_profile_slot = pa_hook_connect(&m->core->hooks[PA_CORE_HOOK_CARD_CHOOSE_INITIAL_PROFILE], PA_HOOK_NORMAL,
                                           (pa_hook_cb_t) card_init_profile_hook_callback, u);

        u->card_unlink_slot = pa_hook_connect(&m->core->hooks[PA_CORE_HOOK_CARD_UNLINK], PA_HOOK_NORMAL,
                                           (pa_hook_cb_t) card_unlink_hook_callback, u);
    }

    u->profile_available_changed_slot = pa_hook_connect(&m->core->hooks[PA_CORE_HOOK_CARD_PROFILE_AVAILABLE_CHANGED],
                                                        PA_HOOK_NORMAL, (pa_hook_cb_t) profile_available_hook_callback, u);

    handle_all_profiles(m->core);

    pa_modargs_free(ma);
    return 0;

fail:
    if (ma)
        pa_modargs_free(ma);
    return -1;
}

void pa__done(pa_module *m) {
    struct userdata *u;

    pa_assert(m);

    if (!(u = m->userdata))
        return;

    if (u->source_put_slot)
        pa_hook_slot_free(u->source_put_slot);

    if (u->sink_put_slot)
        pa_hook_slot_free(u->sink_put_slot);

    if (u->source_output_put_slot)
        pa_hook_slot_free(u->source_output_put_slot);

    if (u->source_output_unlink_slot)
        pa_hook_slot_free(u->source_output_unlink_slot);

    if (u->card_init_profile_slot)
        pa_hook_slot_free(u->card_init_profile_slot);

    if (u->card_unlink_slot)
        pa_hook_slot_free(u->card_unlink_slot);

    if (u->profile_available_changed_slot)
        pa_hook_slot_free(u->profile_available_changed_slot);

    pa_hashmap_free(u->profile_switch_map);

    pa_xfree(u);
}
