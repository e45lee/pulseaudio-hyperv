/***
  This file is part of PulseAudio.

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

#include <pulsecore/sink.h>
#include <pulsecore/modargs.h>

/* Callbacks for virtual sinks. */
int pa_virtual_sink_process_msg(pa_msgobject *o, int code, void *data, int64_t offset, pa_memchunk *chunk);

int pa_virtual_sink_set_state_in_main_thread(pa_sink *s, pa_sink_state_t state, pa_suspend_cause_t suspend_cause);
int pa_virtual_sink_set_state_in_io_thread(pa_sink *s, pa_sink_state_t new_state, pa_suspend_cause_t new_suspend_cause);

void pa_virtual_sink_request_rewind(pa_sink *s);
void pa_virtual_sink_update_requested_latency(pa_sink *s);
void pa_virtual_sink_set_volume(pa_sink *s);
void pa_virtual_sink_set_mute(pa_sink *s);

int pa_virtual_sink_input_pop(pa_sink_input *i, size_t nbytes, pa_memchunk *chunk);

void pa_virtual_sink_input_process_rewind(pa_sink_input *i, size_t nbytes);
void pa_virtual_sink_input_update_max_rewind(pa_sink_input *i, size_t nbytes);
void pa_virtual_sink_input_update_max_request(pa_sink_input *i, size_t nbytes);
void pa_virtual_sink_input_update_sink_latency_range(pa_sink_input *i);
void pa_virtual_sink_input_update_sink_fixed_latency(pa_sink_input *i);

void pa_virtual_sink_input_detach(pa_sink_input *i);
void pa_virtual_sink_input_attach(pa_sink_input *i);
void pa_virtual_sink_input_kill(pa_sink_input *i);
void pa_virtual_sink_input_moving(pa_sink_input *i, pa_sink *dest);
bool pa_virtual_sink_input_may_move_to(pa_sink_input *i, pa_sink *dest);
size_t pa_virtual_sink_input_get_max_rewind_limit(pa_sink_input *i);

void pa_virtual_sink_input_volume_changed(pa_sink_input *i);
void pa_virtual_sink_input_mute_changed(pa_sink_input *i);

void pa_virtual_sink_input_suspend(pa_sink_input *i, pa_sink_state_t old_state, pa_suspend_cause_t old_suspend_cause);

/* Set callbacks for virtual sink and sink input. */
void pa_virtual_sink_set_callbacks(pa_sink *s, bool use_volume_sharing);
void pa_virtual_sink_input_set_callbacks(pa_sink_input *i, bool use_volume_sharing);

/* Create a new virtual sink. Returns a filled vsink structure or NULL on failure. */
pa_vsink *pa_virtual_sink_create(pa_sink *master, const char *sink_type, const char *desc_prefix,
                                 pa_sample_spec *sink_ss, pa_channel_map *sink_map,
                                 pa_sample_spec *sink_input_ss, pa_channel_map *sink_input_map,
                                 pa_module *m, void *userdata, pa_modargs *ma,
                                 bool use_volume_sharing, bool create_memblockq,
                                 int max_rewind);

/* Activate the new virtual sink. */
int pa_virtual_sink_activate(pa_vsink *vs);

/* Destroys the objects associated with the virtual sink. */
void pa_virtual_sink_destroy(pa_vsink *vs);

/* Create vsink structure */
pa_vsink* pa_virtual_sink_vsink_new(pa_sink *s, int max_rewind);

/* Update filter parameters */
void pa_virtual_sink_request_parameter_update(pa_vsink *vs, void *parameters);

/* Send sink input attached message (only needed for module-echo-cancel) */
void pa_virtual_sink_send_input_attached_message(pa_vsink *vs);
