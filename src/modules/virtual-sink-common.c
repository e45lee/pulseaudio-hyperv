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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <modules/virtual-sink-common.h>

#include <pulsecore/core-util.h>
#include <pulse/timeval.h>

PA_DEFINE_PRIVATE_CLASS(pa_vsink, pa_msgobject);
#define PA_VSINK(o) (pa_vsink_cast(o))

#define MEMBLOCKQ_MAXLENGTH (16*1024*1024)

#define NO_REWIND_MAX_LATENCY (50 * PA_USEC_PER_MSEC)
#define MIN_BLOCK_SIZE 16

enum {
    SINK_MESSAGE_UPDATE_PARAMETERS = PA_SINK_MESSAGE_MAX
};

enum {
    VSINK_MESSAGE_INPUT_ATTACHED
};

/* Helper functions */

static inline pa_sink_input* get_input_from_sink(pa_sink *s) {

    if (!s->vsink || !s->vsink->input_to_master)
        return NULL;
    return  s->vsink->input_to_master;
}

static int check_block_sizes(size_t fixed_block_frames, size_t fixed_input_block_frames, size_t overlap_frames, pa_sink *s) {
    size_t max_block_frames;

    max_block_frames = pa_frame_align(pa_mempool_block_size_max(s->core->mempool), &s->sample_spec);
    max_block_frames = max_block_frames / pa_frame_size(&s->sample_spec);

    if (fixed_block_frames > max_block_frames || fixed_input_block_frames > max_block_frames || overlap_frames + MIN_BLOCK_SIZE > max_block_frames) {
        pa_log_warn("At least one of fixed_block_size, fixed_input_block_size or overlap_frames exceeds maximum.");
        return -1;
    }

    if (fixed_block_frames > 0 && fixed_block_frames < MIN_BLOCK_SIZE) {
        pa_log_warn("fixed_block_size too small.");
        return -1;
    }

    if (fixed_input_block_frames > 0 && fixed_input_block_frames < MIN_BLOCK_SIZE) {
        pa_log_warn("fixed_input_block_size too small.");
        return -1;
    }

    if (fixed_block_frames + overlap_frames > max_block_frames) {
        pa_log_warn("Sum of fixed_block_size and overlap_frames exceeds maximum.");
        return -1;
    }

    if (fixed_input_block_frames + overlap_frames > max_block_frames) {
        pa_log_warn("Sum of fixed_input_block_size and overlap_frames exceeds maximum.");
        return -1;
    }

    if (fixed_input_block_frames != 0 && fixed_block_frames > fixed_input_block_frames) {
        pa_log_warn("fixed_block_size larger than fixed_input_block_size.");
        return -1;
    }

    return 0;
}

static size_t get_max_rewind_bytes(pa_vsink *vsink, bool use_master_domain) {
    size_t max_rewind_frames, max_rewind_bytes;

    max_rewind_frames = pa_sink_input_get_max_rewind(vsink->input_to_master) / pa_frame_size(&vsink->input_to_master->sample_spec);

    if (vsink->max_rewind < 0)
        max_rewind_frames = 0;
    else if (vsink->max_rewind > 0)
       max_rewind_frames = PA_MIN(max_rewind_frames, (unsigned) vsink->max_rewind);

    if (!use_master_domain)
        return max_rewind_frames * pa_frame_size(&vsink->sink->sample_spec);

    /* Convert to master frames */
    max_rewind_frames = max_rewind_frames * vsink->input_to_master->sink->sample_spec.rate / vsink->sink->sample_spec.rate;

    /* Convert to bytes */
    max_rewind_bytes = max_rewind_frames * pa_frame_size(&vsink->input_to_master->sink->sample_spec);

    return max_rewind_bytes;
}

/* This function is used to ensure that a larger memblockq max_rewind value set
 * by update_max_rewind() for fixed block size filters or by a local version of
 * update_max_rewind() will not be overwritten. */
static void set_memblockq_max_rewind(pa_vsink *vsink) {
    size_t max_rewind;

    if (!vsink->memblockq)
        return;

    max_rewind = PA_MAX(pa_memblockq_get_maxrewind(vsink->memblockq), get_max_rewind_bytes(vsink, false));
    pa_memblockq_set_maxrewind(vsink->memblockq, max_rewind);
}

static void set_latency_range_within_thread(pa_vsink *vsink) {
    pa_usec_t min_latency, max_latency;
    pa_sink_input *i;
    pa_sink *s;

    pa_assert(s = vsink->sink);
    pa_assert(i = vsink->input_to_master);

    min_latency = i->sink->thread_info.min_latency;
    max_latency = i->sink->thread_info.max_latency;

    if (s->flags & PA_SINK_DYNAMIC_LATENCY) {
        if (vsink->max_latency)
            max_latency = PA_MIN(vsink->max_latency, max_latency);

        if (vsink->fixed_block_size) {
            pa_usec_t latency;

            latency = pa_bytes_to_usec(vsink->fixed_block_size * pa_frame_size(&s->sample_spec), &s->sample_spec);
            min_latency = PA_MAX(min_latency, latency);
        }

        max_latency = PA_MAX(max_latency, min_latency);
    }

    pa_sink_set_latency_range_within_thread(s, min_latency, max_latency);
}

/* Sink callbacks */

/* Called from I/O thread context */
int pa_virtual_sink_process_msg(pa_msgobject *o, int code, void *data, int64_t offset, pa_memchunk *chunk) {
    pa_sink_input *i;
    pa_vsink *vsink;
    size_t old_block_size, old_input_block_size, old_overlap_frames;

    pa_sink *s = PA_SINK(o);
    pa_assert_se(vsink = s->vsink);
    pa_assert_se(i = vsink->input_to_master);

    switch (code) {

        case PA_SINK_MESSAGE_GET_LATENCY:

            /* The sink is _put() before the sink input is, so let's
             * make sure we don't access it in that time. Also, the
             * sink input is first shut down, the sink second. */
            if (!PA_SINK_IS_LINKED(s->thread_info.state) ||
                !PA_SINK_INPUT_IS_LINKED(i->thread_info.state)) {
                *((int64_t*) data) = 0;
                return 0;
            }

            *((int64_t*) data) =

                /* Get the latency of the master sink */
                pa_sink_get_latency_within_thread(i->sink, true) +

                /* Add the latency internal to our sink input on top */
                pa_bytes_to_usec(pa_memblockq_get_length(i->thread_info.render_memblockq), &i->sink->sample_spec);

           /* Add the latency caused by the local memblockq */
           if (vsink->memblockq)
               *((int64_t*) data) += pa_bytes_to_usec(pa_memblockq_get_length(vsink->memblockq), &s->sample_spec);

           /* Add the resampler delay */
           if (vsink->input_to_master->thread_info.resampler)
               *((int64_t*) data) += pa_bytes_to_usec(pa_resampler_get_delay(vsink->input_to_master->thread_info.resampler) * pa_frame_size(&i->sample_spec), &i->sample_spec);

           /* Add additional filter latency if required. */
           if (vsink->get_extra_latency)
               *((int64_t*) data) += vsink->get_extra_latency(s);

            return 0;

        case SINK_MESSAGE_UPDATE_PARAMETERS:

        pa_log_debug("Requesting rewind due to parameter update.");

        /* Rewind the stream. If rewinding is disabled, the filter should handle
         * parameter changes without need to rewind the filter. */
        if (vsink->max_rewind >= 0 && PA_SINK_IS_OPENED(s->thread_info.state))
            pa_sink_request_rewind(s, (size_t) -1);

        /* Save old block sizes */
        old_block_size = vsink->fixed_block_size;
        old_input_block_size = vsink->fixed_input_block_size;
        old_overlap_frames = vsink->overlap_frames;

        /* Let the module update the filter parameters. Because the main thread
         * is waiting, variables can be accessed freely in the callback. */
        if (vsink->update_filter_parameters)
            vsink->update_filter_parameters(data, s->userdata);

        /* Updating the parameters may have changed the block sizes, so check them again. */
        if (check_block_sizes(vsink->fixed_block_size, vsink->fixed_input_block_size, vsink->overlap_frames, vsink->sink) < 0) {
            pa_log_warn("Invalid new block sizes, keeping old values.");
            vsink->fixed_block_size = old_block_size;
            vsink->fixed_input_block_size = old_input_block_size;
            vsink->overlap_frames = old_overlap_frames;
        }

        /* Inform the filter of the block sizes in use */
        if (vsink->update_block_sizes)
            vsink->update_block_sizes(vsink->fixed_block_size, vsink->fixed_input_block_size, vsink->overlap_frames, s->userdata);

        /* If the block sizes changed, max_rewind, tlength and latency range may have changed as well. */
        set_latency_range_within_thread(vsink);
        if (i->update_max_rewind)
            i->update_max_rewind(i, pa_sink_input_get_max_rewind(i));
        pa_memblockq_set_tlength(vsink->memblockq, vsink->fixed_block_size * pa_frame_size(&vsink->sink->sample_spec));

        return 0;
    }

    return pa_sink_process_msg(o, code, data, offset, chunk);
}

/* Called from main context */
int pa_virtual_sink_set_state_in_main_thread(pa_sink *s, pa_sink_state_t state, pa_suspend_cause_t suspend_cause) {
    pa_sink_input *i;

    pa_sink_assert_ref(s);
    pa_assert_se(i = get_input_from_sink(s));

    if (!PA_SINK_IS_LINKED(state) ||
        !PA_SINK_INPUT_IS_LINKED(i->state))
        return 0;

    pa_sink_input_cork(i, state == PA_SINK_SUSPENDED);
    return 0;
}

/* Called from the IO thread. */
int pa_virtual_sink_set_state_in_io_thread(pa_sink *s, pa_sink_state_t new_state, pa_suspend_cause_t new_suspend_cause) {
    pa_sink_input *i;
    pa_vsink *vsink;

    pa_sink_assert_ref(s);
    pa_assert_se(vsink = s->vsink);
    pa_assert_se(i = vsink->input_to_master);

    /* When set to running or idle, request a rewind of the master sink to make
     * sure we are heard immediately. Also set max_rewind on sink and master sink */
    if (PA_SINK_IS_OPENED(new_state) && !PA_SINK_IS_OPENED(s->thread_info.state)) {

        pa_log_debug("Requesting rewind due to state change.");
        pa_sink_input_request_rewind(i, 0, false, true, true);

        set_latency_range_within_thread(vsink);

        pa_sink_set_max_rewind_within_thread(s, get_max_rewind_bytes(vsink, false));
        set_memblockq_max_rewind(vsink);
        pa_sink_set_max_rewind_within_thread(i->sink, get_max_rewind_bytes(vsink, true));
    }

    return 0;
}

/* Called from I/O thread context */
void pa_virtual_sink_request_rewind(pa_sink *s) {
    pa_vsink *vsink;
    pa_sink_input *i;
    size_t amount, in_fs, out_fs;

    pa_sink_assert_ref(s);
    pa_assert_se(vsink = s->vsink);
    pa_assert_se(i = vsink->input_to_master);

    if (!PA_SINK_IS_LINKED(s->thread_info.state) ||
        !PA_SINK_INPUT_IS_LINKED(i->thread_info.state))
        return;

    if (vsink->max_rewind < 0) {
        pa_sink_input_request_rewind(i, 0, true, false, false);
        return;
    }

    out_fs = pa_frame_size(&i->sample_spec);
    in_fs = pa_frame_size(&s->sample_spec);

    amount = s->thread_info.rewind_nbytes;
    if (vsink->memblockq)
        amount += pa_memblockq_get_length(vsink->memblockq);

    /* Convert to sink input domain */
    amount  = amount * out_fs / in_fs;

    /* Just hand this one over to the master sink */
    pa_sink_input_request_rewind(i, amount, true, false, false);
}

/* Called from I/O thread context */
void pa_virtual_sink_update_requested_latency(pa_sink *s) {
    pa_vsink *vsink;
    pa_sink_input *i;
    pa_usec_t latency;

    pa_sink_assert_ref(s);
    pa_assert_se(vsink = s->vsink);
    pa_assert_se(i = vsink->input_to_master);

    if (!PA_SINK_IS_LINKED(s->thread_info.state) ||
        !PA_SINK_INPUT_IS_LINKED(i->thread_info.state))
        return;

    latency = pa_sink_get_requested_latency_within_thread(s);
    if (vsink->max_latency)
        latency = PA_MIN(vsink->max_latency, latency);

    if (PA_SINK_IS_OPENED(s->thread_info.state)) {
        pa_log_debug("Requesting rewind due to latency change.");
        pa_sink_request_rewind(s, (size_t) -1);
    }

    /* Just hand this one over to the master sink */
    pa_sink_input_set_requested_latency_within_thread(i, latency);
}

/* Called from main context */
void pa_virtual_sink_set_volume(pa_sink *s) {
    pa_sink_input *i;
    pa_cvolume vol;

    pa_sink_assert_ref(s);
    pa_assert_se(i = get_input_from_sink(s));

    if (!PA_SINK_IS_LINKED(s->state) ||
        !PA_SINK_INPUT_IS_LINKED(i->state))
        return;

    /* Remap the volume, sink and sink input may have different
     * channel counts. */
    vol = s->real_volume;
    pa_cvolume_remap(&vol, &s->channel_map, &i->channel_map);
    pa_sink_input_set_volume(i, &vol, s->save_volume, true);
}

/* Called from main context */
void pa_virtual_sink_set_mute(pa_sink *s) {
    pa_sink_input *i;

    pa_sink_assert_ref(s);
    pa_assert_se(i = get_input_from_sink(s));

    if (!PA_SINK_IS_LINKED(s->state) ||
        !PA_SINK_INPUT_IS_LINKED(i->state))
        return;

    pa_sink_input_set_mute(i, s->muted, s->save_muted);
}

/* Sink iinput callbacks */

/* Called from I/O thread context */
int pa_virtual_sink_input_pop(pa_sink_input *i, size_t nbytes, pa_memchunk *chunk) {
    pa_sink *s;
    float *src, *dst;
    size_t in_fs, out_fs, in_count;
    size_t overlap_frames, max_block_frames;
    unsigned n;
    pa_memchunk tchunk;
    pa_memchunk history_chunk;
    pa_memchunk src_chunk;
    pa_vsink *vsink;

    pa_sink_input_assert_ref(i);
    pa_assert_se(s = i->origin_sink);
    pa_assert_se(vsink = s->vsink);
    pa_assert(chunk);

    if (!PA_SINK_IS_LINKED(s->thread_info.state))
        return -1;

    /* Hmm, process any rewind request that might be queued up */
    pa_sink_process_rewind(s, 0);

    if (!vsink->process_chunk) {
        pa_sink_render(s, nbytes, chunk);
        return 0;
    }

    pa_assert(vsink->memblockq);

    out_fs = pa_frame_size(&i->sample_spec);
    in_fs = pa_frame_size(&s->sample_spec);

    /* Get new samples. */
    if (!vsink->fixed_block_size) {

        while (pa_memblockq_peek(vsink->memblockq, &tchunk) < 0) {
            pa_memchunk nchunk;

            pa_sink_render(s, nbytes * in_fs / out_fs, &nchunk);
            pa_memblockq_push(vsink->memblockq, &nchunk);
            pa_memblock_unref(nchunk.memblock);
        }

        tchunk.length = PA_MIN(nbytes * in_fs / out_fs, tchunk.length);

    } else {
        size_t bytes_missing;

        /* Make sure that the memblockq contains enough data. */
        while ((bytes_missing = pa_memblockq_get_missing(vsink->memblockq)) != 0) {
            pa_memchunk nchunk;

            pa_sink_render(s, bytes_missing, &nchunk);
            pa_memblockq_push(vsink->memblockq, &nchunk);
            pa_memblock_unref(nchunk.memblock);
        }

        pa_memblockq_peek_fixed_size(vsink->memblockq, vsink->fixed_block_size * in_fs, &tchunk);
    }
    pa_assert(tchunk.length > 0);

    n = (unsigned) (PA_MIN(tchunk.length, vsink->max_chunk_size) / in_fs);

    pa_assert(n > 0);

    /* Calculate size of overlap. */
    overlap_frames = vsink->overlap_frames;
    if (vsink->get_current_overlap)
        overlap_frames = PA_MIN(overlap_frames, vsink->get_current_overlap(i));

    if (vsink->fixed_input_block_size) {
        if (n > vsink->fixed_input_block_size)
            n = vsink->fixed_input_block_size;
        else
            overlap_frames += vsink->fixed_input_block_size - n;
    }

    /* In case of variable block size, it may be possible, that the sum of
     * new samples and history data exceeds pa_mempool_block_size_max().
     * Then the number of new samples must be limited. */
    max_block_frames = pa_frame_align(pa_mempool_block_size_max(i->sink->core->mempool), &vsink->sink->sample_spec) / in_fs;
    if (n + overlap_frames > max_block_frames)
        n = max_block_frames - overlap_frames;

    /* Now get some history data if required. */
    if (overlap_frames) {
        size_t overlap_bytes = overlap_frames * in_fs;

        pa_memblockq_rewind(vsink->memblockq, overlap_bytes);
        pa_memblockq_peek_fixed_size(vsink->memblockq, overlap_bytes, &history_chunk);
    }

    chunk->index = 0;
    chunk->length = n * out_fs;
    chunk->memblock = pa_memblock_new(i->sink->core->mempool, chunk->length);

    in_count = n + overlap_frames;
    pa_memblockq_drop(vsink->memblockq, in_count * in_fs);

    src = pa_memblock_acquire_chunk(&tchunk);
    dst = pa_memblock_acquire(chunk->memblock);

    /* If there is some history data, prepend it to the source data. */
    if (overlap_frames) {
        float *new_src, *history;
        size_t nr_history;

        src_chunk.index = 0;
        src_chunk.length = history_chunk.length + tchunk.length;
        src_chunk.memblock = pa_memblock_new(i->sink->core->mempool, src_chunk.length);

        new_src = pa_memblock_acquire(src_chunk.memblock);
        history = pa_memblock_acquire(history_chunk.memblock);
        nr_history = overlap_frames * vsink->sink->sample_spec.channels;
        memcpy(new_src, history, history_chunk.length);
        memcpy(new_src + nr_history, src, tchunk.length);

        pa_memblock_release(tchunk.memblock);
        pa_memblock_unref(tchunk.memblock);
        pa_memblock_release(history_chunk.memblock);
        pa_memblock_unref(history_chunk.memblock);

        tchunk = src_chunk;
        src = new_src;
    }

    /* Let the filter process the chunk */
    vsink->process_chunk(src, dst, in_count, n, i->userdata);

    /* For fixed block size filters, we may have to drop some of the data
     * after a rewind (see pa_virtual_sink_input_process_rewind()). */
    chunk->index += vsink->drop_bytes;
    chunk->length -= vsink->drop_bytes;
    vsink->drop_bytes = 0;

    pa_memblock_release(tchunk.memblock);
    pa_memblock_release(chunk->memblock);

    pa_memblock_unref(tchunk.memblock);

    return 0;
}

/* Called from I/O thread context */
void pa_virtual_sink_input_process_rewind(pa_sink_input *i, size_t nbytes) {
    pa_sink *s;
    size_t amount = 0;
    size_t in_fs, out_fs;
    size_t rewind_frames;
    pa_vsink *vsink;

    pa_sink_input_assert_ref(i);
    pa_assert_se(s = i->origin_sink);
    pa_assert_se(vsink = s->vsink);

    /* If the sink is not yet linked, there is nothing to rewind */
    if (!PA_SINK_IS_LINKED(s->thread_info.state))
        return;

    /* If the sink input is corked, ignore the rewind request. */
    if (i->thread_info.state == PA_SINK_INPUT_CORKED)
        return;

    out_fs = pa_frame_size(&i->sample_spec);
    in_fs = pa_frame_size(&s->sample_spec);
    rewind_frames = nbytes / out_fs;

    /* For fixed block size filters, rewind the filter by a full number of blocks.
     * This means that during the next sink_input_pop() call, the filter will
     * process some old data that must be discarded after processing. */
    if (vsink->fixed_block_size)
        rewind_frames = PA_ROUND_UP(rewind_frames, vsink->fixed_block_size);

    /* Rewind the filter before changing the write pointer of the memblockq.
     * Because the memblockq is placed before the filter, the filter must always
     * be rewound by the full amount. */
    if (vsink->rewind_filter && nbytes > 0 )
        vsink->rewind_filter(s, rewind_frames);

    if ((s->thread_info.rewind_nbytes > 0) && (vsink->max_rewind >= 0)) {
        size_t max_rewrite;

        max_rewrite = nbytes * in_fs / out_fs;
        if (vsink->memblockq)
            max_rewrite += pa_memblockq_get_length(vsink->memblockq);
        amount = PA_MIN(s->thread_info.rewind_nbytes, max_rewrite);
        s->thread_info.rewind_nbytes = 0;

        /* Update write pointer if the data needs to be rewritten. */
        if (vsink->memblockq && amount > 0)
            pa_memblockq_seek(vsink->memblockq, - (int64_t) amount, PA_SEEK_RELATIVE, true);
    }

    pa_sink_process_rewind(s, amount);

    if (vsink->memblockq) {
        pa_memblockq_rewind(vsink->memblockq, rewind_frames * in_fs);

        /* Remember number of bytes to drop during next sink_input_pop(). */
        if (vsink->fixed_block_size)
            vsink->drop_bytes = rewind_frames * out_fs - nbytes;
    }
}

/* Called from I/O thread context */
size_t pa_virtual_sink_input_get_max_rewind_limit(pa_sink_input *i) {
    pa_sink *s;
    pa_vsink *vsink;
    size_t ret, rewind_limit;
    void *state = NULL;

    pa_sink_input_assert_ref(i);
    pa_assert_se(s = i->origin_sink);
    pa_assert_se(vsink = s->vsink);

    ret = (size_t)(-1);

    if (!PA_SINK_IS_OPENED(s->thread_info.state))
        return ret;

    /* Disable rewinding if max_rewind = -1 */
    if (vsink->max_rewind < 0)
        return 0;

    /* If a max_rewind value > 0 was specified, limit rewinding to
     * the specified number of frames */
    if (vsink->max_rewind > 0)
        ret = vsink->max_rewind;

    /* Calculate the number of frames we can rewind in the sink domain. */
    if (ret != (size_t)(-1)) {
        /* Convert to master frames */
        ret = ret * vsink->input_to_master->sink->sample_spec.rate / vsink->sink->sample_spec.rate;

        /* Convert to bytes */
        ret *= pa_frame_size(&vsink->input_to_master->sink->sample_spec);
    }

    /* Get the limit from the attached sink inputs (in vsink sample spec) */
    rewind_limit = (size_t)(-1);
    if (PA_SINK_IS_LINKED(s->thread_info.state)) {
        PA_HASHMAP_FOREACH(i, s->thread_info.inputs, state) {

            if (i->get_max_rewind_limit) {
                size_t limit;

                limit = i->get_max_rewind_limit(i);
                if (rewind_limit == (size_t)(-1) || rewind_limit > limit)
                    rewind_limit = limit;
            }
        }
    }

    if (rewind_limit != (size_t)(-1)) {

        /* Convert to frames */
        rewind_limit = rewind_limit / pa_frame_size(&vsink->sink->sample_spec);

        /* Convert to master frames */
        rewind_limit = rewind_limit * vsink->input_to_master->sink->sample_spec.rate / vsink->sink->sample_spec.rate;

        /* Convert to bytes */
        rewind_limit *= pa_frame_size(&vsink->input_to_master->sink->sample_spec);

        /* Use the minimum of the local and sink input limit */
        if (ret != (size_t)(-1))
            ret = PA_MIN(ret, rewind_limit);
        else
            ret = rewind_limit;
    }

    return ret;
}

/* Called from I/O thread context */
void pa_virtual_sink_input_update_max_rewind(pa_sink_input *i, size_t nbytes) {
    pa_sink *s;
    size_t in_fs, out_fs, max_rewind;
    pa_vsink *vsink;

    pa_sink_input_assert_ref(i);
    pa_assert_se(s = i->origin_sink);
    pa_assert_se(vsink = s->vsink);

    out_fs = pa_frame_size(&i->sample_spec);
    in_fs = pa_frame_size(&s->sample_spec);

    max_rewind = nbytes * in_fs / out_fs;

    if (vsink->memblockq) {
        size_t add_on_bytes = 0;

        /* For fixed block size filters we have to add one block size to
         * max_rewind of the memblockq to ensure we can rewind to a block
         * border, even if a full rewind is requested. */
        if (max_rewind > 0)
            add_on_bytes = vsink->fixed_block_size * in_fs;

        /* Add the history frames. */
        add_on_bytes += vsink->overlap_frames * in_fs;

        /* For fixed input size filters, simply use vsink->fixed_input_block_size */
        if (vsink->fixed_input_block_size)
            add_on_bytes = vsink->fixed_input_block_size * in_fs;

        pa_memblockq_set_maxrewind(vsink->memblockq, max_rewind + add_on_bytes);
    }

    pa_sink_set_max_rewind_within_thread(s, max_rewind);

    if (vsink->set_filter_max_rewind) {

        max_rewind = nbytes / out_fs;
        if (vsink->fixed_block_size)
            max_rewind = PA_ROUND_UP(max_rewind, vsink->fixed_block_size);

        vsink->set_filter_max_rewind(i, max_rewind);
    }
}

/* Called from I/O thread context */
void pa_virtual_sink_input_update_max_request(pa_sink_input *i, size_t nbytes) {
    pa_sink *s;
    size_t in_fs, out_fs, max_request_frames;
    pa_vsink *vsink;

    pa_sink_input_assert_ref(i);
    pa_assert_se(s = i->origin_sink);
    pa_assert_se(vsink = s->vsink);

    out_fs = pa_frame_size(&i->sample_spec);
    in_fs = pa_frame_size(&s->sample_spec);

    max_request_frames = nbytes / out_fs;

    if (vsink->max_request_frames_min)
        max_request_frames = PA_MAX(max_request_frames, vsink->max_request_frames_min);

    /* For a fixed block size filter, round up to the nearest multiple
     * of the block size. */
    if (vsink->fixed_block_size)
        max_request_frames = PA_ROUND_UP(max_request_frames, vsink->fixed_block_size);

    pa_sink_set_max_request_within_thread(s, max_request_frames * in_fs);
}

/* Called from I/O thread context */
void pa_virtual_sink_input_update_sink_latency_range(pa_sink_input *i) {
    pa_sink *s;
    pa_vsink *vsink;

    pa_sink_input_assert_ref(i);
    pa_assert_se(s = i->origin_sink);
    pa_assert_se(vsink = s->vsink);

    set_latency_range_within_thread(vsink);
}

/* Called from I/O thread context */
void pa_virtual_sink_input_update_sink_fixed_latency(pa_sink_input *i) {
    pa_sink *s;
    pa_vsink *vsink;
    pa_usec_t latency;
    size_t in_fs;

    pa_sink_input_assert_ref(i);
    pa_assert_se(s = i->origin_sink);
    pa_assert_se(vsink = s->vsink);

    in_fs = pa_frame_size(&s->sample_spec);

    /* For filters with fixed block size we have to add the block size minus 1 sample
     * to the fixed latency. */
    latency = i->sink->thread_info.fixed_latency;
    if (vsink->fixed_block_size && !(s->flags & PA_SINK_DYNAMIC_LATENCY))
        latency += pa_bytes_to_usec((vsink->fixed_block_size - 1) * in_fs, &s->sample_spec);

    pa_sink_set_fixed_latency_within_thread(s, latency);
}

/* Called from I/O thread context */
void pa_virtual_sink_input_detach(pa_sink_input *i) {
    pa_sink *s;

    pa_sink_input_assert_ref(i);
    pa_assert_se(s = i->origin_sink);

    if (PA_SINK_IS_LINKED(s->thread_info.state))
        pa_sink_detach_within_thread(s);

    pa_sink_set_rtpoll(s, NULL);
}

/* Called from I/O thread context */
void pa_virtual_sink_input_attach(pa_sink_input *i) {
    pa_sink *s;
    pa_vsink *vsink;
    size_t in_fs, out_fs;
    pa_usec_t latency;
    size_t max_request_frames;

    pa_sink_input_assert_ref(i);
    pa_assert_se(s = i->origin_sink);
    pa_assert_se(vsink = s->vsink);

    out_fs = pa_frame_size(&i->sample_spec);
    in_fs = pa_frame_size(&s->sample_spec);

    pa_sink_set_rtpoll(s, i->sink->thread_info.rtpoll);

    set_latency_range_within_thread(vsink);

    /* For filters with fixed block size we have to add the block size minus one
     * sample to the fixed latency. */
    latency = i->sink->thread_info.fixed_latency;
    if (vsink->fixed_block_size && !(s->flags & PA_SINK_DYNAMIC_LATENCY))
        latency += pa_bytes_to_usec((vsink->fixed_block_size - 1) * in_fs, &s->sample_spec);

    pa_sink_set_fixed_latency_within_thread(s, latency);

    max_request_frames = pa_sink_input_get_max_request(i) / out_fs;

    if (vsink->max_request_frames_min)
        max_request_frames = PA_MAX(max_request_frames, vsink->max_request_frames_min);

    /* For filters with fixed block size, round up to the nearest multiple
     * of the block size. */
    if (vsink->fixed_block_size)
        max_request_frames = PA_ROUND_UP(max_request_frames, vsink->fixed_block_size);

    pa_sink_set_max_request_within_thread(s, max_request_frames * in_fs);

    pa_sink_set_max_rewind_within_thread(s, get_max_rewind_bytes(vsink, false));
    set_memblockq_max_rewind(vsink);
    if (PA_SINK_IS_OPENED(s->thread_info.state))
        pa_sink_set_max_rewind_within_thread(i->sink, get_max_rewind_bytes(vsink, true));

    /* This call is needed to remove the UNAVAILABLE suspend cause after
     * a move when the previous master sink disappeared. */
    pa_virtual_sink_send_input_attached_message(vsink);

    if (PA_SINK_IS_LINKED(s->thread_info.state))
        pa_sink_attach_within_thread(s);
}

/* Called from main context */
void pa_virtual_sink_input_kill(pa_sink_input *i) {
    pa_sink *s;
    pa_vsink *vsink;
    pa_module *m;

    pa_sink_input_assert_ref(i);
    pa_assert_se(s = i->origin_sink);
    pa_assert_se(vsink = s->vsink);

    /* The order here matters! We first kill the sink so that streams
     * can properly be moved away while the sink input is still connected
     * to the master. */
    pa_sink_input_cork(i, true);
    pa_sink_unlink(s);
    pa_sink_input_unlink(i);

    pa_sink_input_unref(i);

    if (vsink->memblockq)
        pa_memblockq_free(vsink->memblockq);

    /* Virtual sinks must set the module */
    pa_assert(m = s->module);
    pa_sink_unref(s);

    vsink->sink = NULL;
    vsink->input_to_master = NULL;
    vsink->memblockq = NULL;

    pa_module_unload_request(m, true);
}

/* Called from main context */
bool pa_virtual_sink_input_may_move_to(pa_sink_input *i, pa_sink *dest) {
    pa_sink *s;
    pa_vsink *vsink;

    pa_sink_input_assert_ref(i);
    pa_assert_se(s = i->origin_sink);
    pa_assert_se(vsink = s->vsink);

    if (vsink->autoloaded)
        return false;

    return s != dest;
}

/* Called from main context */
void pa_virtual_sink_input_moving(pa_sink_input *i, pa_sink *dest) {
    pa_sink *s;
    pa_vsink *vsink;
    uint32_t idx;
    pa_sink_input *input;

    pa_sink_input_assert_ref(i);
    pa_assert_se(s = i->origin_sink);
    pa_assert_se(vsink = s->vsink);

    if (dest) {
        pa_sink_set_asyncmsgq(s, dest->asyncmsgq);
        pa_sink_update_flags(s, PA_SINK_LATENCY|PA_SINK_DYNAMIC_LATENCY, dest->flags);
        pa_proplist_sets(s->proplist, PA_PROP_DEVICE_MASTER_DEVICE, dest->name);
    } else
        pa_sink_set_asyncmsgq(s, NULL);

    if (dest && vsink->set_description)
        vsink->set_description(i, dest);

    else {
        if (vsink->auto_desc && dest) {
            const char *z;
            pa_proplist *pl;
            char *proplist_name;

            pl = pa_proplist_new();
            proplist_name = pa_sprintf_malloc("device.%s.name", vsink->sink_type);
            z = pa_proplist_gets(dest->proplist, PA_PROP_DEVICE_DESCRIPTION);
            pa_proplist_setf(pl, PA_PROP_DEVICE_DESCRIPTION, "%s %s on %s", vsink->desc_head,
                             pa_proplist_gets(s->proplist, proplist_name), z ? z : dest->name);

            pa_sink_update_proplist(s, PA_UPDATE_REPLACE, pl);
            pa_proplist_free(pl);
            pa_xfree(proplist_name);
        }

        if (dest)
            pa_proplist_setf(i->proplist, PA_PROP_MEDIA_NAME, "%s Stream from %s", vsink->desc_head, pa_proplist_gets(s->proplist, PA_PROP_DEVICE_DESCRIPTION));
    }

    /* Propagate asyncmsq change to attached virtual sinks */
    PA_IDXSET_FOREACH(input, s->inputs, idx) {
        if (input->origin_sink && input->moving)
            input->moving(input, s);
    }

    /* Propagate asyncmsq change to virtual sources attached to the monitor */
    if (s->monitor_source) {
        pa_source_output *output;

        PA_IDXSET_FOREACH(output, s->monitor_source->outputs, idx) {
            if (output->destination_source && output->moving)
                output->moving(output, s->monitor_source);
        }
    }
}

/* Called from main context */
void pa_virtual_sink_input_volume_changed(pa_sink_input *i) {
    pa_sink *s;
    pa_cvolume vol;

    pa_sink_input_assert_ref(i);
    pa_assert_se(s = i->origin_sink);

    /* Remap the volume, sink and sink input may have different
     * channel counts. */
    vol = i->volume;
    pa_cvolume_remap(&vol, &i->channel_map, &s->channel_map);
    pa_sink_volume_changed(s, &vol);
}

/* Called from main context */
void pa_virtual_sink_input_mute_changed(pa_sink_input *i) {
    pa_sink *s;

    pa_sink_input_assert_ref(i);
    pa_assert_se(s = i->origin_sink);

    pa_sink_mute_changed(s, i->muted);
}

/* Called from main context */
void pa_virtual_sink_input_suspend(pa_sink_input *i, pa_sink_state_t old_state, pa_suspend_cause_t old_suspend_cause) {
    pa_sink *s;

    pa_sink_input_assert_ref(i);
    pa_assert_se(s = i->origin_sink);

    if (i->sink->state != PA_SINK_SUSPENDED || i->sink->suspend_cause == PA_SUSPEND_IDLE)
        pa_sink_suspend(s, false, PA_SUSPEND_UNAVAILABLE);
    else
        pa_sink_suspend(s, true, PA_SUSPEND_UNAVAILABLE);
}

/* Other functions */

void pa_virtual_sink_set_callbacks(pa_sink *s, bool use_volume_sharing) {

    s->parent.process_msg = pa_virtual_sink_process_msg;
    s->set_state_in_main_thread = pa_virtual_sink_set_state_in_main_thread;
    s->set_state_in_io_thread = pa_virtual_sink_set_state_in_io_thread;
    s->update_requested_latency = pa_virtual_sink_update_requested_latency;
    s->request_rewind = pa_virtual_sink_request_rewind;
    pa_sink_set_set_mute_callback(s, pa_virtual_sink_set_mute);
    if (!use_volume_sharing) {
        pa_sink_set_set_volume_callback(s, pa_virtual_sink_set_volume);
        pa_sink_enable_decibel_volume(s, true);
    }
}

void pa_virtual_sink_input_set_callbacks(pa_sink_input *i, bool use_volume_sharing) {

    i->pop = pa_virtual_sink_input_pop;
    i->process_rewind = pa_virtual_sink_input_process_rewind;
    i->update_max_rewind = pa_virtual_sink_input_update_max_rewind;
    i->update_max_request = pa_virtual_sink_input_update_max_request;
    i->update_sink_latency_range = pa_virtual_sink_input_update_sink_latency_range;
    i->update_sink_fixed_latency = pa_virtual_sink_input_update_sink_fixed_latency;
    i->kill = pa_virtual_sink_input_kill;
    i->attach = pa_virtual_sink_input_attach;
    i->detach = pa_virtual_sink_input_detach;
    i->may_move_to = pa_virtual_sink_input_may_move_to;
    i->moving = pa_virtual_sink_input_moving;
    i->volume_changed = use_volume_sharing ? NULL : pa_virtual_sink_input_volume_changed;
    i->mute_changed = pa_virtual_sink_input_mute_changed;
    i->suspend = pa_virtual_sink_input_suspend;
    i->get_max_rewind_limit = pa_virtual_sink_input_get_max_rewind_limit;
}

static int vsink_process_msg(pa_msgobject *o, int code, void *userdata, int64_t offset, pa_memchunk *chunk) {
    pa_vsink *vsink;
    pa_sink *s;
    pa_sink_input *i;

    pa_assert(o);
    pa_assert_ctl_context();

    vsink = PA_VSINK(o);

    switch (code) {

        case VSINK_MESSAGE_INPUT_ATTACHED:

            pa_assert(s = vsink->sink);
            pa_assert(i = vsink->input_to_master);

            if (PA_SINK_IS_LINKED(s->state)) {
                if (i->sink->state != PA_SINK_SUSPENDED || i->sink->suspend_cause == PA_SUSPEND_IDLE)
                    pa_sink_suspend(s, false, PA_SUSPEND_UNAVAILABLE);
                else
                    pa_sink_suspend(s, true, PA_SUSPEND_UNAVAILABLE);
            }
            return 0;
    }
    return 0;
}

int pa_virtual_sink_activate(pa_vsink *vs) {

    pa_assert(vs);
    pa_assert(vs->sink);
    pa_assert(vs->input_to_master);

    /* Check that block sizes are plausible */
    if (check_block_sizes(vs->fixed_block_size, vs->fixed_input_block_size, vs->overlap_frames, vs->sink) < 0) {
        pa_log_warn("Invalid block sizes.");
        return -1;
    }

    /* For fixed block size filters, set the target length of the memblockq */
    if (vs->memblockq && vs->fixed_block_size)
        pa_memblockq_set_tlength(vs->memblockq, vs->fixed_block_size * pa_frame_size(&vs->sink->sample_spec));

    /* Set sink input latency at startup to max_latency if specified. */
    if (vs->max_latency)
        pa_sink_input_set_requested_latency(vs->input_to_master, vs->max_latency);

    /* Set sink max_rewind on master sink. */
    pa_sink_set_max_rewind(vs->input_to_master->sink, get_max_rewind_bytes(vs, true));

    /* The order here is important. The input must be put first,
     * otherwise streams might attach to the sink before the sink
     * input is attached to the master. */
    pa_sink_input_put(vs->input_to_master);
    pa_sink_put(vs->sink);
    pa_sink_input_cork(vs->input_to_master, false);

    return 0;
}

void pa_virtual_sink_destroy(pa_vsink *vs) {

    pa_assert(vs);

    /* See comments in sink_input_kill() above regarding
     * destruction order! */
    if (vs->input_to_master && PA_SINK_INPUT_IS_LINKED(vs->input_to_master->state))
        pa_sink_input_cork(vs->input_to_master, true);

    if (vs->sink)
        pa_sink_unlink(vs->sink);

    if (vs->input_to_master) {
        pa_sink_input_unlink(vs->input_to_master);
        pa_sink_input_unref(vs->input_to_master);
    }

    if (vs->memblockq)
        pa_memblockq_free(vs->memblockq);

    if (vs->sink)
        pa_sink_unref(vs->sink);

    pa_xfree(vs);
}

/* Manually create a vsink structure. */
pa_vsink* pa_virtual_sink_vsink_new(pa_sink *s, int max_rewind) {
    pa_vsink *vsink;

    pa_assert(s);

    /* Create new vsink */
    vsink = pa_msgobject_new(pa_vsink);
    vsink->parent.process_msg = vsink_process_msg;

    vsink->sink = s;
    s->vsink = vsink;

    /* Reset virtual sink parameters */
    vsink->input_to_master = NULL;
    vsink->memblockq = NULL;
    vsink->auto_desc = false;
    vsink->desc_head = "Unknown Sink";
    vsink->sink_type = "unknown";
    vsink->autoloaded = false;
    vsink->max_chunk_size = pa_frame_align(pa_mempool_block_size_max(s->core->mempool), &s->sample_spec);
    vsink->fixed_block_size = 0;
    vsink->fixed_input_block_size = 0;
    vsink->overlap_frames = 0;
    vsink->drop_bytes = 0;
    vsink->max_request_frames_min = 0;
    vsink->max_latency = 0;
    vsink->max_rewind = max_rewind;
    vsink->rewind_filter = NULL;
    vsink->process_chunk = NULL;
    vsink->get_extra_latency = NULL;
    vsink->set_description = NULL;
    vsink->update_filter_parameters = NULL;
    vsink->update_block_sizes = NULL;

    /* If rewinding is disabled, limit latency to NO_REWIND_MAX_LATENCY.
     * If max_rewind is given, use the maximum of NO_REWIND_MAX_LATENCY
     * and max_rewind, else use maximum latency from master sink. */
    if (max_rewind < 0)
        vsink->max_latency = NO_REWIND_MAX_LATENCY;
    else if (max_rewind > 0) {
        vsink->max_latency = max_rewind * PA_USEC_PER_SEC / s->sample_spec.rate;
        vsink->max_latency = PA_MAX(vsink->max_latency, NO_REWIND_MAX_LATENCY);
    }

    return vsink;
}

pa_vsink *pa_virtual_sink_create(pa_sink *master, const char *sink_type, const char *desc_prefix,
                                 pa_sample_spec *sink_ss, pa_channel_map *sink_map,
                                 pa_sample_spec *sink_input_ss, pa_channel_map *sink_input_map,
                                 pa_module *m, void *userdata, pa_modargs *ma,
                                 bool use_volume_sharing, bool create_memblockq,
                                 int max_rewind) {

    pa_sink_input_new_data sink_input_data;
    pa_sink_new_data sink_data;
    char *sink_type_property;
    bool auto_desc;
    bool force_flat_volume = false;
    bool remix = true;
    pa_resample_method_t resample_method = PA_RESAMPLER_INVALID;
    pa_vsink *vsink;
    pa_sink *s;
    pa_sink_input *i;

    /* Make sure all necessary values are set. Only userdata and sink_name
     * are allowed to be NULL. */
    pa_assert(master);
    pa_assert(sink_ss);
    pa_assert(sink_map);
    pa_assert(sink_input_ss);
    pa_assert(sink_input_map);
    pa_assert(m);
    pa_assert(ma);

    /* We do not support resampling in filters */
    pa_assert(sink_input_ss->rate == sink_ss->rate);

    if (!sink_type)
        sink_type = "unknown";
    if (!desc_prefix)
        desc_prefix = "Unknown Sink";

    /* Get some command line arguments. Because there is no common default
     * for use_volume_sharing, this value must be passed as argument to
     * pa_virtual_sink_create(). */

    if (pa_modargs_get_value_boolean(ma, "force_flat_volume", &force_flat_volume) < 0) {
        pa_log("force_flat_volume= expects a boolean argument");
        return NULL;
    }

    if (use_volume_sharing && force_flat_volume) {
        pa_log("Flat volume can't be forced when using volume sharing.");
        return NULL;
    }

    if (pa_modargs_get_value_boolean(ma, "remix", &remix) < 0) {
        pa_log("Invalid boolean remix parameter");
        return NULL;
    }

    if (pa_modargs_get_resample_method(ma, &resample_method) < 0) {
        pa_log("Invalid resampling method");
        return NULL;
    }

    /* Create sink */
    pa_sink_new_data_init(&sink_data);
    sink_data.driver = m->name;
    sink_data.module = m;
    if (!(sink_data.name = pa_xstrdup(pa_modargs_get_value(ma, "sink_name", NULL))))
        sink_data.name = pa_sprintf_malloc("%s.%s", master->name, sink_type);
    pa_sink_new_data_set_sample_spec(&sink_data, sink_ss);
    pa_sink_new_data_set_channel_map(&sink_data, sink_map);
    pa_proplist_sets(sink_data.proplist, PA_PROP_DEVICE_MASTER_DEVICE, master->name);
    pa_proplist_sets(sink_data.proplist, PA_PROP_DEVICE_CLASS, "filter");

    if (pa_modargs_get_proplist(ma, "sink_properties", sink_data.proplist, PA_UPDATE_REPLACE) < 0) {
        pa_log("Invalid sink properties");
        pa_sink_new_data_done(&sink_data);
        return NULL;
    }

    s = pa_sink_new(m->core, &sink_data, (master->flags & (PA_SINK_LATENCY|PA_SINK_DYNAMIC_LATENCY))
                                               | (use_volume_sharing ? PA_SINK_SHARE_VOLUME_WITH_MASTER : 0));
    pa_sink_new_data_done(&sink_data);

    if (!s) {
        pa_log("Failed to create sink.");
        return NULL;
    }

    /* Set name and description properties after the sink has been created,
     * otherwise they may be duplicate. */
    if ((auto_desc = !pa_proplist_contains(s->proplist, PA_PROP_DEVICE_DESCRIPTION))) {
        const char *z;

        z = pa_proplist_gets(master->proplist, PA_PROP_DEVICE_DESCRIPTION);
        pa_proplist_setf(s->proplist, PA_PROP_DEVICE_DESCRIPTION, "%s %s on %s", desc_prefix, s->name, z ? z : master->name);
    }

    sink_type_property = pa_sprintf_malloc("device.%s.name", sink_type);
    pa_proplist_sets(s->proplist, sink_type_property, s->name);
    pa_xfree(sink_type_property);

    /* Create vsink structure. */
    vsink = pa_virtual_sink_vsink_new(s, max_rewind);

    pa_virtual_sink_set_callbacks(s, use_volume_sharing);
    vsink->auto_desc = auto_desc;
    vsink->desc_head = desc_prefix;
    vsink->sink_type = sink_type;

    /* Normally this flag would be enabled automatically be we can force it. */
    if (force_flat_volume)
        s->flags |= PA_SINK_FLAT_VOLUME;
    s->userdata = userdata;

    pa_sink_set_asyncmsgq(s, master->asyncmsgq);

    /* Create sink input */
    pa_sink_input_new_data_init(&sink_input_data);
    sink_input_data.driver = __FILE__;
    sink_input_data.module = m;
    pa_sink_input_new_data_set_sink(&sink_input_data, master, false, true);
    sink_input_data.origin_sink = s;
    pa_proplist_setf(sink_input_data.proplist, PA_PROP_MEDIA_NAME, "%s Stream from %s", desc_prefix, pa_proplist_gets(s->proplist, PA_PROP_DEVICE_DESCRIPTION));
    pa_proplist_sets(sink_input_data.proplist, PA_PROP_MEDIA_ROLE, "filter");
    pa_sink_input_new_data_set_sample_spec(&sink_input_data, sink_input_ss);
    pa_sink_input_new_data_set_channel_map(&sink_input_data, sink_input_map);
    sink_input_data.resample_method = resample_method;
    sink_input_data.flags = (remix ? 0 : PA_SINK_INPUT_NO_REMIX) | PA_SINK_INPUT_START_CORKED;

    if (pa_modargs_get_proplist(ma, "sink_input_properties", sink_input_data.proplist, PA_UPDATE_REPLACE) < 0) {
        pa_log("Invalid sink input properties");
        pa_sink_input_new_data_done(&sink_input_data);
        pa_virtual_sink_destroy(vsink);
        return NULL;
    }

    pa_sink_input_new(&i, m->core, &sink_input_data);
    pa_sink_input_new_data_done(&sink_input_data);

    if (!i) {
        pa_log("Could not create sink-input");
        pa_virtual_sink_destroy(vsink);
        return NULL;
    }

    pa_virtual_sink_input_set_callbacks(i, use_volume_sharing);
    i->userdata = userdata;

    vsink->input_to_master = i;

    vsink->autoloaded = false;
    if (pa_modargs_get_value_boolean(ma, "autoloaded", &vsink->autoloaded) < 0) {
        pa_log("Failed to parse autoloaded value");
        pa_virtual_sink_destroy(vsink);
        return NULL;
    }

    if (create_memblockq) {
        char *tmp;
        pa_memchunk silence;

        tmp = pa_sprintf_malloc("%s memblockq", desc_prefix);
        pa_sink_input_get_silence(i, &silence);
        vsink->memblockq = pa_memblockq_new(tmp, 0, MEMBLOCKQ_MAXLENGTH, 0, sink_ss, 1, 1, 0, &silence);
        pa_memblock_unref(silence.memblock);
        pa_xfree(tmp);
    }

    return vsink;
}

/* Send request to update filter parameters to the I/O-thread. */
void pa_virtual_sink_request_parameter_update(pa_vsink *vs, void *parameters) {

    pa_assert(vs);
    pa_assert(vs->sink);

    /* parameters may be NULL if it is enough to have access to userdata from the
     * callback. */
    pa_asyncmsgq_send(vs->sink->asyncmsgq, PA_MSGOBJECT(vs->sink), SINK_MESSAGE_UPDATE_PARAMETERS, parameters, 0, NULL);
}

/* Called from I/O context. This is needed as a separate function
 * because module-echo-cancel has to send the message from
 * sink_input_attach_cb(). */
void pa_virtual_sink_send_input_attached_message(pa_vsink *vs) {
    pa_asyncmsgq_post(pa_thread_mq_get()->outq, PA_MSGOBJECT(vs), VSINK_MESSAGE_INPUT_ATTACHED, NULL, 0, NULL, NULL);
}
