/***
  This file is part of PulseAudio.

  Copyright 2008-2013 João Paulo Rechi Vita
  Copyright 2011-2013 BMW Car IT GmbH.
  Copyright 2018-2019 Pali Rohár <pali.rohar@gmail.com>

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

#include <arpa/inet.h>

#include <pulse/rtclock.h>
#include <pulse/timeval.h>
#include <pulse/utf8.h>
#include <pulse/util.h>

#include <pulsecore/core-error.h>
#include <pulsecore/core-rtclock.h>
#include <pulsecore/core-util.h>
#include <pulsecore/i18n.h>
#include <pulsecore/module.h>
#include <pulsecore/modargs.h>
#include <pulsecore/poll.h>
#include <pulsecore/rtpoll.h>
#include <pulsecore/shared.h>
#include <pulsecore/socket-util.h>
#include <pulsecore/thread.h>
#include <pulsecore/thread-mq.h>
#include <pulsecore/time-smoother.h>

#include "a2dp-codecs.h"
#include "a2dp-codec-util.h"
#include "bluez5-util.h"

PA_MODULE_AUTHOR("João Paulo Rechi Vita");
PA_MODULE_DESCRIPTION("BlueZ 5 Bluetooth audio sink and source");
PA_MODULE_VERSION(PACKAGE_VERSION);
PA_MODULE_LOAD_ONCE(false);
PA_MODULE_USAGE("path=<device object path>");

#define FIXED_LATENCY_PLAYBACK_A2DP (25 * PA_USEC_PER_MSEC)
#define FIXED_LATENCY_PLAYBACK_SCO  (25 * PA_USEC_PER_MSEC)
#define FIXED_LATENCY_RECORD_A2DP   (25 * PA_USEC_PER_MSEC)
#define FIXED_LATENCY_RECORD_SCO    (25 * PA_USEC_PER_MSEC)

static const char* const valid_modargs[] = {
    "path",
    NULL
};

enum {
    BLUETOOTH_MESSAGE_IO_THREAD_FAILED,
    BLUETOOTH_MESSAGE_STREAM_FD_HUP,
    BLUETOOTH_MESSAGE_SET_TRANSPORT_PLAYING,
    BLUETOOTH_MESSAGE_MAX
};

enum {
    PA_SOURCE_MESSAGE_SETUP_STREAM = PA_SOURCE_MESSAGE_MAX,
};

enum {
    PA_SINK_MESSAGE_SETUP_STREAM = PA_SINK_MESSAGE_MAX,
};

typedef struct bluetooth_msg {
    pa_msgobject parent;
    pa_card *card;
} bluetooth_msg;
PA_DEFINE_PRIVATE_CLASS(bluetooth_msg, pa_msgobject);
#define BLUETOOTH_MSG(o) (bluetooth_msg_cast(o))

struct userdata {
    pa_module *module;
    pa_core *core;

    pa_hook_slot *device_connection_changed_slot;
    pa_hook_slot *profile_connection_changed_slot;
    pa_hook_slot *transport_state_changed_slot;
    pa_hook_slot *transport_rx_volume_gain_changed_slot;
    pa_hook_slot *transport_tx_volume_gain_changed_slot;

    pa_bluetooth_discovery *discovery;
    pa_bluetooth_device *device;
    pa_bluetooth_transport *transport;
    bool transport_acquired;
    bool stream_setup_done;

    pa_card *card;
    pa_sink *sink;
    pa_source *source;
    pa_bluetooth_profile_t profile;
    char *output_port_name;
    char *input_port_name;

    pa_thread *thread;
    pa_thread_mq thread_mq;
    pa_rtpoll *rtpoll;
    pa_rtpoll_item *rtpoll_item;
    bluetooth_msg *msg;

    int stream_fd;
    int stream_write_type;
    size_t read_link_mtu;
    size_t write_link_mtu;
    size_t read_block_size;
    size_t write_block_size;
    uint64_t read_index;
    uint64_t write_index;
    pa_usec_t started_at;
    pa_smoother *read_smoother;
    pa_memchunk write_memchunk;
    bool support_a2dp_codec_switch;

    void *encoder_info;
    void *encoder_backchannel_info;
    pa_sample_spec encoder_sample_spec;
    void *encoder_buffer;                        /* Codec transfer buffer */
    size_t encoder_buffer_size;                  /* Size of the buffer */

    void *decoder_info;
    void *decoder_backchannel_info;
    pa_sample_spec decoder_sample_spec;
    void *decoder_buffer;                        /* Codec transfer buffer */
    size_t decoder_buffer_size;                  /* Size of the buffer */
};

typedef enum pa_bluetooth_form_factor {
    PA_BLUETOOTH_FORM_FACTOR_UNKNOWN,
    PA_BLUETOOTH_FORM_FACTOR_HEADSET,
    PA_BLUETOOTH_FORM_FACTOR_HANDSFREE,
    PA_BLUETOOTH_FORM_FACTOR_MICROPHONE,
    PA_BLUETOOTH_FORM_FACTOR_SPEAKER,
    PA_BLUETOOTH_FORM_FACTOR_HEADPHONE,
    PA_BLUETOOTH_FORM_FACTOR_PORTABLE,
    PA_BLUETOOTH_FORM_FACTOR_CAR,
    PA_BLUETOOTH_FORM_FACTOR_HIFI,
    PA_BLUETOOTH_FORM_FACTOR_PHONE,
} pa_bluetooth_form_factor_t;

/* Run from main thread */
static pa_bluetooth_form_factor_t form_factor_from_class(uint32_t class_of_device) {
    unsigned major, minor;
    pa_bluetooth_form_factor_t r;

    static const pa_bluetooth_form_factor_t table[] = {
        [1] = PA_BLUETOOTH_FORM_FACTOR_HEADSET,
        [2] = PA_BLUETOOTH_FORM_FACTOR_HANDSFREE,
        [4] = PA_BLUETOOTH_FORM_FACTOR_MICROPHONE,
        [5] = PA_BLUETOOTH_FORM_FACTOR_SPEAKER,
        [6] = PA_BLUETOOTH_FORM_FACTOR_HEADPHONE,
        [7] = PA_BLUETOOTH_FORM_FACTOR_PORTABLE,
        [8] = PA_BLUETOOTH_FORM_FACTOR_CAR,
        [10] = PA_BLUETOOTH_FORM_FACTOR_HIFI
    };

    /*
     * See Bluetooth Assigned Numbers:
     * https://www.bluetooth.org/Technical/AssignedNumbers/baseband.htm
     */
    major = (class_of_device >> 8) & 0x1F;
    minor = (class_of_device >> 2) & 0x3F;

    switch (major) {
        case 2:
            return PA_BLUETOOTH_FORM_FACTOR_PHONE;
        case 4:
            break;
        default:
            pa_log_debug("Unknown Bluetooth major device class %u", major);
            return PA_BLUETOOTH_FORM_FACTOR_UNKNOWN;
    }

    r = minor < PA_ELEMENTSOF(table) ? table[minor] : PA_BLUETOOTH_FORM_FACTOR_UNKNOWN;

    if (!r)
        pa_log_debug("Unknown Bluetooth minor device class %u", minor);

    return r;
}

/* Run from main thread */
static const char *form_factor_to_string(pa_bluetooth_form_factor_t ff) {
    switch (ff) {
        case PA_BLUETOOTH_FORM_FACTOR_UNKNOWN:
            return "unknown";
        case PA_BLUETOOTH_FORM_FACTOR_HEADSET:
            return "headset";
        case PA_BLUETOOTH_FORM_FACTOR_HANDSFREE:
            return "hands-free";
        case PA_BLUETOOTH_FORM_FACTOR_MICROPHONE:
            return "microphone";
        case PA_BLUETOOTH_FORM_FACTOR_SPEAKER:
            return "speaker";
        case PA_BLUETOOTH_FORM_FACTOR_HEADPHONE:
            return "headphone";
        case PA_BLUETOOTH_FORM_FACTOR_PORTABLE:
            return "portable";
        case PA_BLUETOOTH_FORM_FACTOR_CAR:
            return "car";
        case PA_BLUETOOTH_FORM_FACTOR_HIFI:
            return "hifi";
        case PA_BLUETOOTH_FORM_FACTOR_PHONE:
            return "phone";
    }

    pa_assert_not_reached();
}

/* Run from main thread */
static void connect_ports(struct userdata *u, void *new_data, pa_direction_t direction) {
    pa_device_port *port;

    if (direction == PA_DIRECTION_OUTPUT) {
        pa_sink_new_data *sink_new_data = new_data;

        pa_assert_se(port = pa_hashmap_get(u->card->ports, u->output_port_name));
        pa_assert_se(pa_hashmap_put(sink_new_data->ports, port->name, port) >= 0);
        pa_device_port_ref(port);
    } else {
        pa_source_new_data *source_new_data = new_data;

        pa_assert_se(port = pa_hashmap_get(u->card->ports, u->input_port_name));
        pa_assert_se(pa_hashmap_put(source_new_data->ports, port->name, port) >= 0);
        pa_device_port_ref(port);
    }
}

/* Run from IO thread */
static int sco_process_render(struct userdata *u) {
    ssize_t l;
    pa_memchunk memchunk;
    int saved_errno;

    pa_assert(u);
    pa_assert(u->profile == PA_BLUETOOTH_PROFILE_HSP_HEAD_UNIT ||
              u->profile == PA_BLUETOOTH_PROFILE_HFP_HEAD_UNIT ||
              u->profile == PA_BLUETOOTH_PROFILE_HSP_AUDIO_GATEWAY ||
              u->profile == PA_BLUETOOTH_PROFILE_HFP_AUDIO_GATEWAY);
    pa_assert(u->sink);

    pa_sink_render_full(u->sink, u->write_block_size, &memchunk);

    pa_assert(memchunk.length == u->write_block_size);

    for (;;) {
        const void *p;

        /* Now write that data to the socket. The socket is of type
         * SEQPACKET, and we generated the data of the MTU size, so this
         * should just work. */

        p = (const uint8_t *) pa_memblock_acquire_chunk(&memchunk);
        l = pa_write(u->stream_fd, p, memchunk.length, &u->stream_write_type);
        pa_memblock_release(memchunk.memblock);

        pa_assert(l != 0);

        if (l > 0)
            break;

        saved_errno = errno;

        if (saved_errno == EINTR)
            /* Retry right away if we got interrupted */
            continue;

        pa_memblock_unref(memchunk.memblock);

        if (saved_errno == EAGAIN) {
            /* Hmm, apparently the socket was not writable, give up for now.
             * Because the data was already rendered, let's discard the block. */
            pa_log_debug("Got EAGAIN on write() after POLLOUT, probably there is a temporary connection loss.");
            return 1;
        }

        pa_log_error("Failed to write data to SCO socket: %s", pa_cstrerror(saved_errno));
        return -1;
    }

    pa_assert((size_t) l <= memchunk.length);

    if ((size_t) l != memchunk.length) {
        pa_log_error("Wrote memory block to socket only partially! %llu written, wanted to write %llu.",
                    (unsigned long long) l,
                    (unsigned long long) memchunk.length);

        pa_memblock_unref(memchunk.memblock);
        return -1;
    }

    u->write_index += (uint64_t) memchunk.length;
    pa_memblock_unref(memchunk.memblock);

    return 1;
}

/* Run from IO thread */
static int sco_process_push(struct userdata *u) {
    ssize_t l;
    pa_memchunk memchunk;
    struct cmsghdr *cm;
    struct msghdr m;
    bool found_tstamp = false;
    pa_usec_t tstamp = 0;

    pa_assert(u);
    pa_assert(u->profile == PA_BLUETOOTH_PROFILE_HSP_HEAD_UNIT ||
              u->profile == PA_BLUETOOTH_PROFILE_HFP_HEAD_UNIT ||
              u->profile == PA_BLUETOOTH_PROFILE_HSP_AUDIO_GATEWAY ||
              u->profile == PA_BLUETOOTH_PROFILE_HFP_AUDIO_GATEWAY);
    pa_assert(u->source);
    pa_assert(u->read_smoother);

    memchunk.memblock = pa_memblock_new(u->core->mempool, u->read_block_size);
    memchunk.index = memchunk.length = 0;

    for (;;) {
        void *p;
        uint8_t aux[1024];
        struct iovec iov;

        pa_zero(m);
        pa_zero(aux);
        pa_zero(iov);

        m.msg_iov = &iov;
        m.msg_iovlen = 1;
        m.msg_control = aux;
        m.msg_controllen = sizeof(aux);

        p = pa_memblock_acquire(memchunk.memblock);
        iov.iov_base = p;
        iov.iov_len = pa_memblock_get_length(memchunk.memblock);
        l = recvmsg(u->stream_fd, &m, 0);
        pa_memblock_release(memchunk.memblock);

        if (l > 0)
            break;

        if (l < 0 && errno == EINTR)
            /* Retry right away if we got interrupted */
            continue;

        pa_memblock_unref(memchunk.memblock);

        if (l < 0 && errno == EAGAIN)
            /* Hmm, apparently the socket was not readable, give up for now. */
            return 0;

        pa_log_error("Failed to read data from SCO socket: %s", l < 0 ? pa_cstrerror(errno) : "EOF");
        return -1;
    }

    pa_assert((size_t) l <= pa_memblock_get_length(memchunk.memblock));

    /* In some rare occasions, we might receive packets of a very strange
     * size. This could potentially be possible if the SCO packet was
     * received partially over-the-air, or more probably due to hardware
     * issues in our Bluetooth adapter. In these cases, in order to avoid
     * an assertion failure due to unaligned data, just discard the whole
     * packet */
    if (!pa_frame_aligned(l, &u->decoder_sample_spec)) {
        pa_log_warn("SCO packet received of unaligned size: %zu", l);
        pa_memblock_unref(memchunk.memblock);
        return -1;
    }

    memchunk.length = (size_t) l;
    u->read_index += (uint64_t) l;

    for (cm = CMSG_FIRSTHDR(&m); cm; cm = CMSG_NXTHDR(&m, cm))
        if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SO_TIMESTAMP) {
            struct timeval *tv = (struct timeval*) CMSG_DATA(cm);
            pa_rtclock_from_wallclock(tv);
            tstamp = pa_timeval_load(tv);
            found_tstamp = true;
            break;
        }

    if (!found_tstamp) {
        PA_ONCE_BEGIN {
            pa_log_warn("Couldn't find SO_TIMESTAMP data in auxiliary recvmsg() data!");
        } PA_ONCE_END;
        tstamp = pa_rtclock_now();
    }

    pa_smoother_put(u->read_smoother, tstamp, pa_bytes_to_usec(u->read_index, &u->decoder_sample_spec));
    pa_smoother_resume(u->read_smoother, tstamp, true);

    pa_source_post(u->source, &memchunk);
    pa_memblock_unref(memchunk.memblock);

    return l;
}

/* Run from IO thread */
static void a2dp_prepare_encoder_buffer(struct userdata *u) {
    pa_assert(u);

    if (u->encoder_buffer_size < u->write_link_mtu) {
        pa_xfree(u->encoder_buffer);
        u->encoder_buffer = pa_xmalloc(u->write_link_mtu);
    }

    /* Encoder buffer cannot be larger then link MTU, otherwise
     * encode method would produce larger packets then link MTU */
    u->encoder_buffer_size = u->write_link_mtu;
}

/* Run from IO thread */
static void a2dp_prepare_decoder_buffer(struct userdata *u) {
    pa_assert(u);

    if (u->decoder_buffer_size < u->read_link_mtu) {
        pa_xfree(u->decoder_buffer);
        u->decoder_buffer = pa_xmalloc(u->read_link_mtu);
    }

    /* Decoder buffer cannot be larger then link MTU, otherwise
     * decode method would produce larger output then read_block_size */
    u->decoder_buffer_size = u->read_link_mtu;
}

/* Run from IO thread */
static int a2dp_write_buffer(struct userdata *u, size_t nbytes) {
    int ret = 0;

    /* Encoder function of A2DP codec may provide empty buffer, in this case do
     * not post any empty buffer via A2DP socket. It may be because of codec
     * internal state, e.g. encoder is waiting for more samples so it can
     * provide encoded data. */
    if (PA_UNLIKELY(!nbytes)) {
        u->write_index += (uint64_t) u->write_memchunk.length;
        pa_memblock_unref(u->write_memchunk.memblock);
        pa_memchunk_reset(&u->write_memchunk);
        return 0;
    }

    for (;;) {
        ssize_t l;

        l = pa_write(u->stream_fd, u->encoder_buffer, nbytes, &u->stream_write_type);

        pa_assert(l != 0);

        if (l < 0) {

            if (errno == EINTR)
                /* Retry right away if we got interrupted */
                continue;

            else if (errno == EAGAIN) {
                /* Hmm, apparently the socket was not writable, give up for now */
                pa_log_debug("Got EAGAIN on write() after POLLOUT, probably there is a temporary connection loss.");
                break;
            }

            pa_log_error("Failed to write data to socket: %s", pa_cstrerror(errno));
            ret = -1;
            break;
        }

        pa_assert((size_t) l <= nbytes);

        if ((size_t) l != nbytes) {
            pa_log_warn("Wrote memory block to socket only partially! %llu written, wanted to write %llu.",
                        (unsigned long long) l,
                        (unsigned long long) nbytes);
            ret = -1;
            break;
        }

        u->write_index += (uint64_t) u->write_memchunk.length;
        pa_memblock_unref(u->write_memchunk.memblock);
        pa_memchunk_reset(&u->write_memchunk);

        ret = 1;

        break;
    }

    return ret;
}

/* Run from IO thread */
static int a2dp_process_render(struct userdata *u) {
    const pa_a2dp_codec *a2dp_codec;
    const uint8_t *ptr;
    size_t processed;
    size_t length;

    pa_assert(u);
    pa_assert(u->sink);

    a2dp_codec = pa_bluetooth_profile_to_a2dp_codec(u->profile);

    /* First, render some data */
    if (!u->write_memchunk.memblock)
        pa_sink_render_full(u->sink, u->write_block_size, &u->write_memchunk);

    pa_assert(u->write_memchunk.length == u->write_block_size);

    a2dp_prepare_encoder_buffer(u);

    /* Try to create a packet of the full MTU */
    ptr = (const uint8_t *) pa_memblock_acquire_chunk(&u->write_memchunk);

    length = a2dp_codec->encode_buffer(pa_bluetooth_profile_is_a2dp_sink(u->profile) ? u->encoder_info : u->encoder_backchannel_info, u->write_index / pa_frame_size(&u->encoder_sample_spec), ptr, u->write_memchunk.length, u->encoder_buffer, u->encoder_buffer_size, &processed);

    pa_memblock_release(u->write_memchunk.memblock);

    if (processed != u->write_memchunk.length) {
        pa_log_error("Encoding error");
        return -1;
    }

    return a2dp_write_buffer(u, length);
}

/* Run from IO thread */
static int a2dp_process_push(struct userdata *u) {
    const pa_a2dp_codec *a2dp_codec;
    int ret = 0;
    pa_memchunk memchunk;

    pa_assert(u);
    pa_assert(u->source);
    pa_assert(u->read_smoother);

    a2dp_codec = pa_bluetooth_profile_to_a2dp_codec(u->profile);

    memchunk.memblock = pa_memblock_new(u->core->mempool, u->read_block_size);
    memchunk.index = memchunk.length = 0;

    a2dp_prepare_decoder_buffer(u);

    for (;;) {
        uint8_t aux[1024];
        struct iovec iov;
        struct cmsghdr *cm;
        struct msghdr m;
        bool found_tstamp = false;
        pa_usec_t tstamp;
        uint8_t *ptr;
        ssize_t l;
        size_t processed;

        pa_zero(m);
        pa_zero(aux);
        pa_zero(iov);

        m.msg_iov = &iov;
        m.msg_iovlen = 1;
        m.msg_control = aux;
        m.msg_controllen = sizeof(aux);

        iov.iov_base = u->decoder_buffer;
        iov.iov_len = u->decoder_buffer_size;

        l = recvmsg(u->stream_fd, &m, 0);

        if (l <= 0) {

            if (l < 0 && errno == EINTR)
                /* Retry right away if we got interrupted */
                continue;

            else if (l < 0 && errno == EAGAIN)
                /* Hmm, apparently the socket was not readable, give up for now. */
                break;

            pa_log_error("Failed to read data from socket: %s", l < 0 ? pa_cstrerror(errno) : "EOF");
            ret = -1;
            break;
        }

        pa_assert((size_t) l <= u->decoder_buffer_size);

        /* TODO: get timestamp from rtp */

        for (cm = CMSG_FIRSTHDR(&m); cm; cm = CMSG_NXTHDR(&m, cm)) {
            if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SO_TIMESTAMP) {
                struct timeval *tv = (struct timeval*) CMSG_DATA(cm);
                pa_rtclock_from_wallclock(tv);
                tstamp = pa_timeval_load(tv);
                found_tstamp = true;
                break;
            }
        }

        if (!found_tstamp) {
            PA_ONCE_BEGIN {
                pa_log_warn("Couldn't find SO_TIMESTAMP data in auxiliary recvmsg() data!");
            } PA_ONCE_END;
            tstamp = pa_rtclock_now();
        }

        ptr = pa_memblock_acquire(memchunk.memblock);
        memchunk.length = pa_memblock_get_length(memchunk.memblock);

        memchunk.length = a2dp_codec->decode_buffer(pa_bluetooth_profile_is_a2dp_source(u->profile) ? u->decoder_info : u->decoder_backchannel_info, u->decoder_buffer, l, ptr, memchunk.length, &processed);

        pa_memblock_release(memchunk.memblock);

        if (processed != (size_t) l) {
            pa_log_error("Decoding error");
            ret = -1;
            break;
        }

        u->read_index += (uint64_t) memchunk.length;
        pa_smoother_put(u->read_smoother, tstamp, pa_bytes_to_usec(u->read_index, &u->decoder_sample_spec));
        pa_smoother_resume(u->read_smoother, tstamp, true);

        /* Decoding of A2DP codec data may result in empty buffer, in this case
         * do not post empty audio samples. It may happen due to algorithmic
         * delay of audio codec. */
        if (PA_LIKELY(memchunk.length))
            pa_source_post(u->source, &memchunk);

        ret = l;
        break;
    }

    pa_memblock_unref(memchunk.memblock);

    return ret;
}

static void update_sink_buffer_size(struct userdata *u) {
    int old_bufsize;
    socklen_t len = sizeof(int);
    int ret;

    ret = getsockopt(u->stream_fd, SOL_SOCKET, SO_SNDBUF, &old_bufsize, &len);
    if (ret == -1) {
        pa_log_warn("Changing bluetooth buffer size: Failed to getsockopt(SO_SNDBUF): %s", pa_cstrerror(errno));
    } else {
        int new_bufsize;

        /* Set send buffer size as small as possible. The minimum value is 1024 according to the
         * socket man page. The data is written to the socket in chunks of write_block_size, so
         * there should at least be room for two chunks in the buffer. Generally, write_block_size
         * is larger than 512. If not, use the next multiple of write_block_size which is larger
         * than 1024. */
        new_bufsize = 2 * u->write_block_size;
        if (new_bufsize < 1024)
            new_bufsize = (1024 / u->write_block_size + 1) * u->write_block_size;

        /* The kernel internally doubles the buffer size that was set by setsockopt and getsockopt
         * returns the doubled value. */
        if (new_bufsize != old_bufsize / 2) {
            ret = setsockopt(u->stream_fd, SOL_SOCKET, SO_SNDBUF, &new_bufsize, len);
            if (ret == -1)
                pa_log_warn("Changing bluetooth buffer size: Failed to change from %d to %d: %s", old_bufsize / 2, new_bufsize, pa_cstrerror(errno));
            else
                pa_log_info("Changing bluetooth buffer size: Changed from %d to %d", old_bufsize / 2, new_bufsize);
        }
    }
}

static void teardown_stream(struct userdata *u) {
    if (u->rtpoll_item) {
        pa_rtpoll_item_free(u->rtpoll_item);
        u->rtpoll_item = NULL;
    }

    if (u->stream_fd >= 0) {
        pa_close(u->stream_fd);
        u->stream_fd = -1;
    }

    if (u->read_smoother) {
        pa_smoother_free(u->read_smoother);
        u->read_smoother = NULL;
    }

    if (u->write_memchunk.memblock) {
        pa_memblock_unref(u->write_memchunk.memblock);
        pa_memchunk_reset(&u->write_memchunk);
    }

    pa_log_debug("Audio stream torn down");
    u->stream_setup_done = false;
}

static int transport_acquire(struct userdata *u) {
    pa_assert(u->transport);

    if (u->transport_acquired)
        return 0;

    pa_log_debug("Acquiring transport %s", u->transport->path);

    u->stream_fd = u->transport->acquire(u->transport, &u->read_link_mtu, &u->write_link_mtu);
    if (u->stream_fd < 0)
        return u->stream_fd;

    /* transport_acquired must be set before calling
     * pa_bluetooth_transport_set_state() */
    u->transport_acquired = true;
    pa_log_info("Transport %s acquired: fd %d", u->transport->path, u->stream_fd);

    if (u->transport->state == PA_BLUETOOTH_TRANSPORT_STATE_IDLE) {
        if (pa_thread_mq_get() != NULL)
            pa_asyncmsgq_post(pa_thread_mq_get()->outq, PA_MSGOBJECT(u->msg), BLUETOOTH_MESSAGE_SET_TRANSPORT_PLAYING, NULL, 0, NULL, NULL);
        else
            pa_bluetooth_transport_set_state(u->transport, PA_BLUETOOTH_TRANSPORT_STATE_PLAYING);
    }

    return 0;
}

static void transport_release(struct userdata *u) {
    pa_assert(u->transport);

    /* Ignore if already released */
    if (!u->transport_acquired)
        return;

    pa_log_debug("Releasing transport %s", u->transport->path);

    u->transport->release(u->transport);

    u->transport_acquired = false;

    teardown_stream(u);

    /* Set transport state to idle if this was not already done by the remote end closing
     * the file descriptor. Only do this when called from the I/O thread */
    if (pa_thread_mq_get() != NULL && u->transport->state == PA_BLUETOOTH_TRANSPORT_STATE_PLAYING)
        pa_asyncmsgq_post(pa_thread_mq_get()->outq, PA_MSGOBJECT(u->msg), BLUETOOTH_MESSAGE_STREAM_FD_HUP, NULL, 0, NULL, NULL);
}

/* Run from I/O thread */
static void handle_sink_block_size_change(struct userdata *u) {
    pa_sink_set_max_request_within_thread(u->sink, u->write_block_size);
    pa_sink_set_fixed_latency_within_thread(u->sink,
                                            (pa_bluetooth_profile_is_a2dp(u->profile) ?
                                             FIXED_LATENCY_PLAYBACK_A2DP : FIXED_LATENCY_PLAYBACK_SCO) +
                                            pa_bytes_to_usec(u->write_block_size, &u->encoder_sample_spec));

    /* If there is still data in the memchunk, we have to discard it
     * because the write_block_size may have changed. */
    if (u->write_memchunk.memblock) {
        pa_memblock_unref(u->write_memchunk.memblock);
        pa_memchunk_reset(&u->write_memchunk);
    }

    update_sink_buffer_size(u);
}

/* Run from I/O thread */
static void transport_config_mtu(struct userdata *u) {
    if (u->profile == PA_BLUETOOTH_PROFILE_HSP_HEAD_UNIT ||
        u->profile == PA_BLUETOOTH_PROFILE_HFP_HEAD_UNIT ||
        u->profile == PA_BLUETOOTH_PROFILE_HSP_AUDIO_GATEWAY ||
        u->profile == PA_BLUETOOTH_PROFILE_HFP_AUDIO_GATEWAY) {
        u->read_block_size = u->read_link_mtu;
        u->write_block_size = u->write_link_mtu;

        if (!pa_frame_aligned(u->read_block_size, &u->source->sample_spec)) {
            pa_log_debug("Got invalid read MTU: %lu, rounding down", u->read_block_size);
            u->read_block_size = pa_frame_align(u->read_block_size, &u->source->sample_spec);
        }

        if (!pa_frame_aligned(u->write_block_size, &u->sink->sample_spec)) {
            pa_log_debug("Got invalid write MTU: %lu, rounding down", u->write_block_size);
            u->write_block_size = pa_frame_align(u->write_block_size, &u->sink->sample_spec);
        }
    } else {
        const pa_a2dp_codec *a2dp_codec = pa_bluetooth_profile_to_a2dp_codec(u->profile);
        if (pa_bluetooth_profile_is_a2dp_sink(u->profile)) {
            u->write_block_size = a2dp_codec->get_write_block_size(u->encoder_info, u->write_link_mtu);
            if (u->source)
                u->read_block_size = a2dp_codec->get_read_block_size(u->decoder_backchannel_info, u->read_link_mtu);
        } else {
            u->read_block_size = a2dp_codec->get_read_block_size(u->decoder_info, u->read_link_mtu);
            if (u->sink)
                u->write_block_size = a2dp_codec->get_write_block_size(u->encoder_backchannel_info, u->write_link_mtu);
        }
    }

    if (u->sink)
        handle_sink_block_size_change(u);

    if (u->source)
        pa_source_set_fixed_latency_within_thread(u->source,
                                                  (pa_bluetooth_profile_is_a2dp(u->profile) ?
                                                   FIXED_LATENCY_RECORD_A2DP : FIXED_LATENCY_RECORD_SCO) +
                                                  pa_bytes_to_usec(u->read_block_size, &u->decoder_sample_spec));
}

/* Run from I/O thread */
static int setup_stream(struct userdata *u) {
    const pa_a2dp_codec *a2dp_codec;
    struct pollfd *pollfd;
    int one;

    pa_assert(u->stream_fd >= 0);

    /* return if stream is already set up */
    if (u->stream_setup_done)
        return 0;

    pa_log_info("Transport %s resuming", u->transport->path);

    if (pa_bluetooth_profile_is_a2dp(u->profile)) {
        a2dp_codec = pa_bluetooth_profile_to_a2dp_codec(u->profile);
        if (pa_bluetooth_profile_is_a2dp_sink(u->profile)) {
            if (a2dp_codec->reset(u->encoder_info) < 0)
                return -1;
            if (u->source) {
                if (a2dp_codec->reset(u->decoder_backchannel_info) < 0)
                    return -1;
            }
        } else {
            if (a2dp_codec->reset(u->decoder_info) < 0)
                return -1;
            if (u->sink) {
                if (a2dp_codec->reset(u->encoder_backchannel_info) < 0)
                    return -1;
            }
        }
    }

    transport_config_mtu(u);

    pa_make_fd_nonblock(u->stream_fd);
    pa_make_socket_low_delay(u->stream_fd);

    one = 1;
    if (setsockopt(u->stream_fd, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof(one)) < 0)
        pa_log_warn("Failed to enable SO_TIMESTAMP: %s", pa_cstrerror(errno));

    pa_log_debug("Stream properly set up, we're ready to roll!");

    u->rtpoll_item = pa_rtpoll_item_new(u->rtpoll, PA_RTPOLL_NEVER, 1);
    pollfd = pa_rtpoll_item_get_pollfd(u->rtpoll_item, NULL);
    pollfd->fd = u->stream_fd;
    pollfd->events = pollfd->revents = 0;

    u->read_index = u->write_index = 0;
    u->started_at = 0;
    u->stream_setup_done = true;

    if (u->source)
        u->read_smoother = pa_smoother_new(PA_USEC_PER_SEC, 2*PA_USEC_PER_SEC, true, true, 10, pa_rtclock_now(), true);

    return 0;
}

/* Called from I/O thread, returns true if the transport was acquired or
 * a connection was requested successfully. */
static bool setup_transport_and_stream(struct userdata *u) {
    int transport_error;

    transport_error = transport_acquire(u);
    if (transport_error < 0) {
        if (transport_error != -EAGAIN)
            return false;
    } else {
        if (setup_stream(u) < 0)
            return false;
    }
    return true;
}

/* Run from IO thread */
static int source_process_msg(pa_msgobject *o, int code, void *data, int64_t offset, pa_memchunk *chunk) {
    struct userdata *u = PA_SOURCE(o)->userdata;

    pa_assert(u->source == PA_SOURCE(o));
    pa_assert(u->transport);

    switch (code) {

        case PA_SOURCE_MESSAGE_GET_LATENCY: {
            int64_t wi, ri;

            if (u->read_smoother) {
                wi = pa_smoother_get(u->read_smoother, pa_rtclock_now());
                ri = pa_bytes_to_usec(u->read_index, &u->decoder_sample_spec);

                *((int64_t*) data) = u->source->thread_info.fixed_latency + wi - ri;
            } else
                *((int64_t*) data) = 0;

            return 0;
        }

        case PA_SOURCE_MESSAGE_SETUP_STREAM:
            /* Skip stream setup if stream_fd has been invalidated.
               This can occur if the stream has already been set up and
               then immediately received POLLHUP. If the stream has
               already been set up earlier, then this setup_stream()
               call is redundant anyway, but currently the code
               is such that this kind of unnecessary setup_stream()
               calls can happen. */
            if (u->stream_fd < 0)
                pa_log_debug("Skip source stream setup while closing");
            else
                setup_stream(u);
            return 0;

    }

    return pa_source_process_msg(o, code, data, offset, chunk);
}

/* Called from the IO thread. */
static int source_set_state_in_io_thread_cb(pa_source *s, pa_source_state_t new_state, pa_suspend_cause_t new_suspend_cause) {
    struct userdata *u;

    pa_assert(s);
    pa_assert_se(u = s->userdata);

    switch (new_state) {

        case PA_SOURCE_SUSPENDED:
            /* Ignore if transition is PA_SOURCE_INIT->PA_SOURCE_SUSPENDED */
            if (!PA_SOURCE_IS_OPENED(s->thread_info.state))
                break;

            /* Stop the device if the sink is suspended as well */
            if (!u->sink || u->sink->state == PA_SINK_SUSPENDED)
                transport_release(u);

            if (u->read_smoother)
                pa_smoother_pause(u->read_smoother, pa_rtclock_now());

            break;

        case PA_SOURCE_IDLE:
        case PA_SOURCE_RUNNING:
            if (s->thread_info.state != PA_SOURCE_SUSPENDED)
                break;

            /* Resume the device if the sink was suspended as well */
            if (!u->sink || !PA_SINK_IS_OPENED(u->sink->thread_info.state))
                if (!setup_transport_and_stream(u))
                    return -1;

            /* We don't resume the smoother here. Instead we
             * wait until the first packet arrives */

            break;

        case PA_SOURCE_UNLINKED:
        case PA_SOURCE_INIT:
        case PA_SOURCE_INVALID_STATE:
            break;
    }

    return 0;
}

/* Run from main thread */
static void source_set_volume_cb(pa_source *s) {
    uint16_t gain;
    pa_volume_t volume;
    struct userdata *u;

    pa_assert(s);
    pa_assert(s->core);

    u = s->userdata;

    pa_assert(u);
    pa_assert(u->source == s);

    gain = (pa_cvolume_max(&s->real_volume) * u->transport->max_rx_volume_gain) / PA_VOLUME_NORM;

    if (gain > u->transport->max_rx_volume_gain)
        gain = u->transport->max_rx_volume_gain;

    volume = (pa_volume_t) (gain * PA_VOLUME_NORM / u->transport->max_rx_volume_gain);

    /* increment volume by one to correct rounding errors */
    if (volume < PA_VOLUME_NORM)
        volume++;

    pa_cvolume_set(&s->real_volume, u->decoder_sample_spec.channels, volume);

    /* Set soft volume when transport requires it, otherwise reset soft volume to default */
    if (u->transport->rx_soft_volume)
        pa_cvolume_set(&s->soft_volume, u->decoder_sample_spec.channels, volume);
    else
        pa_cvolume_reset(&s->soft_volume, u->decoder_sample_spec.channels);

    if (u->transport->set_rx_volume_gain)
        u->transport->set_rx_volume_gain(u->transport, gain);
}

/* Run from main thread */
static int add_source(struct userdata *u) {
    pa_source_new_data data;
    pa_card_profile *cp;

    pa_assert(u->transport);

    pa_source_new_data_init(&data);
    data.module = u->module;
    data.card = u->card;
    data.driver = __FILE__;
    data.name = pa_sprintf_malloc("bluez_source.%s.%s", u->device->address, pa_bluetooth_profile_to_string(u->profile));
    data.namereg_fail = false;
    pa_proplist_sets(data.proplist, "bluetooth.protocol", pa_bluetooth_profile_to_string(u->profile));
    pa_source_new_data_set_sample_spec(&data, &u->decoder_sample_spec);
    if (u->profile == PA_BLUETOOTH_PROFILE_HSP_HEAD_UNIT || u->profile == PA_BLUETOOTH_PROFILE_HFP_HEAD_UNIT)
        pa_proplist_sets(data.proplist, PA_PROP_DEVICE_INTENDED_ROLES, "phone");

    pa_assert_se(cp = pa_hashmap_get(u->card->profiles, pa_bluetooth_profile_to_string(u->profile)));
    pa_proplist_setf(data.proplist, PA_PROP_DEVICE_DESCRIPTION, "%s - %s", pa_proplist_gets(u->card->proplist, PA_PROP_DEVICE_DESCRIPTION), cp->description);

    connect_ports(u, &data, PA_DIRECTION_INPUT);

    if (!u->transport_acquired)
        data.suspend_cause = PA_SUSPEND_USER;

    u->source = pa_source_new(u->core, &data, PA_SOURCE_HARDWARE|PA_SOURCE_LATENCY);
    pa_source_new_data_done(&data);
    if (!u->source) {
        pa_log_error("Failed to create source");
        return -1;
    }

    u->source->userdata = u;
    u->source->parent.process_msg = source_process_msg;
    u->source->set_state_in_io_thread = source_set_state_in_io_thread_cb;

    pa_source_set_set_volume_callback(u->source, source_set_volume_cb);
    u->source->n_volume_steps = u->transport->max_rx_volume_gain + 1;
    return 0;
}

/* Run from IO thread */
static int sink_process_msg(pa_msgobject *o, int code, void *data, int64_t offset, pa_memchunk *chunk) {
    struct userdata *u = PA_SINK(o)->userdata;

    pa_assert(u->sink == PA_SINK(o));
    pa_assert(u->transport);

    switch (code) {

        case PA_SINK_MESSAGE_GET_LATENCY: {
            int64_t wi = 0, ri = 0;

            /* Do not use read smoother for A2DP sink as it belongs to independent backchannel */
            if (!pa_bluetooth_profile_is_a2dp(u->profile) && u->read_smoother) {
                ri = pa_smoother_get(u->read_smoother, pa_rtclock_now());
                wi = pa_bytes_to_usec(u->write_index + u->write_block_size, &u->encoder_sample_spec);
            } else if (u->started_at) {
                ri = pa_rtclock_now() - u->started_at;
                wi = pa_bytes_to_usec(u->write_index, &u->encoder_sample_spec);
            }

            *((int64_t*) data) = u->sink->thread_info.fixed_latency + wi - ri;

            return 0;
        }

        case PA_SINK_MESSAGE_SETUP_STREAM:
            /* Skip stream setup if stream_fd has been invalidated.
               This can occur if the stream has already been set up and
               then immediately received POLLHUP. If the stream has
               already been set up earlier, then this setup_stream()
               call is redundant anyway, but currently the code
               is such that this kind of unnecessary setup_stream()
               calls can happen. */
            if (u->stream_fd < 0)
                pa_log_debug("Skip sink stream setup while closing");
            else
                setup_stream(u);
            return 0;
    }

    return pa_sink_process_msg(o, code, data, offset, chunk);
}

/* Called from the IO thread. */
static int sink_set_state_in_io_thread_cb(pa_sink *s, pa_sink_state_t new_state, pa_suspend_cause_t new_suspend_cause) {
    struct userdata *u;

    pa_assert(s);
    pa_assert_se(u = s->userdata);

    switch (new_state) {

        case PA_SINK_SUSPENDED:
            /* Ignore if transition is PA_SINK_INIT->PA_SINK_SUSPENDED */
            if (!PA_SINK_IS_OPENED(s->thread_info.state))
                break;

            /* Stop the device if the source is suspended as well */
            if (!u->source || u->source->state == PA_SOURCE_SUSPENDED)
                /* We deliberately ignore whether stopping
                 * actually worked. Since the stream_fd is
                 * closed it doesn't really matter */
                transport_release(u);

            break;

        case PA_SINK_IDLE:
        case PA_SINK_RUNNING:
            if (s->thread_info.state != PA_SINK_SUSPENDED)
                break;

            /* Resume the device if the source was suspended as well */
            if (!u->source || !PA_SOURCE_IS_OPENED(u->source->thread_info.state))
                if (!setup_transport_and_stream(u))
                    return -1;

            break;

        case PA_SINK_UNLINKED:
        case PA_SINK_INIT:
        case PA_SINK_INVALID_STATE:
            break;
    }

    return 0;
}

/* Run from main thread */
static void sink_set_volume_cb(pa_sink *s) {
    uint16_t gain;
    pa_volume_t volume;
    struct userdata *u;

    pa_assert(s);
    pa_assert(s->core);

    u = s->userdata;

    pa_assert(u);
    pa_assert(u->sink == s);

    gain = (pa_cvolume_max(&s->real_volume) * u->transport->max_tx_volume_gain) / PA_VOLUME_NORM;

    if (gain > u->transport->max_tx_volume_gain)
        gain = u->transport->max_tx_volume_gain;

    volume = (pa_volume_t) (gain * PA_VOLUME_NORM / u->transport->max_tx_volume_gain);

    /* increment volume by one to correct rounding errors */
    if (volume < PA_VOLUME_NORM)
        volume++;

    pa_cvolume_set(&s->real_volume, u->encoder_sample_spec.channels, volume);

    /* Set soft volume when transport requires it, otherwise reset soft volume to default */
    if (u->transport->tx_soft_volume)
        pa_cvolume_set(&s->soft_volume, u->encoder_sample_spec.channels, volume);
    else
        pa_cvolume_reset(&s->soft_volume, u->encoder_sample_spec.channels);

    if (u->transport->set_tx_volume_gain)
        u->transport->set_tx_volume_gain(u->transport, gain);
}

/* Run from main thread */
static int add_sink(struct userdata *u) {
    pa_sink_new_data data;
    pa_card_profile *cp;

    pa_assert(u->transport);

    pa_sink_new_data_init(&data);
    data.module = u->module;
    data.card = u->card;
    data.driver = __FILE__;
    data.name = pa_sprintf_malloc("bluez_sink.%s.%s", u->device->address, pa_bluetooth_profile_to_string(u->profile));
    data.namereg_fail = false;
    pa_proplist_sets(data.proplist, "bluetooth.protocol", pa_bluetooth_profile_to_string(u->profile));
    pa_sink_new_data_set_sample_spec(&data, &u->encoder_sample_spec);
    if (u->profile == PA_BLUETOOTH_PROFILE_HSP_HEAD_UNIT || u->profile == PA_BLUETOOTH_PROFILE_HFP_HEAD_UNIT)
        pa_proplist_sets(data.proplist, PA_PROP_DEVICE_INTENDED_ROLES, "phone");

    pa_assert_se(cp = pa_hashmap_get(u->card->profiles, pa_bluetooth_profile_to_string(u->profile)));
    pa_proplist_setf(data.proplist, PA_PROP_DEVICE_DESCRIPTION, "%s - %s", pa_proplist_gets(u->card->proplist, PA_PROP_DEVICE_DESCRIPTION), cp->description);

    connect_ports(u, &data, PA_DIRECTION_OUTPUT);

    if (!u->transport_acquired)
        data.suspend_cause = PA_SUSPEND_USER;

    u->sink = pa_sink_new(u->core, &data, PA_SINK_HARDWARE|PA_SINK_LATENCY);
    pa_sink_new_data_done(&data);
    if (!u->sink) {
        pa_log_error("Failed to create sink");
        return -1;
    }

    u->sink->userdata = u;
    u->sink->parent.process_msg = sink_process_msg;
    u->sink->set_state_in_io_thread = sink_set_state_in_io_thread_cb;

    pa_sink_set_set_volume_callback(u->sink, sink_set_volume_cb);
    u->sink->n_volume_steps = u->transport->max_tx_volume_gain + 1;
    return 0;
}

/* Run from main thread */
static int transport_config(struct userdata *u) {
    if (u->profile == PA_BLUETOOTH_PROFILE_HSP_HEAD_UNIT ||
        u->profile == PA_BLUETOOTH_PROFILE_HFP_HEAD_UNIT ||
        u->profile == PA_BLUETOOTH_PROFILE_HSP_AUDIO_GATEWAY ||
        u->profile == PA_BLUETOOTH_PROFILE_HFP_AUDIO_GATEWAY) {
        u->encoder_sample_spec.format = PA_SAMPLE_S16LE;
        u->encoder_sample_spec.channels = 1;
        u->encoder_sample_spec.rate = 8000;
        u->decoder_sample_spec.format = PA_SAMPLE_S16LE;
        u->decoder_sample_spec.channels = 1;
        u->decoder_sample_spec.rate = 8000;
        return 0;
    } else {
        const pa_a2dp_codec *a2dp_codec = pa_bluetooth_profile_to_a2dp_codec(u->profile);
        bool is_a2dp_sink = pa_bluetooth_profile_is_a2dp_sink(u->profile);
        void *info;

        pa_assert(u->transport);

        pa_assert(!u->encoder_info);
        pa_assert(!u->decoder_info);
        pa_assert(!u->encoder_backchannel_info);
        pa_assert(!u->decoder_backchannel_info);

        info = a2dp_codec->init(is_a2dp_sink, false, u->transport->config, u->transport->config_size, is_a2dp_sink ? &u->encoder_sample_spec : &u->decoder_sample_spec);
        if (is_a2dp_sink)
            u->encoder_info = info;
        else
            u->decoder_info = info;

        if (!info)
            return -1;

        if (a2dp_codec->support_backchannel) {
            info = a2dp_codec->init(!is_a2dp_sink, true, u->transport->config, u->transport->config_size, !is_a2dp_sink ? &u->encoder_sample_spec : &u->decoder_sample_spec);
            if (is_a2dp_sink)
                u->decoder_backchannel_info = info;
            else
                u->encoder_backchannel_info = info;

            if (!info) {
                if (is_a2dp_sink) {
                    a2dp_codec->deinit(u->encoder_info);
                    u->encoder_info = NULL;
                } else {
                    a2dp_codec->deinit(u->decoder_info);
                    u->decoder_info = NULL;
                }
                return -1;
            }
        }

        return 0;
    }
}

/* Run from main thread */
static int setup_transport(struct userdata *u) {
    pa_bluetooth_transport *t;
    int transport_error;

    pa_assert(u);
    pa_assert(!u->transport);
    pa_assert(u->profile != PA_BLUETOOTH_PROFILE_OFF);

    /* check if profile has a transport */
    t = u->device->transports[u->profile];
    if (!t || t->state <= PA_BLUETOOTH_TRANSPORT_STATE_DISCONNECTED) {
        pa_log_warn("Profile %s has no transport", pa_bluetooth_profile_to_string(u->profile));
        return -1;
    }

    u->transport = t;

    transport_error = transport_acquire(u);
    if (transport_error < 0 && transport_error != -EAGAIN)
        return -1; /* We need to fail here until the interactions with module-suspend-on-idle and alike get improved */
    /* When transport_error is -EAGAIN then the sink/sources will be created suspended */

    return transport_config(u);
}

/* Run from main thread */
static pa_direction_t get_profile_direction(pa_bluetooth_profile_t p) {
    if (p == PA_BLUETOOTH_PROFILE_HSP_HEAD_UNIT ||
        p == PA_BLUETOOTH_PROFILE_HFP_HEAD_UNIT ||
        p == PA_BLUETOOTH_PROFILE_HSP_AUDIO_GATEWAY ||
        p == PA_BLUETOOTH_PROFILE_HFP_AUDIO_GATEWAY)
        return PA_DIRECTION_INPUT | PA_DIRECTION_OUTPUT;
    else if (p == PA_BLUETOOTH_PROFILE_OFF)
        return 0;
    else if (pa_bluetooth_profile_is_a2dp_sink(p)) {
        if (pa_bluetooth_profile_support_a2dp_backchannel(p))
            return PA_DIRECTION_INPUT | PA_DIRECTION_OUTPUT;
        else
            return PA_DIRECTION_OUTPUT;
    } else if (pa_bluetooth_profile_is_a2dp_source(p)) {
        if (pa_bluetooth_profile_support_a2dp_backchannel(p))
            return PA_DIRECTION_INPUT | PA_DIRECTION_OUTPUT;
        else
            return PA_DIRECTION_INPUT;
    } else
        pa_assert_not_reached();
}

/* Run from main thread */
static int init_profile(struct userdata *u) {
    int r = 0;
    pa_assert(u);
    pa_assert(u->profile != PA_BLUETOOTH_PROFILE_OFF);

    r = setup_transport(u);
    if (r < 0)
        return -1;

    pa_assert(u->transport);

    if (get_profile_direction (u->profile) & PA_DIRECTION_OUTPUT)
        if (add_sink(u) < 0)
            r = -1;

    if (get_profile_direction (u->profile) & PA_DIRECTION_INPUT)
        if (add_source(u) < 0)
            r = -1;

    return r;
}

static int write_block(struct userdata *u) {
    int n_written;

    if (u->write_index <= 0)
        u->started_at = pa_rtclock_now();

    if (pa_bluetooth_profile_is_a2dp(u->profile)) {
        if ((n_written = a2dp_process_render(u)) < 0)
            return -1;
    } else {
        if ((n_written = sco_process_render(u)) < 0)
            return -1;
    }

    return n_written;
}


/* I/O thread function */
static void thread_func(void *userdata) {
    struct userdata *u = userdata;
    unsigned blocks_to_write = 0;
    unsigned bytes_to_write = 0;

    pa_assert(u);
    pa_assert(u->transport);

    pa_log_debug("IO Thread starting up");

    if (u->core->realtime_scheduling)
        pa_thread_make_realtime(u->core->realtime_priority);

    pa_thread_mq_install(&u->thread_mq);

    /* Setup the stream only if the transport was already acquired */
    if (u->transport_acquired)
        setup_stream(u);

    for (;;) {
        struct pollfd *pollfd;
        int ret;
        bool disable_timer = true;
        bool writable = false;
        bool have_source = u->source ? PA_SOURCE_IS_LINKED(u->source->thread_info.state) : false;
        bool have_sink = u->sink ? PA_SINK_IS_LINKED(u->sink->thread_info.state) : false;

        pollfd = u->rtpoll_item ? pa_rtpoll_item_get_pollfd(u->rtpoll_item, NULL) : NULL;

        /* Check for stream error or close */
        if (pollfd && (pollfd->revents & ~(POLLOUT|POLLIN))) {
            pa_log_info("FD error: %s%s%s%s",
                        pollfd->revents & POLLERR ? "POLLERR " :"",
                        pollfd->revents & POLLHUP ? "POLLHUP " :"",
                        pollfd->revents & POLLPRI ? "POLLPRI " :"",
                        pollfd->revents & POLLNVAL ? "POLLNVAL " :"");

            if (pollfd->revents & POLLHUP) {
                pollfd = NULL;
                teardown_stream(u);
                blocks_to_write = 0;
                bytes_to_write = 0;
                pa_asyncmsgq_post(pa_thread_mq_get()->outq, PA_MSGOBJECT(u->msg), BLUETOOTH_MESSAGE_STREAM_FD_HUP, NULL, 0, NULL, NULL);
            } else
                goto fail;
        }

        /* If there is a pollfd, the stream is set up and we need to do something */
        if (pollfd) {

            /* Handle source if present */
            if (have_source) {

                /* We should send two blocks to the device before we expect a response. */
                if (have_sink && u->write_index == 0 && u->read_index <= 0)
                    blocks_to_write = 2;

                /* If we got woken up by POLLIN let's do some reading */
                if (pollfd->revents & POLLIN) {
                    int n_read;

                    if (pa_bluetooth_profile_is_a2dp(u->profile))
                        n_read = a2dp_process_push(u);
                    else
                        n_read = sco_process_push(u);

                    if (n_read < 0)
                        goto fail;

                    if (have_sink && n_read > 0 && !pa_bluetooth_profile_is_a2dp(u->profile)) {
                        /* We just read something, so we are supposed to write something, too */
                        bytes_to_write += n_read;
                        blocks_to_write += bytes_to_write / u->write_block_size;
                        bytes_to_write = bytes_to_write % u->write_block_size;

                        /* SCO is synchronous socket, ensure that we do not send more bytes than we received */
                        if (u->write_block_size != (size_t) n_read && (size_t) n_read <= u->write_link_mtu) {
                            u->write_block_size = (size_t) n_read;
                            handle_sink_block_size_change(u);
                        }
                    }
                }
            }

            /* Handle sink if present */
            if (have_sink) {

                /* Process rewinds */
                if (PA_UNLIKELY(u->sink->thread_info.rewind_requested))
                    pa_sink_process_rewind(u->sink, 0);

                /* Test if the stream is writable */
                if (pollfd->revents & POLLOUT)
                    writable = true;

                /* If we have a source, we let the source determine the timing
                 * for the sink */
                if (have_source && !pa_bluetooth_profile_is_a2dp(u->profile)) {

                    if (writable && blocks_to_write > 0) {
                        int result;

                        if ((result = write_block(u)) < 0)
                            goto fail;

                        blocks_to_write -= result;

                        /* writable controls whether we set POLLOUT when polling - we set it to
                         * false to enable POLLOUT. If there are more blocks to write, we want to
                         * be woken up immediately when the socket becomes writable. If there
                         * aren't currently any more blocks to write, then we'll have to wait
                         * until we've received more data, so in that case we only want to set
                         * POLLIN. Note that when we are woken up the next time, POLLOUT won't be
                         * set in revents even if the socket has meanwhile become writable, which
                         * may seem bad, but in that case we'll set POLLOUT in the subsequent
                         * poll, and the poll will return immediately, so our writes won't be
                         * delayed. */
                        if (blocks_to_write > 0)
                            writable = false;
                    }

                /* There is no source, we have to use the system clock for timing */
                } else {
                    bool have_written = false;
                    pa_usec_t time_passed = 0;
                    pa_usec_t audio_sent = 0;

                    if (u->started_at) {
                        time_passed = pa_rtclock_now() - u->started_at;
                        audio_sent = pa_bytes_to_usec(u->write_index, &u->encoder_sample_spec);
                    }

                    /* A new block needs to be sent. */
                    if (audio_sent <= time_passed) {
                        size_t bytes_to_send = pa_usec_to_bytes(time_passed - audio_sent, &u->encoder_sample_spec);

                        /* There are more than two blocks that need to be written. It seems that
                         * the socket has not been accepting data fast enough (could be due to
                         * hiccups in the wireless transmission). We need to discard everything
                         * older than two block sizes to keep the latency from growing. */
                        if (bytes_to_send > 2 * u->write_block_size) {
                            uint64_t skip_bytes;
                            pa_memchunk tmp;
                            size_t mempool_max_block_size = pa_mempool_block_size_max(u->core->mempool);
                            pa_usec_t skip_usec;

                            skip_bytes = bytes_to_send - 2 * u->write_block_size;
                            skip_usec = pa_bytes_to_usec(skip_bytes, &u->encoder_sample_spec);

                            pa_log_debug("Skipping %llu us (= %llu bytes) in audio stream",
                                        (unsigned long long) skip_usec,
                                        (unsigned long long) skip_bytes);

                            while (skip_bytes > 0) {
                                size_t bytes_to_render;

                                if (skip_bytes > mempool_max_block_size)
                                    bytes_to_render = mempool_max_block_size;
                                else
                                    bytes_to_render = skip_bytes;

                                pa_sink_render_full(u->sink, bytes_to_render, &tmp);
                                pa_memblock_unref(tmp.memblock);
                                u->write_index += bytes_to_render;
                                skip_bytes -= bytes_to_render;
                            }

                            if (u->write_index > 0 && pa_bluetooth_profile_is_a2dp(u->profile)) {
                                bool is_a2dp_sink = pa_bluetooth_profile_is_a2dp_sink(u->profile);
                                const pa_a2dp_codec *a2dp_codec = pa_bluetooth_profile_to_a2dp_codec(u->profile);
                                size_t new_write_block_size = a2dp_codec->reduce_encoder_bitrate(is_a2dp_sink ? u->encoder_info : u->encoder_backchannel_info, u->write_link_mtu);
                                if (new_write_block_size) {
                                    u->write_block_size = new_write_block_size;
                                    handle_sink_block_size_change(u);
                                }
                            }
                        }

                        blocks_to_write = 1;
                    }

                    /* If the stream is writable, send some data if necessary */
                    if (writable && blocks_to_write > 0) {
                        int result;

                        if ((result = write_block(u)) < 0)
                            goto fail;

                        blocks_to_write -= result;
                        writable = false;
                        if (result)
                            have_written = true;
                    }

                    /* If nothing was written during this iteration, either the stream
                     * is not writable or there was no write pending. Set up a timer that
                     * will wake up the thread when the next data needs to be written. */
                    if (!have_written) {
                        pa_usec_t sleep_for;
                        pa_usec_t next_write_at;

                        if (writable) {
                            /* There was no write pending on this iteration of the loop.
                             * Let's estimate when we need to wake up next */
                            next_write_at = pa_bytes_to_usec(u->write_index, &u->encoder_sample_spec);
                            sleep_for = time_passed < next_write_at ? next_write_at - time_passed : 0;
                            /* pa_log("Sleeping for %lu; time passed %lu, next write at %lu", (unsigned long) sleep_for, (unsigned long) time_passed, (unsigned long)next_write_at); */
                        } else
                            /* We could not write because the stream was not ready. Let's try
                             * again in 500 ms and drop audio if we still can't write. The
                             * thread will also be woken up when we can write again. */
                            sleep_for = PA_USEC_PER_MSEC * 500;

                        pa_rtpoll_set_timer_relative(u->rtpoll, sleep_for);
                        disable_timer = false;
                    }
                }
            }

            /* Set events to wake up the thread */
            pollfd->events = (short) (((have_sink && !writable) ? POLLOUT : 0) | (have_source ? POLLIN : 0));

        }

        if (disable_timer)
            pa_rtpoll_set_timer_disabled(u->rtpoll);

        if ((ret = pa_rtpoll_run(u->rtpoll)) < 0) {
            pa_log_debug("pa_rtpoll_run failed with: %d", ret);
            goto fail;
        }

        if (ret == 0) {
            pa_log_debug("IO thread shutdown requested, stopping cleanly");
            transport_release(u);
            goto finish;
        }
    }

fail:
    /* If this was no regular exit from the loop we have to continue processing messages until we receive PA_MESSAGE_SHUTDOWN */
    pa_log_debug("IO thread failed");
    pa_asyncmsgq_post(pa_thread_mq_get()->outq, PA_MSGOBJECT(u->msg), BLUETOOTH_MESSAGE_IO_THREAD_FAILED, NULL, 0, NULL, NULL);
    pa_asyncmsgq_wait_for(u->thread_mq.inq, PA_MESSAGE_SHUTDOWN);

finish:
    pa_log_debug("IO thread shutting down");
}

/* Run from main thread */
static int start_thread(struct userdata *u) {
    pa_assert(u);
    pa_assert(!u->thread);
    pa_assert(!u->rtpoll);
    pa_assert(!u->rtpoll_item);

    u->rtpoll = pa_rtpoll_new();

    if (pa_thread_mq_init(&u->thread_mq, u->core->mainloop, u->rtpoll) < 0) {
        pa_log("pa_thread_mq_init() failed.");
        return -1;
    }

    if (!(u->thread = pa_thread_new("bluetooth", thread_func, u))) {
        pa_log_error("Failed to create IO thread");
        return -1;
    }

    if (u->sink) {
        pa_sink_set_asyncmsgq(u->sink, u->thread_mq.inq);
        pa_sink_set_rtpoll(u->sink, u->rtpoll);

        /* If we are in the headset role, the sink should not become default
         * unless there is no other sound device available. */
        if (u->profile == PA_BLUETOOTH_PROFILE_HSP_AUDIO_GATEWAY || u->profile == PA_BLUETOOTH_PROFILE_HFP_AUDIO_GATEWAY)
            u->sink->priority = 1500;

        if (u->sink->set_volume)
            u->sink->set_volume(u->sink);

        pa_sink_put(u->sink);
    }

    if (u->source) {
        pa_source_set_asyncmsgq(u->source, u->thread_mq.inq);
        pa_source_set_rtpoll(u->source, u->rtpoll);

        /* If we are in the headset role or the device is an a2dp source,
         * the source should not become default unless there is no other
         * sound device available. */
        if (u->profile == PA_BLUETOOTH_PROFILE_HSP_AUDIO_GATEWAY || u->profile == PA_BLUETOOTH_PROFILE_HFP_AUDIO_GATEWAY || pa_bluetooth_profile_is_a2dp_source(u->profile))
            u->source->priority = 1500;

        if (u->source->set_volume)
            u->source->set_volume(u->source);

        pa_source_put(u->source);
    }

    return 0;
}

/* Run from main thread */
static void stop_thread(struct userdata *u) {
    const pa_a2dp_codec *a2dp_codec;

    pa_assert(u);

    if (u->sink)
        pa_sink_unlink(u->sink);

    if (u->source)
        pa_source_unlink(u->source);

    if (u->thread) {
        pa_asyncmsgq_send(u->thread_mq.inq, NULL, PA_MESSAGE_SHUTDOWN, NULL, 0, NULL);
        pa_thread_free(u->thread);
        u->thread = NULL;
    }

    if (u->rtpoll_item) {
        pa_rtpoll_item_free(u->rtpoll_item);
        u->rtpoll_item = NULL;
    }

    if (u->rtpoll) {
        pa_rtpoll_free(u->rtpoll);
        u->rtpoll = NULL;
        pa_thread_mq_done(&u->thread_mq);
    }

    if (u->transport) {
        transport_release(u);
        u->transport = NULL;
    }

    if (u->sink) {
        pa_sink_unref(u->sink);
        u->sink = NULL;
    }

    if (u->source) {
        pa_source_unref(u->source);
        u->source = NULL;
    }

    if (u->read_smoother) {
        pa_smoother_free(u->read_smoother);
        u->read_smoother = NULL;
    }

    if (pa_bluetooth_profile_is_a2dp(u->profile)) {
        a2dp_codec = pa_bluetooth_profile_to_a2dp_codec(u->profile);

        if (u->encoder_info) {
            a2dp_codec->deinit(u->encoder_info);
            u->encoder_info = NULL;
        }

        if (u->decoder_info) {
            a2dp_codec->deinit(u->decoder_info);
            u->decoder_info = NULL;
        }

        if (u->decoder_backchannel_info) {
            a2dp_codec->deinit(u->decoder_backchannel_info);
            u->decoder_backchannel_info = NULL;
        }

        if (u->encoder_backchannel_info) {
            a2dp_codec->deinit(u->encoder_backchannel_info);
            u->encoder_backchannel_info = NULL;
        }
    }
}

/* Run from main thread */
static pa_available_t get_port_availability(struct userdata *u, pa_direction_t direction) {
    pa_available_t result = PA_AVAILABLE_NO;
    unsigned i, count;

    pa_assert(u);
    pa_assert(u->device);

    count = pa_bluetooth_profile_count();
    for (i = 0; i < count; i++) {
        pa_bluetooth_transport *transport;

        if (!(get_profile_direction(i) & direction))
            continue;

        if (!(transport = u->device->transports[i]))
            continue;

        switch(transport->state) {
            case PA_BLUETOOTH_TRANSPORT_STATE_DISCONNECTED:
                continue;

            case PA_BLUETOOTH_TRANSPORT_STATE_IDLE:
                if (result == PA_AVAILABLE_NO)
                    result = PA_AVAILABLE_UNKNOWN;

                break;

            case PA_BLUETOOTH_TRANSPORT_STATE_PLAYING:
                return PA_AVAILABLE_YES;
        }
    }

    return result;
}

/* Run from main thread */
static pa_available_t transport_state_to_availability(pa_bluetooth_transport_state_t state) {
    switch (state) {
        case PA_BLUETOOTH_TRANSPORT_STATE_DISCONNECTED:
            return PA_AVAILABLE_NO;
        case PA_BLUETOOTH_TRANSPORT_STATE_PLAYING:
            return PA_AVAILABLE_YES;
        default:
            return PA_AVAILABLE_UNKNOWN;
    }
}

/* Run from main thread */
static void create_card_ports(struct userdata *u, pa_hashmap *ports) {
    pa_device_port *port;
    pa_device_port_new_data port_data;
    const char *name_prefix, *input_description, *output_description;

    pa_assert(u);
    pa_assert(ports);
    pa_assert(u->device);

    name_prefix = "unknown";
    input_description = _("Bluetooth Input");
    output_description = _("Bluetooth Output");

    switch (form_factor_from_class(u->device->class_of_device)) {
        case PA_BLUETOOTH_FORM_FACTOR_HEADSET:
            name_prefix = "headset";
            input_description = output_description = _("Headset");
            break;

        case PA_BLUETOOTH_FORM_FACTOR_HANDSFREE:
            name_prefix = "handsfree";
            input_description = output_description = _("Handsfree");
            break;

        case PA_BLUETOOTH_FORM_FACTOR_MICROPHONE:
            name_prefix = "microphone";
            input_description = _("Microphone");
            output_description = _("Bluetooth Output");
            break;

        case PA_BLUETOOTH_FORM_FACTOR_SPEAKER:
            name_prefix = "speaker";
            input_description = _("Bluetooth Input");
            output_description = _("Speaker");
            break;

        case PA_BLUETOOTH_FORM_FACTOR_HEADPHONE:
            name_prefix = "headphone";
            input_description = _("Bluetooth Input");
            output_description = _("Headphone");
            break;

        case PA_BLUETOOTH_FORM_FACTOR_PORTABLE:
            name_prefix = "portable";
            input_description = output_description = _("Portable");
            break;

        case PA_BLUETOOTH_FORM_FACTOR_CAR:
            name_prefix = "car";
            input_description = output_description = _("Car");
            break;

        case PA_BLUETOOTH_FORM_FACTOR_HIFI:
            name_prefix = "hifi";
            input_description = output_description = _("HiFi");
            break;

        case PA_BLUETOOTH_FORM_FACTOR_PHONE:
            name_prefix = "phone";
            input_description = output_description = _("Phone");
            break;

        case PA_BLUETOOTH_FORM_FACTOR_UNKNOWN:
            name_prefix = "unknown";
            input_description = _("Bluetooth Input");
            output_description = _("Bluetooth Output");
            break;
    }

    u->output_port_name = pa_sprintf_malloc("%s-output", name_prefix);
    pa_device_port_new_data_init(&port_data);
    pa_device_port_new_data_set_name(&port_data, u->output_port_name);
    pa_device_port_new_data_set_description(&port_data, output_description);
    pa_device_port_new_data_set_direction(&port_data, PA_DIRECTION_OUTPUT);
    pa_device_port_new_data_set_available(&port_data, get_port_availability(u, PA_DIRECTION_OUTPUT));
    pa_assert_se(port = pa_device_port_new(u->core, &port_data, 0));
    pa_assert_se(pa_hashmap_put(ports, port->name, port) >= 0);
    pa_device_port_new_data_done(&port_data);

    u->input_port_name = pa_sprintf_malloc("%s-input", name_prefix);
    pa_device_port_new_data_init(&port_data);
    pa_device_port_new_data_set_name(&port_data, u->input_port_name);
    pa_device_port_new_data_set_description(&port_data, input_description);
    pa_device_port_new_data_set_direction(&port_data, PA_DIRECTION_INPUT);
    pa_device_port_new_data_set_available(&port_data, get_port_availability(u, PA_DIRECTION_INPUT));
    pa_assert_se(port = pa_device_port_new(u->core, &port_data, 0));
    pa_assert_se(pa_hashmap_put(ports, port->name, port) >= 0);
    pa_device_port_new_data_done(&port_data);
}

/* Run from main thread */
static pa_card_profile *create_card_profile(struct userdata *u, pa_bluetooth_profile_t profile, pa_hashmap *ports) {
    pa_device_port *input_port, *output_port;
    const char *name;
    char *description;
    pa_card_profile *cp = NULL;
    pa_bluetooth_profile_t *p;
    const pa_a2dp_codec *a2dp_codec;
    bool is_a2dp_sink;
    bool support_backchannel;

    pa_assert(u->input_port_name);
    pa_assert(u->output_port_name);
    pa_assert_se(input_port = pa_hashmap_get(ports, u->input_port_name));
    pa_assert_se(output_port = pa_hashmap_get(ports, u->output_port_name));

    name = pa_bluetooth_profile_to_string(profile);

    if (profile == PA_BLUETOOTH_PROFILE_HSP_HEAD_UNIT ||
        profile == PA_BLUETOOTH_PROFILE_HFP_HEAD_UNIT ||
        profile == PA_BLUETOOTH_PROFILE_HSP_AUDIO_GATEWAY ||
        profile == PA_BLUETOOTH_PROFILE_HFP_AUDIO_GATEWAY) {
        if (profile == PA_BLUETOOTH_PROFILE_HSP_HEAD_UNIT)
            description = _("Headset Head Unit (HSP)");
        else if (profile == PA_BLUETOOTH_PROFILE_HFP_HEAD_UNIT)
            description = _("Headset Head Unit (HFP)");
        else if (profile == PA_BLUETOOTH_PROFILE_HSP_AUDIO_GATEWAY)
            description = _("Headset Audio Gateway (HSP)");
        else
            description = _("Headset Audio Gateway (HFP)");
        cp = pa_card_profile_new(name, description, sizeof(pa_bluetooth_profile_t));
        cp->priority = profile;
        cp->n_sinks = 1;
        cp->n_sources = 1;
        cp->max_sink_channels = 1;
        cp->max_source_channels = 1;
        pa_hashmap_put(input_port->profiles, cp->name, cp);
        pa_hashmap_put(output_port->profiles, cp->name, cp);

        p = PA_CARD_PROFILE_DATA(cp);
    } else if (pa_bluetooth_profile_is_a2dp(profile)) {
        a2dp_codec = pa_bluetooth_profile_to_a2dp_codec(profile);
        is_a2dp_sink = pa_bluetooth_profile_is_a2dp_sink(profile);
        support_backchannel = pa_bluetooth_profile_support_a2dp_backchannel(profile);

        if (is_a2dp_sink)
            description = pa_sprintf_malloc(_("High Fidelity Playback (A2DP Sink) with codec %s"), a2dp_codec->description);
        else
            description = pa_sprintf_malloc(_("High Fidelity Capture (A2DP Source) with codec %s"), a2dp_codec->description);

        cp = pa_card_profile_new(name, description, sizeof(pa_bluetooth_profile_t));
        pa_xfree(description);

        cp->priority = profile;

        if (is_a2dp_sink) {
            cp->n_sinks = 1;
            cp->n_sources = support_backchannel ? 1 : 0;
            cp->max_sink_channels = 2;
            cp->max_source_channels = support_backchannel ? 1 : 0;
        } else {
            cp->n_sinks = support_backchannel ? 1 : 0;
            cp->n_sources = 1;
            cp->max_sink_channels = support_backchannel ? 1 : 0;
            cp->max_source_channels = 2;
        }

        if (is_a2dp_sink || support_backchannel)
            pa_hashmap_put(output_port->profiles, cp->name, cp);

        if (!is_a2dp_sink || support_backchannel)
            pa_hashmap_put(input_port->profiles, cp->name, cp);

        p = PA_CARD_PROFILE_DATA(cp);
    } else {
        pa_assert_not_reached();
    }

    *p = profile;

    if (u->device->transports[*p])
        cp->available = transport_state_to_availability(u->device->transports[*p]->state);
    else
        cp->available = PA_AVAILABLE_NO;

    if (cp->available == PA_AVAILABLE_NO && u->support_a2dp_codec_switch &&
        (u->device->new_profile_in_progress ||
         (pa_bluetooth_profile_is_a2dp_sink(profile) && pa_bluetooth_device_a2dp_sink_transport_connected(u->device)) ||
         (pa_bluetooth_profile_is_a2dp_source(profile) && pa_bluetooth_device_a2dp_source_transport_connected(u->device))))
        cp->available = PA_AVAILABLE_UNKNOWN;

    return cp;
}

/* Run from main thread */
static int set_profile_cb(pa_card *c, pa_card_profile *new_profile) {
    struct userdata *u;
    pa_bluetooth_profile_t *p;

    pa_assert(c);
    pa_assert(new_profile);
    pa_assert_se(u = c->userdata);

    p = PA_CARD_PROFILE_DATA(new_profile);

    if (*p != PA_BLUETOOTH_PROFILE_OFF) {
        pa_bluetooth_device *d = u->device;

        d->new_profile_in_progress = 0;

        if (!d->transports[*p] || d->transports[*p]->state <= PA_BLUETOOTH_TRANSPORT_STATE_DISCONNECTED) {
            if (pa_bluetooth_profile_is_a2dp(*p) && u->support_a2dp_codec_switch) {
                if ((pa_bluetooth_profile_is_a2dp_sink(*p) && pa_bluetooth_device_a2dp_sink_transport_connected(d)) ||
                    (pa_bluetooth_profile_is_a2dp_source(*p) && pa_bluetooth_device_a2dp_source_transport_connected(d))) {
                    pa_log_info("Profile with different A2DP codec is in use, trying to asynchronously change it");
                    if (!pa_bluetooth_device_change_a2dp_profile(d, *p))
                        return -PA_ERR_IO;
                    d->new_profile_in_progress = *p;
                    /* profile changing is in progress now, return error from callback as new profile is not active yet */
                    return -PA_ERR_IO;
                }
            }

            pa_log_info("Profile %s is not connected yet, trying to asynchronously connect it", new_profile->name);
            pa_bluetooth_device_connect_profile(d, *p);
            d->new_profile_in_progress = *p;
            /* profile changing is in progress now, return error from callback as new profile is not active yet */
            return -PA_ERR_IO;
        }
    }

    stop_thread(u);

    u->profile = *p;

    if (u->profile != PA_BLUETOOTH_PROFILE_OFF)
        if (init_profile(u) < 0)
            goto off;

    if (u->sink || u->source)
        if (start_thread(u) < 0)
            goto off;

    return 0;

off:
    stop_thread(u);

    pa_assert_se(pa_card_set_profile(u->card, pa_hashmap_get(u->card->profiles, "off"), false) >= 0);

    return -PA_ERR_IO;
}

static void add_card_profile(pa_bluetooth_profile_t profile, pa_card_new_data *data, struct userdata *u) {
    pa_card_profile *cp;

    if (pa_hashmap_get(data->profiles, pa_bluetooth_profile_to_string(profile)))
        return;

    cp = create_card_profile(u, profile, data->ports);
    pa_hashmap_put(data->profiles, cp->name, cp);
}

static void choose_initial_profile(struct userdata *u) {
    pa_bluetooth_transport *transport;
    pa_card_profile *iter_profile;
    pa_card_profile *profile;
    void *state;

    pa_log_debug("Looking for A2DP profile which has active bluez transport for card %s", u->card->name);

    profile = NULL;

    /* Try to find the best A2DP profile with active transport */
    PA_HASHMAP_FOREACH(iter_profile, u->card->profiles, state) {
        transport = u->device->transports[*(pa_bluetooth_profile_t *)PA_CARD_PROFILE_DATA(iter_profile)];

        /* Ignore profiles without active bluez transport */
        if (!transport || transport->state == PA_BLUETOOTH_TRANSPORT_STATE_DISCONNECTED)
            continue;

        /* Ignore non-A2DP profiles */
        if (!pa_bluetooth_profile_is_a2dp(transport->profile))
            continue;

        pa_log_debug("%s has active bluez transport", iter_profile->name);

        if (!profile || iter_profile->priority > profile->priority)
            profile = iter_profile;
    }

    /* When there is no active A2DP bluez transport, fallback to core pulseaudio function for choosing initial profile */
    if (!profile) {
        pa_log_debug("No A2DP profile with bluez active transport was found for card %s", u->card->name);
        pa_card_choose_initial_profile(u->card);
        return;
    }

    /* Do same job as pa_card_choose_initial_profile() */
    pa_log_info("Setting initial A2DP profile '%s' for card %s", profile->name, u->card->name);
    u->card->active_profile = profile;
    u->card->save_profile = false;

    /* Let policy modules override the default. */
    pa_hook_fire(&u->card->core->hooks[PA_CORE_HOOK_CARD_CHOOSE_INITIAL_PROFILE], u->card);
}

/* Run from main thread */
static int add_card(struct userdata *u) {
    const pa_bluetooth_device *d;
    pa_card_new_data data;
    char *alias;
    pa_bluetooth_form_factor_t ff;
    pa_card_profile *cp;
    pa_bluetooth_profile_t *p;
    bool have_a2dp_sink;
    bool have_a2dp_source;
    const char *uuid;
    void *state;

    pa_assert(u);
    pa_assert(u->device);

    d = u->device;

    pa_card_new_data_init(&data);
    data.driver = __FILE__;
    data.module = u->module;

    alias = pa_utf8_filter(d->alias);
    pa_proplist_sets(data.proplist, PA_PROP_DEVICE_DESCRIPTION, alias);
    pa_xfree(alias);

    pa_proplist_sets(data.proplist, PA_PROP_DEVICE_STRING, d->address);
    pa_proplist_sets(data.proplist, PA_PROP_DEVICE_API, "bluez");
    pa_proplist_sets(data.proplist, PA_PROP_DEVICE_CLASS, "sound");
    pa_proplist_sets(data.proplist, PA_PROP_DEVICE_BUS, "bluetooth");

    if ((ff = form_factor_from_class(d->class_of_device)) != PA_BLUETOOTH_FORM_FACTOR_UNKNOWN)
        pa_proplist_sets(data.proplist, PA_PROP_DEVICE_FORM_FACTOR, form_factor_to_string(ff));

    pa_proplist_sets(data.proplist, "bluez.path", d->path);
    pa_proplist_setf(data.proplist, "bluez.class", "0x%06x", d->class_of_device);
    pa_proplist_sets(data.proplist, "bluez.alias", d->alias);
    data.name = pa_sprintf_malloc("bluez_card.%s", d->address);
    data.namereg_fail = false;

    create_card_ports(u, data.ports);

    have_a2dp_sink = false;
    have_a2dp_source = false;

    PA_HASHMAP_FOREACH(uuid, d->uuids, state) {
        pa_bluetooth_profile_t profile;

        if (pa_bluetooth_uuid_is_hsp_hs(uuid))
            profile = PA_BLUETOOTH_PROFILE_HSP_HEAD_UNIT;
        else if (pa_streq(uuid, PA_BLUETOOTH_UUID_HFP_HF))
            profile = PA_BLUETOOTH_PROFILE_HFP_HEAD_UNIT;
        else if (pa_streq(uuid, PA_BLUETOOTH_UUID_HSP_AG))
            profile = PA_BLUETOOTH_PROFILE_HSP_AUDIO_GATEWAY;
        else if (pa_streq(uuid, PA_BLUETOOTH_UUID_HFP_AG))
            profile = PA_BLUETOOTH_PROFILE_HFP_AUDIO_GATEWAY;
        else {
            if (pa_streq(uuid, PA_BLUETOOTH_UUID_A2DP_SINK))
                have_a2dp_sink = true;
            else if (pa_streq(uuid, PA_BLUETOOTH_UUID_A2DP_SOURCE))
                have_a2dp_source = true;
            continue;
        }

        add_card_profile(profile, &data, u);
    }

    if (have_a2dp_sink || have_a2dp_source) {
        if (!d->adapter->media_application_registered) {
            /*
             * We are running old version of bluez which does not announce supported codecs
             * by remote device nor does not support codec switching. Pulseaudio already
             * registered to bluez only SBC codec, so create only one profile for SBC codec.
             */
            pa_log_warn("Detected old bluez version, only SBC codec is supported");
            u->support_a2dp_codec_switch = false;

            if (have_a2dp_sink)
                add_card_profile(pa_bluetooth_profile_for_a2dp_codec("sbc", true), &data, u);

            if (have_a2dp_source)
                add_card_profile(pa_bluetooth_profile_for_a2dp_codec("sbc", false), &data, u);
        } else {
            const pa_a2dp_codec *a2dp_codec;
            pa_bluetooth_profile_t profile;
            const char *endpoint;
            unsigned i, count;

            u->support_a2dp_codec_switch = true;

            count = pa_bluetooth_a2dp_codec_count();
            for (i = 0; i < count; i++) {
                a2dp_codec = pa_bluetooth_a2dp_codec_iter(i);

                if (pa_bluetooth_device_find_a2dp_endpoints_for_codec(d, a2dp_codec, true, &endpoint, 1) > 0) {
                    profile = pa_bluetooth_profile_for_a2dp_codec(a2dp_codec->name, true);
                    add_card_profile(profile, &data, u);
                    pa_log_info("Detected codec %s on sink endpoint %s", a2dp_codec->name, endpoint);
                }

                if (pa_bluetooth_device_find_a2dp_endpoints_for_codec(d, a2dp_codec, false, &endpoint, 1) > 0) {
                    profile = pa_bluetooth_profile_for_a2dp_codec(a2dp_codec->name, false);
                    add_card_profile(profile, &data, u);
                    pa_log_info("Detected codec %s on source endpoint %s", a2dp_codec->name, endpoint);
                }
            }
        }
    }

    pa_assert(!pa_hashmap_isempty(data.profiles));

    cp = pa_card_profile_new("off", _("Off"), sizeof(pa_bluetooth_profile_t));
    cp->available = PA_AVAILABLE_YES;
    p = PA_CARD_PROFILE_DATA(cp);
    *p = PA_BLUETOOTH_PROFILE_OFF;
    pa_hashmap_put(data.profiles, cp->name, cp);

    u->card = pa_card_new(u->core, &data);
    pa_card_new_data_done(&data);
    if (!u->card) {
        pa_log("Failed to allocate card.");
        return -1;
    }

    u->card->userdata = u;
    u->card->set_profile = set_profile_cb;
    choose_initial_profile(u);
    pa_card_put(u->card);

    p = PA_CARD_PROFILE_DATA(u->card->active_profile);
    u->profile = *p;

    return 0;
}

/* Run from main thread */
static void handle_transport_state_change(struct userdata *u, struct pa_bluetooth_transport *t) {
    bool acquire = false;
    bool release = false;
    pa_card_profile *cp;
    pa_device_port *port;
    pa_available_t oldavail;
    pa_available_t newavail;

    pa_assert(u);
    pa_assert(t);

    cp = pa_hashmap_get(u->card->profiles, pa_bluetooth_profile_to_string(t->profile));
    if (!cp) {
        /* Profile does not exist or associated A2DP codec is not supported, switch to off */
        pa_assert_se(pa_card_set_profile(u->card, pa_hashmap_get(u->card->profiles, "off"), false) >= 0);
        return;
    }

    oldavail = cp->available;

    newavail = transport_state_to_availability(t->state);

    if (u->support_a2dp_codec_switch && pa_bluetooth_profile_is_a2dp(t->profile)) {
        pa_card_profile *iter_cp;
        void *state;

        if (newavail == PA_AVAILABLE_NO &&
            (u->device->new_profile_in_progress ||
             (pa_bluetooth_profile_is_a2dp_sink(t->profile) && pa_bluetooth_device_a2dp_sink_transport_connected(u->device)) ||
             (pa_bluetooth_profile_is_a2dp_source(t->profile) && pa_bluetooth_device_a2dp_source_transport_connected(u->device)))) {
            newavail = PA_AVAILABLE_UNKNOWN;
        }

        /* Change availability for other profiles (except current) in same A2DP category (sink / source) */
        PA_HASHMAP_FOREACH(iter_cp, u->card->profiles, state) {
            if (cp == iter_cp)
                continue;
            if (!pa_startswith(iter_cp->name, "a2dp_"))
                continue;
            if (pa_bluetooth_profile_is_a2dp_sink(t->profile) && !pa_startswith(iter_cp->name, "a2dp_sink"))
                continue;
            if (pa_bluetooth_profile_is_a2dp_source(t->profile) && !pa_startswith(iter_cp->name, "a2dp_source"))
                continue;
            /* Do not set PA_AVAILABLE_YES for other profiles */
            pa_card_profile_set_available(iter_cp, (newavail == PA_AVAILABLE_YES) ? PA_AVAILABLE_UNKNOWN : newavail);
        }
    }

    pa_card_profile_set_available(cp, newavail);

    /* Update port availability */
    pa_assert_se(port = pa_hashmap_get(u->card->ports, u->output_port_name));
    pa_device_port_set_available(port, get_port_availability(u, PA_DIRECTION_OUTPUT));
    pa_assert_se(port = pa_hashmap_get(u->card->ports, u->input_port_name));
    pa_device_port_set_available(port, get_port_availability(u, PA_DIRECTION_INPUT));

    /* Acquire or release transport as needed */
    acquire = (t->state == PA_BLUETOOTH_TRANSPORT_STATE_PLAYING && u->profile == t->profile);
    release = (oldavail != PA_AVAILABLE_NO && t->state != PA_BLUETOOTH_TRANSPORT_STATE_PLAYING && u->profile == t->profile);

    if (acquire && transport_acquire(u) >= 0) {
        if (u->source) {
            pa_log_debug("Resuming source %s because its transport state changed to playing", u->source->name);

            /* When the ofono backend resumes source or sink when in the audio gateway role, the
             * state of source or sink may already be RUNNING before the transport is acquired via
             * hf_audio_agent_new_connection(), so the pa_source_suspend() call will not lead to a
             * state change message. In this case we explicitly need to signal the I/O thread to
             * set up the stream. */
            if (PA_SOURCE_IS_OPENED(u->source->state))
                pa_asyncmsgq_send(u->source->asyncmsgq, PA_MSGOBJECT(u->source), PA_SOURCE_MESSAGE_SETUP_STREAM, NULL, 0, NULL);

            /* We remove the IDLE suspend cause, because otherwise
             * module-loopback doesn't uncork its streams. FIXME: Messing with
             * the IDLE suspend cause here is wrong, the correct way to handle
             * this would probably be to uncork the loopback streams not only
             * when the other end is unsuspended, but also when the other end's
             * suspend cause changes to IDLE only (currently there's no
             * notification mechanism for suspend cause changes, though). */
            pa_source_suspend(u->source, false, PA_SUSPEND_IDLE|PA_SUSPEND_USER);
        }

        if (u->sink) {
            pa_log_debug("Resuming sink %s because its transport state changed to playing", u->sink->name);

            /* Same comment as above */
            if (PA_SINK_IS_OPENED(u->sink->state))
                pa_asyncmsgq_send(u->sink->asyncmsgq, PA_MSGOBJECT(u->sink), PA_SINK_MESSAGE_SETUP_STREAM, NULL, 0, NULL);

            /* FIXME: See the previous comment. */
            pa_sink_suspend(u->sink, false, PA_SUSPEND_IDLE|PA_SUSPEND_USER);
        }
    }

    if (release && u->transport_acquired) {
        /* FIXME: this release is racy, since the audio stream might have
         * been set up again in the meantime (but not processed yet by PA).
         * BlueZ should probably release the transport automatically, and in
         * that case we would just mark the transport as released */

        /* Remote side closed the stream so we consider it PA_SUSPEND_USER */
        if (u->source) {
            pa_log_debug("Suspending source %s because the remote end closed the stream", u->source->name);
            pa_source_suspend(u->source, true, PA_SUSPEND_USER);
        }

        if (u->sink) {
            pa_log_debug("Suspending sink %s because the remote end closed the stream", u->sink->name);
            pa_sink_suspend(u->sink, true, PA_SUSPEND_USER);
        }
    }
}

/* Run from main thread */
static pa_hook_result_t device_connection_changed_cb(pa_bluetooth_discovery *y, const pa_bluetooth_device *d, struct userdata *u) {
    pa_assert(d);
    pa_assert(u);

    if (d != u->device || pa_bluetooth_device_any_transport_connected(d) || d->new_profile_in_progress)
        return PA_HOOK_OK;

    pa_log_debug("Unloading module for device %s", d->path);
    pa_module_unload(u->module, true);

    return PA_HOOK_OK;
}

/* Run from main thread */
static pa_hook_result_t profile_connection_changed_cb(pa_bluetooth_discovery *y, const struct pa_bluetooth_device_and_profile *device_and_profile, struct userdata *u) {
    const pa_bluetooth_device *d = device_and_profile->device;
    pa_bluetooth_profile_t p = device_and_profile->profile;
    pa_bluetooth_status s = device_and_profile->status;
    pa_bluetooth_transport *t;
    pa_card_profile *cp;

    pa_assert(d);
    pa_assert(p);
    pa_assert(u);

    if (d != u->device || !u->device->new_profile_in_progress)
        return PA_HOOK_OK;

    pa_assert(p != PA_BLUETOOTH_PROFILE_OFF);

    if (p == u->device->new_profile_in_progress ||
        (u->support_a2dp_codec_switch &&
         ((pa_bluetooth_profile_is_a2dp_sink(p) && pa_bluetooth_profile_is_a2dp_sink(u->device->new_profile_in_progress)) ||
          (pa_bluetooth_profile_is_a2dp_source(p) && pa_bluetooth_profile_is_a2dp_source(u->device->new_profile_in_progress))))) {

        /* Asynchronous operation for profile change finished */
        u->device->new_profile_in_progress = 0;

        t = u->device->transports[p];
        if ((t && t->state > PA_BLUETOOTH_TRANSPORT_STATE_DISCONNECTED) ||
            (u->support_a2dp_codec_switch &&
             ((pa_bluetooth_profile_is_a2dp_sink(p) && pa_bluetooth_device_a2dp_sink_transport_connected(u->device)) ||
              (pa_bluetooth_profile_is_a2dp_source(p) && pa_bluetooth_device_a2dp_source_transport_connected(u->device))))) {
            /* Activate newly connected profile */
            pa_assert_se(cp = pa_hashmap_get(u->card->profiles, pa_bluetooth_profile_to_string(p)));
            pa_card_set_profile(u->card, cp, true);
        } else if (s != PA_BLUETOOTH_STATUS_NOTAVAILABLE) {
            /* Some bluetooth headsets do not allow connecting both HSP and HFP profile at the same time
             * Try to first disconnect one profile and then connect second profile
             * But do not try it when previous attempt failed with error "NotAvailable", it means hsphfpd or pulseaudio cannot handle that profile */
            u->device->new_profile_in_progress = p;
            if (p == PA_BLUETOOTH_PROFILE_HSP_HEAD_UNIT && u->device->transports[PA_BLUETOOTH_PROFILE_HFP_HEAD_UNIT] && u->device->transports[PA_BLUETOOTH_PROFILE_HFP_HEAD_UNIT]->state >= PA_BLUETOOTH_TRANSPORT_STATE_DISCONNECTED)
                pa_bluetooth_device_disconnect_and_connect_profile(u->device, PA_BLUETOOTH_PROFILE_HFP_HEAD_UNIT, PA_BLUETOOTH_PROFILE_HSP_HEAD_UNIT);
            else if (p == PA_BLUETOOTH_PROFILE_HFP_HEAD_UNIT && u->device->transports[PA_BLUETOOTH_PROFILE_HSP_HEAD_UNIT] && u->device->transports[PA_BLUETOOTH_PROFILE_HSP_HEAD_UNIT]->state >= PA_BLUETOOTH_TRANSPORT_STATE_DISCONNECTED)
                pa_bluetooth_device_disconnect_and_connect_profile(u->device, PA_BLUETOOTH_PROFILE_HSP_HEAD_UNIT, PA_BLUETOOTH_PROFILE_HFP_HEAD_UNIT);
            else if (p == PA_BLUETOOTH_PROFILE_HSP_AUDIO_GATEWAY && u->device->transports[PA_BLUETOOTH_PROFILE_HFP_AUDIO_GATEWAY] && u->device->transports[PA_BLUETOOTH_PROFILE_HFP_AUDIO_GATEWAY]->state >= PA_BLUETOOTH_TRANSPORT_STATE_DISCONNECTED)
                pa_bluetooth_device_disconnect_and_connect_profile(u->device, PA_BLUETOOTH_PROFILE_HFP_AUDIO_GATEWAY, PA_BLUETOOTH_PROFILE_HSP_AUDIO_GATEWAY);
            else if (p == PA_BLUETOOTH_PROFILE_HFP_AUDIO_GATEWAY && u->device->transports[PA_BLUETOOTH_PROFILE_HSP_AUDIO_GATEWAY] && u->device->transports[PA_BLUETOOTH_PROFILE_HSP_AUDIO_GATEWAY]->state >= PA_BLUETOOTH_TRANSPORT_STATE_DISCONNECTED)
                pa_bluetooth_device_disconnect_and_connect_profile(u->device, PA_BLUETOOTH_PROFILE_HSP_AUDIO_GATEWAY, PA_BLUETOOTH_PROFILE_HFP_AUDIO_GATEWAY);
            else
                u->device->new_profile_in_progress = 0;
        }
    }

    return PA_HOOK_OK;
}

/* Run from main thread */
static pa_hook_result_t transport_state_changed_cb(pa_bluetooth_discovery *y, pa_bluetooth_transport *t, struct userdata *u) {
    pa_assert(t);
    pa_assert(u);

    if (t == u->transport && t->state <= PA_BLUETOOTH_TRANSPORT_STATE_DISCONNECTED)
        pa_assert_se(pa_card_set_profile(u->card, pa_hashmap_get(u->card->profiles, "off"), false) >= 0);

    if (t->device == u->device)
        handle_transport_state_change(u, t);

    return PA_HOOK_OK;
}

static pa_hook_result_t transport_tx_volume_gain_changed_cb(pa_bluetooth_discovery *y, pa_bluetooth_transport *t, struct userdata *u) {
    pa_volume_t volume;
    pa_cvolume v;
    uint16_t gain;

    pa_assert(t);
    pa_assert(u);

    if (t != u->transport)
      return PA_HOOK_OK;

    gain = t->tx_volume_gain;
    volume = (pa_volume_t) (gain * PA_VOLUME_NORM / t->max_tx_volume_gain);

    /* increment volume by one to correct rounding errors */
    if (volume < PA_VOLUME_NORM)
        volume++;

    pa_cvolume_set(&v, u->encoder_sample_spec.channels, volume);

    if (!t->tx_soft_volume)
        pa_sink_volume_changed(u->sink, &v);
    else
        pa_sink_set_volume(u->sink, &v, true, true);

    return PA_HOOK_OK;
}

static pa_hook_result_t transport_rx_volume_gain_changed_cb(pa_bluetooth_discovery *y, pa_bluetooth_transport *t, struct userdata *u) {
    pa_volume_t volume;
    pa_cvolume v;
    uint16_t gain;

    pa_assert(t);
    pa_assert(u);

    if (t != u->transport)
      return PA_HOOK_OK;

    gain = t->rx_volume_gain;
    volume = (pa_volume_t) (gain * PA_VOLUME_NORM / t->max_rx_volume_gain);

    /* increment volume by one to correct rounding errors */
    if (volume < PA_VOLUME_NORM)
        volume++;

    pa_cvolume_set(&v, u->decoder_sample_spec.channels, volume);

    if (!t->rx_soft_volume)
        pa_source_volume_changed(u->source, &v);
    else
        pa_source_set_volume(u->source, &v, true, true);

    return PA_HOOK_OK;
}

/* Run from main thread context */
static int device_process_msg(pa_msgobject *obj, int code, void *data, int64_t offset, pa_memchunk *chunk) {
    struct bluetooth_msg *m = BLUETOOTH_MSG(obj);
    struct userdata *u = m->card->userdata;

    switch (code) {
        case BLUETOOTH_MESSAGE_IO_THREAD_FAILED:
            if (m->card->module->unload_requested)
                break;

            pa_log_debug("Switching the profile to off due to IO thread failure.");
            pa_assert_se(pa_card_set_profile(m->card, pa_hashmap_get(m->card->profiles, "off"), false) >= 0);
            break;
        case BLUETOOTH_MESSAGE_STREAM_FD_HUP:
            if (u->transport->state > PA_BLUETOOTH_TRANSPORT_STATE_IDLE)
                pa_bluetooth_transport_set_state(u->transport, PA_BLUETOOTH_TRANSPORT_STATE_IDLE);
            break;
        case BLUETOOTH_MESSAGE_SET_TRANSPORT_PLAYING:
            /* transport_acquired needs to be checked here, because a message could have been
             * pending when the profile was switched. If the new transport has been acquired
             * correctly, the call below will have no effect because the transport state is
             * already PLAYING. If transport_acquire() failed for the new profile, the transport
             * state should not be changed. If the transport has been released for other reasons
             * (I/O thread shutdown), transport_acquired will also be false. */
            if (u->transport_acquired)
                pa_bluetooth_transport_set_state(u->transport, PA_BLUETOOTH_TRANSPORT_STATE_PLAYING);
            break;
    }

    return 0;
}

int pa__init(pa_module* m) {
    struct userdata *u;
    const char *path;
    pa_modargs *ma;

    pa_assert(m);

    m->userdata = u = pa_xnew0(struct userdata, 1);
    u->module = m;
    u->core = m->core;

    if (!(ma = pa_modargs_new(m->argument, valid_modargs))) {
        pa_log_error("Failed to parse module arguments");
        goto fail_free_modargs;
    }

    if (!(path = pa_modargs_get_value(ma, "path", NULL))) {
        pa_log_error("Failed to get device path from module arguments");
        goto fail_free_modargs;
    }

    if ((u->discovery = pa_shared_get(u->core, "bluetooth-discovery")))
        pa_bluetooth_discovery_ref(u->discovery);
    else {
        pa_log_error("module-bluez5-discover doesn't seem to be loaded, refusing to load module-bluez5-device");
        goto fail_free_modargs;
    }

    if (!(u->device = pa_bluetooth_discovery_get_device_by_path(u->discovery, path))) {
        pa_log_error("%s is unknown", path);
        goto fail_free_modargs;
    }

    pa_modargs_free(ma);

    u->device_connection_changed_slot =
        pa_hook_connect(pa_bluetooth_discovery_hook(u->discovery, PA_BLUETOOTH_HOOK_DEVICE_CONNECTION_CHANGED),
                        PA_HOOK_NORMAL, (pa_hook_cb_t) device_connection_changed_cb, u);

    u->profile_connection_changed_slot =
        pa_hook_connect(pa_bluetooth_discovery_hook(u->discovery, PA_BLUETOOTH_HOOK_PROFILE_CONNECTION_CHANGED),
                        PA_HOOK_NORMAL, (pa_hook_cb_t) profile_connection_changed_cb, u);

    u->transport_state_changed_slot =
        pa_hook_connect(pa_bluetooth_discovery_hook(u->discovery, PA_BLUETOOTH_HOOK_TRANSPORT_STATE_CHANGED),
                        PA_HOOK_NORMAL, (pa_hook_cb_t) transport_state_changed_cb, u);

    u->transport_rx_volume_gain_changed_slot =
        pa_hook_connect(pa_bluetooth_discovery_hook(u->discovery, PA_BLUETOOTH_HOOK_TRANSPORT_RX_VOLUME_GAIN_CHANGED), PA_HOOK_NORMAL, (pa_hook_cb_t) transport_rx_volume_gain_changed_cb, u);

    u->transport_tx_volume_gain_changed_slot =
        pa_hook_connect(pa_bluetooth_discovery_hook(u->discovery, PA_BLUETOOTH_HOOK_TRANSPORT_TX_VOLUME_GAIN_CHANGED), PA_HOOK_NORMAL, (pa_hook_cb_t) transport_tx_volume_gain_changed_cb, u);

    if (add_card(u) < 0)
        goto fail;

    if (!(u->msg = pa_msgobject_new(bluetooth_msg)))
        goto fail;

    u->msg->parent.process_msg = device_process_msg;
    u->msg->card = u->card;
    u->stream_setup_done = false;

    if (u->profile != PA_BLUETOOTH_PROFILE_OFF)
        if (init_profile(u) < 0)
            goto off;

    if (u->sink || u->source)
        if (start_thread(u) < 0)
            goto off;

    return 0;

off:
    stop_thread(u);

    pa_assert_se(pa_card_set_profile(u->card, pa_hashmap_get(u->card->profiles, "off"), false) >= 0);

    return 0;

fail_free_modargs:

    if (ma)
        pa_modargs_free(ma);

fail:

    pa__done(m);

    return -1;
}

void pa__done(pa_module *m) {
    struct userdata *u;

    pa_assert(m);

    if (!(u = m->userdata))
        return;

    stop_thread(u);

    if (u->device_connection_changed_slot)
        pa_hook_slot_free(u->device_connection_changed_slot);

    if (u->profile_connection_changed_slot)
        pa_hook_slot_free(u->profile_connection_changed_slot);

    if (u->transport_state_changed_slot)
        pa_hook_slot_free(u->transport_state_changed_slot);

    if (u->transport_rx_volume_gain_changed_slot)
        pa_hook_slot_free(u->transport_rx_volume_gain_changed_slot);

    if (u->transport_tx_volume_gain_changed_slot)
        pa_hook_slot_free(u->transport_tx_volume_gain_changed_slot);

    if (u->encoder_buffer)
        pa_xfree(u->encoder_buffer);

    if (u->decoder_buffer)
        pa_xfree(u->decoder_buffer);

    if (u->msg)
        pa_xfree(u->msg);

    if (u->card)
        pa_card_free(u->card);

    if (u->discovery)
        pa_bluetooth_discovery_unref(u->discovery);

    pa_xfree(u->output_port_name);
    pa_xfree(u->input_port_name);

    pa_xfree(u);
}

int pa__get_n_used(pa_module *m) {
    struct userdata *u;

    pa_assert(m);
    pa_assert_se(u = m->userdata);

    return (u->sink ? pa_sink_linked_by(u->sink) : 0) + (u->source ? pa_source_linked_by(u->source) : 0);
}
