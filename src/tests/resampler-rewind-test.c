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

#include <stdio.h>
#include <getopt.h>
#include <locale.h>
#include <math.h>

#include <pulse/pulseaudio.h>

#include <pulse/rtclock.h>
#include <pulse/sample.h>
#include <pulse/volume.h>

#include <pulsecore/i18n.h>
#include <pulsecore/log.h>
#include <pulsecore/resampler.h>
#include <pulsecore/macro.h>
#include <pulsecore/endianmacros.h>
#include <pulsecore/memblock.h>
#include <pulsecore/memblockq.h>
#include <pulsecore/sample-util.h>
#include <pulsecore/core-util.h>

#define MEMBLOCKQ_MAXLENGTH (16*1024*1024)
#define PA_SILENCE_MAX (pa_page_size()*16)
#define MAX_MATCHING_PERIOD 500

static pa_memblock *silence_memblock_new(pa_mempool *pool, uint8_t c) {
    pa_memblock *b;
    size_t length;
    void *data;

    pa_assert(pool);

    length = PA_MIN(pa_mempool_block_size_max(pool), PA_SILENCE_MAX);

    b = pa_memblock_new(pool, length);

    data = pa_memblock_acquire(b);
    memset(data, c, length);
    pa_memblock_release(b);

    pa_memblock_set_is_silence(b, true);

    return b;
}

static size_t convert_to_input_length(pa_resampler *r, pa_sample_spec *in_spec, pa_sample_spec *out_spec, size_t length) {

    /* Transform from output to input domain */
    length = pa_resampler_request(r, length);

    if (in_spec->rate < out_spec->rate && length > 0)
        length = length - pa_frame_size(in_spec);

    return length;
}

static size_t get_matching_period(unsigned in_rate, unsigned out_rate) {
    unsigned gcd, n;

    /* Calculate GCD */
    gcd = in_rate;
    n = out_rate;
    while(gcd != n) {
        if(gcd > n)
            gcd -= n;
        else
            n -= gcd;
    }
    pa_log_debug("GCD is %u", gcd);

    n = in_rate / gcd;
    if (n > MAX_MATCHING_PERIOD)
        n = in_rate / 500;

    pa_log_debug("Using matching period %u", n);

    return n;
}

/* Calculate number of history bytes needed for the rewind */
static size_t calculate_resampler_history_bytes(pa_resampler *r, size_t in_rewind_frames, pa_sample_spec *in_ss, pa_sample_spec *out_ss) {
    size_t history_frames, matching_period, rounded_rewind_frames;

    /* Get the current internal delay of the resampler. Round down. */
    history_frames = pa_resampler_get_delay(r);

    /* Make the total rewind including history equal to a multiple of the matching period */
    matching_period = get_matching_period(in_ss->rate, out_ss->rate);
    rounded_rewind_frames = PA_ROUND_UP(in_rewind_frames + history_frames, matching_period);
    history_frames = rounded_rewind_frames - in_rewind_frames;

    return history_frames * pa_frame_size(in_ss);
}

static float compare_blocks(const pa_sample_spec *ss, const pa_memchunk *chunk_a, const pa_memchunk *chunk_b) {
    float *a, *b, max_diff = 0;
    unsigned i;

    a = pa_memblock_acquire(chunk_a->memblock);
    b = pa_memblock_acquire(chunk_b->memblock);
    a += chunk_a->index / pa_frame_size(ss);
    b += chunk_b->index / pa_frame_size(ss);

    for (i = 0; i < chunk_a->length / pa_frame_size(ss); i++) {
        if (fabs(a[i] - b[i]) > max_diff)
            max_diff = fabs(a[i] - b[i]);
    }

    pa_memblock_release(chunk_a->memblock);
    pa_memblock_release(chunk_b->memblock);

    return max_diff;
}

static pa_memblock* generate_block(pa_mempool *pool, const pa_sample_spec *ss, unsigned frequency, size_t nr_of_samples) {
    pa_memblock *r;
    float *d;
    float val;
    unsigned i;
    int n;
    float t, dt, dt_period;

    pa_assert(frequency);
    pa_assert(nr_of_samples);
    pa_assert(ss->channels == 1);
    pa_assert(ss->format == PA_SAMPLE_FLOAT32NE);

    pa_assert_se(r = pa_memblock_new(pool, pa_frame_size(ss) * nr_of_samples));
    d = pa_memblock_acquire(r);

    /* Generate square wave with given length, frequency and sample rate. */
    val = 0.5;
    t = 0;
    n = 1;
    dt = 1 / ss->rate;
    dt_period = 1 / frequency;
    for (i=0; i < nr_of_samples; i++) {
        d[i] = val;

        if ((int)(2 * t / dt_period) > n) {
            n++;
            if (val > 0)
                val = -0.5;
            else
                val = 0.5;
        }

        t += dt;
    }

    pa_memblock_release(r);

    return r;
}

static void help(const char *argv0) {
    printf("%s [options]\n\n"
           "-h, --help                            Show this help\n"
           "-v, --verbose                         Print debug messages\n"
           "      --from-rate=SAMPLERATE          From sample rate in Hz (defaults to 44100)\n"
           "      --to-rate=SAMPLERATE            To sample rate in Hz (defaults to 44100)\n"
           "      --resample-method=METHOD        Resample method (defaults to auto)\n"
           "      --frequency=unsigned            Frequency of square wave\n"
           "      --samples=unsigned              Number of samples for square wave\n"
           "      --rewind=unsigned               Number of output samples to rewind\n"
           "\n"
           "This test generates samples for a square wave of given frequency, number of samples\n"
           "and input sample rate. Then this input data is resampled to the output rate, rewound\n"
           "by rewind samples and the rewound part is processed again. Then output is compared to\n"
           "the result of the first pass.\n"
           "\n"
           "See --dump-resample-methods for possible values of resample methods.\n",
           argv0);
}

enum {
    ARG_VERSION = 256,
    ARG_FROM_SAMPLERATE,
    ARG_TO_SAMPLERATE,
    ARG_FREQUENCY,
    ARG_SAMPLES,
    ARG_REWIND,
    ARG_RESAMPLE_METHOD,
    ARG_DUMP_RESAMPLE_METHODS
};

static void dump_resample_methods(void) {
    int i;

    for (i = 0; i < PA_RESAMPLER_MAX; i++)
        if (pa_resample_method_supported(i))
            printf("%s\n", pa_resample_method_to_string(i));

}

int main(int argc, char *argv[]) {
    pa_mempool *pool = NULL;
    pa_sample_spec a, b;
    pa_resample_method_t method;
    int ret = 1, c;
    unsigned samples, frequency, rewind;
    unsigned crossover_freq = 120;
    pa_resampler *resampler;
    pa_memchunk in_chunk, out_chunk, rewound_chunk, silence_chunk;
    pa_usec_t ts;
    pa_memblockq *history_queue;
    size_t in_rewind_size, in_frame_size, history_size, out_rewind_size, old_length;
    float max_diff;

    static const struct option long_options[] = {
        {"help",                  0, NULL, 'h'},
        {"verbose",               0, NULL, 'v'},
        {"version",               0, NULL, ARG_VERSION},
        {"from-rate",             1, NULL, ARG_FROM_SAMPLERATE},
        {"to-rate",               1, NULL, ARG_TO_SAMPLERATE},
        {"frequency",             1, NULL, ARG_FREQUENCY},
        {"samples",               1, NULL, ARG_SAMPLES},
        {"rewind",                1, NULL, ARG_REWIND},
        {"resample-method",       1, NULL, ARG_RESAMPLE_METHOD},
        {"dump-resample-methods", 0, NULL, ARG_DUMP_RESAMPLE_METHODS},
        {NULL,                    0, NULL, 0}
    };

    setlocale(LC_ALL, "");
#ifdef ENABLE_NLS
    bindtextdomain(GETTEXT_PACKAGE, PULSE_LOCALEDIR);
#endif

    pa_log_set_level(PA_LOG_WARN);
    if (!getenv("MAKE_CHECK"))
        pa_log_set_level(PA_LOG_INFO);

    a.channels = b.channels = 1;
    a.rate = 48000;
    b.rate = 44100;
    a.format = b.format = PA_SAMPLE_FLOAT32NE;

    method = PA_RESAMPLER_AUTO;
    frequency = 1000;
    samples = 5000;
    rewind = 2500;

    while ((c = getopt_long(argc, argv, "hv", long_options, NULL)) != -1) {

        switch (c) {
            case 'h' :
                help(argv[0]);
                ret = 0;
                goto quit;

            case 'v':
                pa_log_set_level(PA_LOG_DEBUG);
                break;

            case ARG_VERSION:
                printf("%s %s\n", argv[0], PACKAGE_VERSION);
                ret = 0;
                goto quit;

            case ARG_DUMP_RESAMPLE_METHODS:
                dump_resample_methods();
                ret = 0;
                goto quit;

            case ARG_FROM_SAMPLERATE:
                a.rate = (uint32_t) atoi(optarg);
                break;

            case ARG_TO_SAMPLERATE:
                b.rate = (uint32_t) atoi(optarg);
                break;

            case ARG_FREQUENCY:
                frequency = (unsigned) atoi(optarg);
                break;

            case ARG_SAMPLES:
                samples = (unsigned) atoi(optarg);
                break;

            case ARG_REWIND:
                rewind = (unsigned) atoi(optarg);
                break;

            case ARG_RESAMPLE_METHOD:
                if (*optarg == '\0' || pa_streq(optarg, "help")) {
                    dump_resample_methods();
                    ret = 0;
                    goto quit;
                }
                method = pa_parse_resample_method(optarg);
                break;

            default:
                goto quit;
        }
    }

    pa_log_info("=== Square wave %u Hz, %u samples. Resampling using %s from %u Hz to %u Hz, rewinding %u output samples.", frequency,
                   samples, pa_resample_method_to_string(method), a.rate, b.rate, rewind);

    ret = 0;
    pa_assert_se(pool = pa_mempool_new(PA_MEM_TYPE_PRIVATE, 0, true));

    pa_log_debug("Compilation CFLAGS: %s", PA_CFLAGS);

    /* Setup resampler */
    ts = pa_rtclock_now();
    pa_assert_se(resampler = pa_resampler_new(pool, &a, NULL, &b, NULL, crossover_freq, method, 0));
    pa_log_info("Init took %llu usec", (long long unsigned)(pa_rtclock_now() - ts));

    /* Generate input data */
    in_chunk.memblock = generate_block(pool, &a, frequency, samples);
    in_chunk.length = pa_memblock_get_length(in_chunk.memblock);
    in_chunk.index = 0;
    in_frame_size = pa_frame_size(&a);

    /* First, resample the full block */
    ts = pa_rtclock_now();
    pa_resampler_run(resampler, &in_chunk, &out_chunk);
    if (!out_chunk.memblock) {
        pa_memblock_unref(in_chunk.memblock);
        ret = 1;
        goto quit;
    }

    pa_log_info("resampling took %llu usec.", (long long unsigned)(pa_rtclock_now() - ts));

    /* Create and prepare history queue */
    silence_chunk.memblock = silence_memblock_new(pool, 0);
    silence_chunk.length = pa_frame_align(pa_memblock_get_length(silence_chunk.memblock), &a);
    silence_chunk.index = 0;
    history_queue = pa_memblockq_new("Test-Queue", 0, MEMBLOCKQ_MAXLENGTH, 0, &a, 0, 1, samples * in_frame_size, &silence_chunk);
    pa_memblock_unref(silence_chunk.memblock);

    pa_memblockq_push(history_queue, &in_chunk);
    pa_memblockq_drop(history_queue, samples * in_frame_size);

    in_rewind_size = convert_to_input_length(resampler, &a, &b, rewind * pa_frame_size(&b));
    out_rewind_size = rewind * pa_frame_size(&b);
    pa_log_debug("Have to rewind %lu input frames", in_rewind_size / in_frame_size);
    ts = pa_rtclock_now();

    /* Now rewind the resampler */
    pa_memblockq_rewind(history_queue, in_rewind_size);
    history_size = calculate_resampler_history_bytes(resampler, in_rewind_size / in_frame_size, &a, &b);
    pa_log_debug("History is %lu frames.", history_size / in_frame_size);
    pa_resampler_rewind(resampler, out_rewind_size, history_queue, history_size);

    pa_log_info("Rewind took %llu usec.", (long long unsigned)(pa_rtclock_now() - ts));
    ts = pa_rtclock_now();

    /* Re-run the resampler */
    old_length = in_chunk.length;
    in_chunk.length = in_rewind_size;
    in_chunk.index = old_length - in_chunk.length;
    pa_resampler_run(resampler, &in_chunk, &rewound_chunk);
    if (!rewound_chunk.memblock) {
        ret = 1;
        goto quit1;
    }

    pa_log_info("Second resampler run took %llu usec.", (long long unsigned)(pa_rtclock_now() - ts));
    pa_log_debug("Got %lu output frames", rewound_chunk.length / pa_frame_size(&b));
    old_length = out_chunk.length;
    out_chunk.length = rewound_chunk.length;
    out_chunk.index = old_length - out_chunk.length;

    max_diff = compare_blocks(&b, &out_chunk, &rewound_chunk);
    pa_log_info("Maximum difference is %.*g", 6, max_diff);

    pa_memblock_unref(rewound_chunk.memblock);

quit1:
    pa_memblock_unref(in_chunk.memblock);
    pa_memblock_unref(out_chunk.memblock);

    pa_resampler_free(resampler);
    pa_memblockq_free(history_queue);

quit:
    if (pool)
        pa_mempool_unref(pool);

    return ret;
}
