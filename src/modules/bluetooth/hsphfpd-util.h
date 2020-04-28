#ifndef foohsphfpdutilhfoo
#define foohsphfpdutilhfoo

/***
  This file is part of PulseAudio.

  Copyrigth 2020 Pali Rohár <pali.rohar@gmail.com>

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

#include <pulsecore/core.h>

typedef struct pa_bluetooth_hsphfpd pa_bluetooth_hsphfpd;

pa_bluetooth_hsphfpd *pa_bluetooth_hsphfpd_new(pa_core *core, pa_bluetooth_discovery *discovery);
void pa_bluetooth_hsphfpd_free(pa_bluetooth_hsphfpd *hsphfpd);

#endif
