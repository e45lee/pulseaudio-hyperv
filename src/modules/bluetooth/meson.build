libbluez5_util_sources = [
  'a2dp-codec-faststream.c',
  'a2dp-codec-sbc.c',
  'a2dp-codec-util.c',
  'bluez5-util.c',
]

libbluez5_util_headers = [
  'a2dp-codec-api.h',
  'a2dp-codecs.h',
  'a2dp-codec-util.h',
  'bluez5-util.h',
  'rtp.h',
]

if get_option('bluez5-legacy-hsp')
  libbluez5_util_sources += [ 'legacy-hsp.c' ]
endif

if bluez5_aptx
  libbluez5_util_sources += [ 'a2dp-codec-aptx.c' ]
endif

libbluez5_util = shared_library('bluez5-util',
  libbluez5_util_sources,
  libbluez5_util_headers,
  c_args : [pa_c_args, server_c_args],
  link_args : [nodelete_link_args],
  include_directories : [configinc, topinc],
  dependencies : [libpulse_dep, libpulsecommon_dep, libpulsecore_dep, dbus_dep, sbc_dep, libintl_dep, bluez5_aptx_dep],
  install : true,
  install_rpath : privlibdir,
  install_dir : modlibexecdir,
)
