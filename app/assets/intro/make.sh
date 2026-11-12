#!/bin/sh
# The first start's introduction, intro.webm, from the film's master render (an MP4), and its sound master if there is
# one: VP9, and Opus, in WebM, which GStreamer's usual plug-ins play. Opus is made from the sound master when given,
# rather than from the MP4's own (already lossy) sound. The colours stay BT.709: the film ends on the window's ground.
# usage: app/assets/intro/make.sh MASTER.mp4 [SOUND.flac]
set -eu
[ $# -eq 1 ] || [ $# -eq 2 ] || { echo "usage: $0 MASTER.mp4 [SOUND.flac]"; exit 2; }
master=$1
if [ $# -eq 2 ]; then set -- -i "$2" -map 0:v:0 -map 1:a:0; else set -- -map 0:v:0 -map "0:a:0?"; fi
ffmpeg -v error -y -i "$master" "$@" -c:v libvpx-vp9 -crf 30 -b:v 0 -row-mt 1 -deadline good -cpu-used 1 \
  -pix_fmt yuv420p -colorspace bt709 -color_primaries bt709 -color_trc bt709 -color_range tv -c:a libopus -b:a 96k \
  -shortest "$(dirname "$0")/intro.webm"
