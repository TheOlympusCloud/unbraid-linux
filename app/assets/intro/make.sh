#!/bin/sh
# The first start's introduction, intro.webm, from the film's master render (an MP4): VP9, and Opus when the master has
# sound, in WebM, which GStreamer's usual plug-ins play. Its colours stay BT.709: the film ends on the window's ground.
# usage: app/assets/intro/make.sh MASTER.mp4
set -eu
[ $# -eq 1 ] || { echo "usage: $0 MASTER.mp4"; exit 2; }
ffmpeg -v error -y -i "$1" -c:v libvpx-vp9 -crf 30 -b:v 0 -row-mt 1 -deadline good -cpu-used 1 -pix_fmt yuv420p \
  -colorspace bt709 -color_primaries bt709 -color_trc bt709 -color_range tv -c:a libopus -b:a 96k \
  "$(dirname "$0")/intro.webm"
