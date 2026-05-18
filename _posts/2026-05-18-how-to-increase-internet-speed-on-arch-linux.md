---
title: "How I Increased My Internet Speed"
date: 2026-05-18 10:00:00 -0500
categories: [Linux, Performance]
tags: [arch-linux, networking, performance-tuning, wifi, tcp, bbr, sysctl]
image:
  path: https://archlinux.org/static/logos/archlinux-logo-dark-1200dpi.b42bd35d5916.png
---

I noticed that fast.com reported my connection at around 620 Mbps while command line tools like `speedtest-cli` were reporting closer to 109 Mbps. That discrepancy bothered me, so I spent an evening working through the network stack on my Arch Linux machine to figure out where the bottleneck actually lived and what I could tune locally.

The first lesson was that single-stream HTTP tests against a far-away server are not measuring your link. They are measuring the slowest hop in a long path, combined with the TCP window divided by the round-trip time. Tools like fast.com use roughly sixteen parallel streams against a nearby Netflix CDN edge, which is why their numbers look so different from a single-threaded Python speedtest hitting a random Ookla mirror. Before changing anything, I established a baseline using multi-stream `curl` against a known mirror so I had something honest to compare against.

The biggest configuration win came from switching the TCP congestion control algorithm from the default `cubic` to BBR. BBR was developed at Google and tends to perform much better than cubic on links with any meaningful round-trip time or packet loss, because it models bandwidth and latency directly instead of reacting to drops. I paired it with the `cake` queueing discipline, which handles bufferbloat gracefully. The change was a one-time edit to `/etc/sysctl.d/99-bbr.conf` plus loading the `tcp_bbr` module at boot through `/etc/modules-load.d/bbr.conf`.

The next tuning step was socket buffer sizes. Arch ships with `net.core.rmem_max` and `net.core.wmem_max` set to four megabytes, which is fine for slow links but caps single-stream throughput on gigabit. I raised both to thirty-two megabytes, expanded the auto-tuning ranges for `tcp_rmem` and `tcp_wmem` to match, enabled TCP Fast Open, turned on MTU probing, and bumped `netdev_max_backlog` to absorb traffic bursts. All of those went into `/etc/sysctl.d/99-net-tune.conf` so they persist across reboots.

After the kernel-side tuning, I turned to the NIC itself. I installed `ethtool` and enabled TCP segmentation offload, generic segmentation offload, and generic receive offload on the wireless interface. These offloads let the network card handle packet segmentation work that would otherwise consume CPU cycles. On wireless drivers the gains are smaller than on wired NICs, but the toggle is cheap and reversible. Ring buffer tuning was not available on this card because wireless drivers expose them as `n/a`, which is normal.

Wireless power saving was the next target. By default, `iwlwifi` will throttle the radio aggressively when idle to save battery. On a desktop or plugged-in laptop, this introduces latency spikes and reduces sustained throughput. Turning it off with `iw dev wlan0 set power_save off` gave an immediate, if variable, improvement.

The deepest insight came from `iw dev wlan0 link`. My laptop has an Intel 700-series CNVi card connected over Wi-Fi 6E on the six gigahertz band at 160 megahertz width. The transmit PHY rate was 1.92 gigabits per second using two spatial streams, but the receive rate was only 681 megabits using a single stream. That asymmetry meant my real download ceiling over wireless was around 400 megabits, regardless of any local tuning. The access point was only beamforming a single spatial stream toward me on the downlink. That is not something the client can force; it is dictated by the access point. The honest answer is that to push past that ceiling I either need to update the router firmware, change its MU-MIMO and OFDMA settings, or run a cable to my ethernet port.

Once the tuning was in place I checked for accumulated bloat that might be slowing things down in other ways. The pacman package cache had grown to eighteen gigabytes, the user cache directory under `~/.cache` was eleven gigabytes, and the systemd journal was sitting at over two gigabytes. None of those were responsible for slow networking, but cleaning them up freed about thirty gigabytes of disk space without removing anything I actually used. I trimmed pacman with `paccache -r`, removed six orphan packages, capped the journal at five hundred megabytes, and cleared user caches that applications regenerate on demand.

The end result is a system where the kernel and NIC are no longer the limitation. Single-stream throughput against a reasonable mirror roughly tripled, and parallel downloads now saturate whatever the remote server is willing to give. The remaining gap between what I measure locally and what fast.com reports comes down to the wireless link itself, which is a router-side and physics-side problem rather than a Linux problem.

If I had to pick the single most valuable change from this session, it would be BBR. The socket buffer tuning matters too, but BBR shows up everywhere — every browser tab, every `git clone`, every `pacman -Syu` over a distant mirror. The rest is incremental polish on top of that.
