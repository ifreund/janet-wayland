# janet-wayland

Ergonomic Wayland protocol scanner and libwayland bindings for [Janet](https://janet-lang.org).

The main repository is on [codeberg](https://codeberg.org/ifreund/janet-wayland),
which is where the issue tracker may be found and where contributions are accepted.

Read-only mirrors exist on [sourcehut](https://git.sr.ht/~ifreund/janet-wayland)
and [github](https://github.com/ifreund/janet-wayland).

## Installation

Currently janet-wayland requires a
[libwayland patch](https://gitlab.freedesktop.org/wayland/wayland/-/merge_requests/485)
that has not yet been merged at the time of this writing.

With a patched version of libwayland installed on the system, run:

```
janet-pm install https://codeberg.org/ifreund/janet-wayland
```

## Status

The API of janet-wayland is not yet considered stable. I don't foresee major
breakage at this point, but janet-wayland has not yet had enough usage to work
out all the kinks.

Documentation is pretty non-existent. It should nonetheless be pretty easy to
figure out for anyone already familiar with writing Wayland clients and reading
Wayland protocols.

Currently janet-wayland only supports writing Wayland clients, not Wayland
servers. Although writing such a latency-sensitive program as a Wayland
compositor in a high level, garbage collected language doesn't make much sense,
it would be nice to have support for writing basic servers in janet for testing
purposes. Probably it will make sense to expose two separate modules for clients
and servers rather than a single wayland module, this will be a breaking change.

## Usage

See the [examples](example/).

## License

janet-wayland is released under the MIT (expat) license.
