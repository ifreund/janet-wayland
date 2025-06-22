(declare-project
  :name "wayland"
  :description "Wayland scanner and libwayland bindings for janet"
  :author "Isaac Freund"
  :dependencies [{:url "https://github.com/janet-lang/spork"}
                 {:url "https://github.com/ifreund/lemongrass"}]
  :version "0.0.0")

(declare-source
  :source ["src/wayland.janet"])

(declare-native
  :name "wayland-native"
  :source ["src/wayland-native.c"]
  :pkg-config-libs ["wayland-client"])
