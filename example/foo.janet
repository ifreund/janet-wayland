(import ../src/wayland :as wl)

(def display (wl/display/connect))

(def registry (:get-registry display)

(pp registry)

(:roundtrip display)
(:disconnect display)
