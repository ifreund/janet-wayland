(import ../src/wayland :as wl)

(def display (wl/display/connect))

(def registry (:send display :get-registry))

(pp registry)

(:roundtrip display)
(:disconnect display)
