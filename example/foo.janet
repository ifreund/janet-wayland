(import ../src/wayland :as wl)

(wl/scan "/usr/share/wayland/wayland.xml")

(def display (wl/display/connect))

(def registry (:get_registry display))
(:set-listener registry
               (fn [event]
                 (match event
                   [:global name interface version] (pp event)
                   [:global_remove name] (pp event))))

(:roundtrip display)
(:disconnect display)
