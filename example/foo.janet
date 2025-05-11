(import ../src/wayland :as wl)

(def display (wl/display/connect))

(def registry (:get-registry display))
(:set-listener registry
               (fn [event]
                 (match event
                   [:global name interface version] (pp event)
                   [:global-remove name] (pp event))))

(:roundtrip display)
(:disconnect display)
