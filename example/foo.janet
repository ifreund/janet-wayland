(import ../src/wayland :as wl)

(def interfaces (wl/scan))

(defn main [&]
  (def display (wl/display/connect interfaces))
  (def registry (:get_registry display))
  (:set-listener registry
                 (fn [event]
                   (match event
                     [:global name interface version] (pp event)
                     [:global_remove name] (pp event))))
  (:roundtrip display)
  (:disconnect display))
