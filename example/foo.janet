(import wayland :as wl)

(def interfaces (wl/scan))

(defn main [&]
  (def display (wl/display/connect interfaces))
  (def registry (:get-registry display))
  (:set-listener registry
                 (fn [event]
                   (match event
                     [:global name interface version] (pp event)
                     [:global-remove name] (pp event))))
  (:roundtrip display)
  (:disconnect display))
