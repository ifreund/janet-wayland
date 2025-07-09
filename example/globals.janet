(import wayland)

(def interfaces (wayland/scan))

(defn main [&]
  (def display (wayland/connect interfaces))
  (def registry (:get-registry display))
  (:set-handler registry
                (fn [event]
                  (match event
                    [:global name interface version] (pp event)
                    [:global-remove name] (pp event))))
  (:roundtrip display)
  (:destroy registry)
  (:disconnect display))
