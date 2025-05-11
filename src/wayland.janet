(import ./wayland-native :prefix "" :export true)

(def- interfaces @{})

(put interfaces
     "wl_callback"
     {:name "wl_callback"
      :version 1
      :requests []
      :events [{:name "done"
                :signature "u"
                :types [nil]}]
      :send (fn [request]
              (case request
                (errorf "unknown request %v" request)))})

(put interfaces
     "wl_display"
     {:name "wl_display"
      :version 1
      :requests [{:name "sync"
                  :signature "o"
                  :types ["wl_callback"]}
                 {:name "get_registry"
                  :signature "n"
                  :types ["wl_registry"]}]
      :events [{:name "error"
                :signature "ous"
                :types [nil nil nil]}
               {:name "delete_id"
                :signature "u"
                :types [nil]}]
      :send (fn [request]
              (case request
                :sync (fn [display] (:send-raw display interfaces 0 "wl_callback" 1 {} [nil]))
                :get-registry (fn [display] (:send-raw display interfaces 1 "wl_registry" 1 {} [nil]))
                (errorf "unknown request %v" request)))})

(put interfaces
     "wl_registry"
     {:name "wl_registry"
      :version 1
      :requests [{:name "bind"
                  :signature "usun"
                  :types [nil nil nil nil]}]
      :events [{:name "global"
                :signature "usu"
                :types [nil nil nil]}
               {:name "global_remove"
                :signature "u"
                :types [nil]}]
      :send (fn [request]
              (case request
                :bind (fn [registry name interface version]
                        (:send-raw registry interfaces 0 interface version {}
                                   [name interface version nil]))
                (errorf "unknown request %v" request)))})

(defn display/connect
  [&opt name]
  (display/connect-raw interfaces name))
