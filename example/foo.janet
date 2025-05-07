(import ./jwl :as wl)

(def wl-registry {:name "wl_registry"
                  :version 1
                  :requests [{:name "bind"
                              :signature "usun"
                              :types [nil nil nil nil]}]
                  :events [{:name "global"
                              :signature "usu"
                              :types [nil nil nil]}
                           {:name "global_remove"
                              :signature "u"
                              :types [nil]}]})

(def d (wl/display/connect))

(:marshal d 1 wl-registry 1 {} [nil])

(:roundtrip d)
(:disconnect d)
