(import lemongrass)
(import spork/sh)

(import ./wayland-native :prefix "" :export true)

(defn display/dispatch [display]
  (display/send-recv display)
  (loop [[handler event] :iterate (display/pop-event display)]
    (handler event)))

(defn display/roundtrip [display]
  (def callback (:sync display))
  (defer (:destroy callback)
    (var done false)
    (:set-handler callback (fn [_] (set done true)))
    (while (not done)
      (display/dispatch display))))

(defn- scan-args-signature [[_ attrs & _]]
  (string/join
    [(case (attrs :allow-null)
       "true" "?"
       "false" ""
       nil ""
       (errorf "invalid allow-null value %v" (attrs :allow-null)))
     (case (attrs :type)
       "int" "i"
       "uint" "u"
       "fixed" "f"
       "string" "s"
       "object" "o"
       "new_id" (if (attrs :interface) "n" "sun")
       "array" "a"
       "fd" "h"
       (errorf "unknown arg type %v" (attrs :type)))]))

(defn- scan-args-types [[_ attrs & _]]
  (case (attrs :type)
    "object" (if-let [i (attrs :interface)] [(keyword i)] [nil])
    "new_id" (if-let [i (attrs :interface)] [(keyword i)] [nil nil nil])
    [nil]))

(defn- keybab [snake]
  (keyword (string/replace-all "_" "-" snake)))

(defn- scan-enum [[_ attrs & enum]]
  (def entries (filter |(= (first $) :entry) enum))
  (def enums-values
    (struct ;(->> entries (mapcat (fn [[_ attrs & _]]
                                    [(keybab (attrs :name))
                                     (scan-number (attrs :value))])))))
  (def values-enums (invert enums-values))
  (defn to-value [e]
    (if-let [v (enums-values e)] v (errorf "unknown enum variant %v" e)))
  # Some wayland interfaces (e.g. wl_shm) get enum entries added to them
  # willy-nilly with no version bump. This means we cannot error on an
  # unknown enum value without breaking forwards compatibility.
  (defn to-enum [v]
    (if-let [e (values-enums v)] e (keyword nil)))
  [(keyword (attrs :name))
   (if (= (attrs :bitfield) "true")
     {:to-value (fn [set]
                  (bor ;(->> (pairs set)
                             (keep (fn [[e v]] (if v e)))
                             (map to-value))))
      :to-enum (fn [value]
                 (struct ;(->> (pairs values-enums)
                               (filter (fn [[v e]] (= v (band value v))))
                               (mapcat (fn [[v e]] [e true])))))}
     {:to-value to-value
      :to-enum to-enum})])

(defn- scan-paths [paths]
  (def interfaces
    (->> paths
         (mapcat (fn [path] (->> (slurp path)
                                 (lemongrass/markup->janet)
                                 (filter |(= (first $) :protocol)))))
         (mapcat (fn [[_ attrs & protocol]]
                   (->> protocol (filter |(= (first $) :interface)))))))

  (def enums
    (struct ;(->> interfaces
                  (mapcat (fn [[_ attrs & interface]]
                            [(keyword (attrs :name))
                             (struct ;(->> interface
                                           (filter |(= (first $) :enum))
                                           (mapcat scan-enum)))])))))

  (defn scan-interface [[_ attrs & interface]]
    (def requests (filter |(= (first $) :request) interface))
    (def events (filter |(= (first $) :event) interface))
    (def current-interface (keyword (attrs :name)))

    (defn resolve-enum [enum-ref]
      (match (string/split "." enum-ref)
        [enum-interface enum-name]
        ((enums (keyword enum-interface)) (keyword enum-name))
        [enum-name]
        ((enums current-interface) (keyword enum-name))))

    (defn- scan-args-enums [[_ attrs & _]]
      (match (attrs :type)
        (t (or (= t "int") (= t "uint")))
        (if-let [e (attrs :enum)]
          [((resolve-enum e) :to-enum)]
          [nil])
        "new_id" (if (attrs :interface) [nil] [nil nil nil])
        [nil]))

    (defn scan-message [[_ attrs & message]]
      (def args (filter |(= (first $) :arg) message))
      {:name (attrs :name)
       :signature (string (or (attrs :since) "")
                          (string/join (map scan-args-signature args)))
       :types (mapcat scan-args-types args)
       :enums (mapcat scan-args-enums args)})

    (defn request-params [[_ attrs & _]]
      (case (attrs :type)
        "new_id" (if (attrs :interface) [] ['interface 'version])
        [(symbol (attrs :name))]))

    (defn request-args [[_ attrs & _]]
      (match (attrs :type)
        (t (or (= t "int") (= t "uint")))
        (if-let [e (attrs :enum)]
          [~(,((resolve-enum e) :to-value) ,(symbol (attrs :name)))]
          [(symbol (attrs :name))])
        "new_id" (if (attrs :interface) [nil] ['interface 'version nil])
        [(symbol (attrs :name))]))

    (defn request-method [[_ attrs & request] opcode]
      (def args (filter |(= (first $) :arg) request))
      (def generic-constructor (find (fn [[_ attrs & _]]
                                       (and (= (attrs :type) "new_id")
                                            (not (attrs :interface)))) args))
      (def constructor (find (fn [[_ attrs & _]]
                               (= (attrs :type) "new_id")) args))
      [(keybab (attrs :name))
       (eval ~(fn ,(symbol (keybab current-interface) "/" (keybab (attrs :name)))
                [object ,;(mapcat request-params args)]
                (,proxy/request-raw
                  object
                  ,opcode
                  ,(cond
                     generic-constructor '(keyword interface)
                     constructor ~(keyword ,((get constructor 1) :interface)))
                  ,(if generic-constructor 'version 0)
                  ,(if (= (attrs :type) "destructor") {:destroy true} {})
                  ,(tuple/brackets ;(mapcat request-args args)))))])

    [current-interface
     {:version (assert (scan-number (attrs :version)))
      :requests (map scan-message requests)
      :events (map scan-message events)
      :methods (struct
                 :set-handler proxy/set-handler
                 :set-user-data proxy/set-user-data
                 :get-user-data proxy/get-user-data
                 ;(if (= current-interface :wl_display)
                    [:dispatch display/dispatch
                     :roundtrip display/roundtrip
                     :disconnect display/disconnect]
                    [:destroy proxy/destroy])
                 # If there is a destroy request in the protocol it will
                 # replace the proxy/destroy method.
                 ;(mapcat request-method requests (range (length requests))))}])

  (freeze (struct ;(mapcat scan-interface interfaces))))

(defn scan
  "Reads Wayland protocol XML files to generate the interfaces table for (wayland/connect)"
  [&named wayland-xml system-protocols system-protocols-dir custom-protocols]
  (default wayland-xml
    (string (sh/exec-slurp "pkg-config" "--variable=pkgdatadir" "wayland-scanner") "/wayland.xml"))
  (default system-protocols-dir
    (sh/exec-slurp "pkg-config" "--variable=pkgdatadir" "wayland-protocols"))
  (default system-protocols [])
  (default custom-protocols [])
  (scan-paths (array/concat @[wayland-xml]
                            (map |(string system-protocols-dir "/" $) system-protocols)
                            custom-protocols)))
