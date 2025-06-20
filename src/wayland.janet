(import lemongrass)

(defn- scan-get-signature [[_ attrs & _]]
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

(defn- scan-get-types [[_ attrs & _]]
  (case (attrs :type)
    "object" (if-let [i (attrs :interface)] [(keyword i)])
    "new_id" (if-let [i (attrs :interface)] [(keyword i)] [nil nil nil])
    [nil]))

(defn- scan-message [[_ attrs & message]]
  (def args (filter |(= (first $) :arg) message))
  {:name (attrs :name)
   :signature (string (or (attrs :since) "")
                      (string/join (map scan-get-signature args)))
   :types (tuple/brackets ;(mapcat scan-get-types args))})

(defn- scan-send-args [[_ attrs & _]]
  (case (attrs :type)
    "new_id" (if (attrs :interface) [nil] ['interface 'version nil])
    [(symbol (attrs :name))]))

(defn- scan-send-case [[_ attrs & request] opcode]
  (def args (filter |(= (first $) :arg) request))
  (def generic-constructor (find (fn [[_ attrs & _]]
                                   (and (= (attrs :type) "new_id")
                                        (not (attrs :interface)))) args))
  (def constructor (find (fn [[_ attrs & _]]
                           (= (attrs :type) "new_id")) args))
  # TODO use kebab-case
  [(keyword (attrs :name))
   ~(fn [object ,;(filter truthy? (mapcat scan-send-args args))]
      (:send-raw object
                 ,opcode
                 ,(cond
                    generic-constructor '(keyword interface)
                    constructor ~(keyword ,((get constructor 1) :interface)))
                 ,(if generic-constructor 'version 0)
                 ,(if (= (attrs :type) "destructor") {:destroy true} {})
                 ,(tuple/brackets ;(mapcat scan-send-args args))))])

# TODO enums?
(defn- scan-interface [[_ attrs & interface]]
  (def requests (filter |(= (first $) :request) interface))
  (def events (filter |(= (first $) :event) interface))
  {(keyword (attrs :name))
   {:version (assert (scan-number (attrs :version)))
    :requests (tuple/brackets ;(map scan-message requests))
    :events (tuple/brackets ;(map scan-message events))
    :send (eval ~(fn [request]
                   (case request
                     ,;(mapcat scan-send-case requests (range (length requests)))
                     (errorf "unknown request %v" request))))}})

(defn- scan-protocol [[_ attrs & protocol]]
  (->> protocol
       (filter |(= (first $) :interface))
       (map scan-interface)))

(defn- scan-path [path]
  (->> (slurp path)
       (lemongrass/markup->janet)
       (filter |(= (first $) :protocol))
       (mapcat scan-protocol)
       (reduce merge @{})))

# Returns the interfaces table for wl/display/connect
(defn scan [& paths]
  (->> paths
       (map scan-path)
       (reduce merge @{})))

(import ./wayland-native :prefix "" :export true)
