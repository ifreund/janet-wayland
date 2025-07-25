(import wayland)

(def interfaces
  (wayland/scan
    :system-protocols ["stable/xdg-shell/xdg-shell.xml"
                       "stable/viewporter/viewporter.xml"
                       "staging/single-pixel-buffer/single-pixel-buffer-v1.xml"]))

(defn main [&]
  (def display (wayland/connect interfaces))

  (var compositor nil)
  (var viewporter nil)
  (var wm-base nil)
  (var single-pixel-buffer-man nil)

  (def registry (:get-registry display))
  (:set-listener registry
                 (fn [registry event]
                   (match event
                     [:global name interface version]
                     (case interface
                       "wl_compositor" (set compositor (:bind registry name interface 1))
                       "wp_viewporter" (set viewporter (:bind registry name interface 1))
                       "xdg_wm_base" (set wm-base (:bind registry name interface 5))
                       "wp_single_pixel_buffer_manager_v1" (set single-pixel-buffer-man (:bind registry name interface 1))))))

  (:roundtrip display)

  (assert compositor)
  (assert viewporter)
  (assert wm-base)
  (assert single-pixel-buffer-man)

  (def buffer (:create-u32-rgba-buffer single-pixel-buffer-man 0 (- (math/pow 2 32) 1) 0 (- (math/pow 2 32) 1)))
  (def surface (:create-surface compositor))
  (def viewport (:get-viewport viewporter surface))
  (def xdg-surface (:get-xdg-surface wm-base surface))
  (def xdg-toplevel (:get-toplevel xdg-surface))

  (:set-listener xdg-surface
                 (fn [xdg-surface event]
                   (match event
                     [:configure serial] (do
                                           (:ack-configure xdg-surface serial)
                                           (:commit surface)))))

  (var running true)
  (:set-listener xdg-toplevel
                 (fn [xdg-toplevel event]
                   (match event
                     [:configure w h] (let [w (if (= w 0) 42 w)
                                            h (if (= h 0) 42 h)]
                                        (:set-destination viewport w h)
                                        (:commit surface))
                     [:close] (set running false))))

  (:commit surface)
  (:roundtrip display)

  (:attach surface buffer 0 0)
  (:commit surface)

  (while running
    (:dispatch display))

  (:disconnect display))
