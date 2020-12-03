;;; snitch-log.el                          -*- lexical-binding: t; -*-
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; See snitch.el for full details.
;;
;; Copyright (C) 2020 Trevor Bentley
;; Author: Trevor Bentley <snitch.el@x.mrmekon.com>
;; URL: https://github.com/mrmekon/snitch-el
;;
;; This file is not part of GNU Emacs.
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;;; Commentary:
;;
;; This file provides logging, notification, and log-to-filter
;; functionality for snitch.el.
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation; either version 2, or (at your option)
;; any later version.
;;
;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.
;;
;; You should have received a copy of the GNU General Public License
;; along with this program; see the file COPYING.  If not, write to
;; the Free Software Foundation, Inc., 51 Franklin Street, Fifth
;; Floor, Boston, MA 02110-1301, USA.
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;;; Code:

;; optional dependency on alert package
(defvar snitch--have-alert (require 'alert nil t))

(defvar snitch--log-buffer-name "*snitch firewall log*"
  "Name of the buffer for the snitch firewall log.")
(defvar snitch--log-filter-buffer-name "*snitch filter wizard*"
  "Name of the buffer for the log filter 'wizard' popup window.")

(defvar snitch--log-filter-buffer nil
  "Buffer in the log filter 'wizard' popup window")

(defvar snitch--log-prune-timer nil
  "Periodic timer to prune snitch log buffer to its maximum
permitted size.")

(defun snitch--exact-log-match (policies)
  "Return true if any of policies are explicitly defined in
snitch-log-policy."
  (seq-some 'identity
            (mapcar (lambda (l) (member l snitch-log-policy))
                    policies)))

(defun snitch--log-policy-match (policies)
  "Return true of any of the log policies in POLICIES are
covered by one of the currently enabled policies in
‘snitch-log-policy’.

This does not require exact matches.  For instance, if POLICIES
contains ‘process-whitelisted’ and ‘snitch-log-policy’ contains
‘whitelisted’, this function returns true, as ‘whitelisted’ is a
larger set including both ‘process-whitelisted’ and
‘network-whitelisted’."
  (cond
   ;; all in policy, everything true
   ((member 'all snitch-log-policy) t)
   ;; exact match between requested and configured policies
   ((snitch--exact-log-match policies) t)
   ;; generalize whitelist policies
   ((and (or (member 'process-whitelisted policies)
             (member 'network-whitelisted policies))
         (member 'whitelisted snitch-log-policy)) t)
   ;; generalize blacklist policies
   ((and (or (member 'process-blacklisted policies)
             (member 'network-blacklisted policies))
         (member 'blacklisted snitch-log-policy)) t)
   ;; generalize allowed policies
   ((and (or (member 'process-allowed policies)
             (member 'network-allowed policies))
         (member 'allowed snitch-log-policy)) t)
   ;; generalize blocked policies
   ((and (or (member 'process-blocked policies)
             (member 'network-blocked policies))
         (member 'blocked snitch-log-policy)) t)))

(defun snitch--pretty-obj-string (event)
  "Return an event eieio object in a 'pretty-printed' form, which
can be used to deserialize back into an object with eval."
  ;; write eieio object out as a pretty string by redirecting
  ;; standard output stream to a function that consumes the output
  ;; char by char.  This must be reversed and concatenated to
  ;; produce the final string.
  (setq pretty-obj nil)
  (let ((old-std standard-output))
    (setq standard-output (lambda (c) (setq pretty-obj (cons c pretty-obj))))
    (object-write event)
    (setq pretty-obj (concat (nreverse pretty-obj)))
    (setq standard-output old-std))
  pretty-obj)

(defun snitch--propertize (logmsg event)
  "Add text properties to LOGMSG with elements from EVENT.  This
allows the log filter commands to re-assemble an event from its
log message. "
  (cond
   ;; process events
   ((snitch-process-entry-p event)
    (propertize logmsg
                'snitch-class snitch-process-entry
                'snitch-src-fn (oref event src-fn)
                'snitch-src-path (oref event src-path)
                'snitch-src-pkg (oref event src-pkg)
                'snitch-proc-name (oref event proc-name)
                'snitch-executable (oref event executable)
                'snitch-args (oref event args)))
   ;; network events
   ((snitch-network-entry-p event)
    (propertize logmsg
                'snitch-class snitch-network-entry
                'snitch-src-fn (oref event src-fn)
                'snitch-src-path (oref event src-path)
                'snitch-src-pkg (oref event src-pkg)
                'snitch-proc-name (oref event proc-name)
                'snitch-host (oref event host)
                'snitch-port (oref event port)
                'snitch-family (oref event family)))))

(defun snitch--log (evt-type event)
  "Log a snitch event to the dedicated snitch firewall log
buffer.  EVENT is an event object, and EVT-TYPE is any policy
type from ‘snitch-log-policies’."
  (when (snitch--log-policy-match (list evt-type))
    (let* ((name (cond ((eq evt-type 'all) "event")
                       ((eq evt-type 'whitelisted) "whitelisted")
                       ((eq evt-type 'process-whitelisted) "whitelisted")
                       ((eq evt-type 'network-whitelisted) "whitelisted")
                       ((eq evt-type 'blacklisted) "blacklisted")
                       ((eq evt-type 'process-blacklisted) "blacklisted")
                       ((eq evt-type 'network-blacklisted) "blacklisted")
                       ((eq evt-type 'allowed) "allowed")
                       ((eq evt-type 'process-allowed) "allowed")
                       ((eq evt-type 'network-allowed) "allowed")
                       ((eq evt-type 'blocked) "blocked")
                       ((eq evt-type 'process-blocked) "blocked")
                       ((eq evt-type 'network-blocked) "blocked")
                       (t "other")))
           (buf (get-buffer-create snitch--log-buffer-name))
           (pretty-obj (snitch--pretty-obj-string event))
           (timestamp (format-time-string "%Y-%m-%d %H:%M:%S"))
           (logmsg (snitch--propertize
                    (cond (snitch-log-verbose (format "[%s] (%s) --\n%s"
                                                      timestamp name pretty-obj))
                          (t (format "[%s] (%s) -- %s\n"
                                     timestamp name event)))
                    event)))
      ;; start timer to keep log size limited
      (snitch--maybe-start-log-prune-timer)
      ;; write the formatted log entry to the log buffer
      (with-current-buffer buf
        (setq buffer-read-only nil)
        (buffer-disable-undo)
        (save-excursion
          (goto-char (point-max))
          (insert logmsg))
        (setq buffer-read-only t))
      ;; if the alert package is available and notifications are
      ;; enabled, also raise a notification
      (when (and snitch--have-alert snitch-enable-notifications)
        (alert logmsg
               :title (format "Snitch Event: %s" name)
               :severity 'normal
               :category 'snitch
               ;; :id allows alert to replace notifications with
               ;; updated ones.  Since it is possible to get two
               ;; alerts for one object with snitch (if ’all logging
               ;; policy is enabled along with any other policy), we
               ;; pass the internal eieio object name, which is the
               ;; same if this event is raised again later
               :id (eieio-object-name-string event)
               ;; We also pass the raw event, so custom alert
               ;; handlers can parse it.  There is no way to get
               ;; feedback from an alert, so this is only
               ;; informative.
               :data event)))))

(defun snitch--prune-log-buffer ()
  ;; ensure timer is stopped.  it will be started again by the next
  ;; log event.  it’s wasteful to have a timer running when we know
  ;; the buffer isn’t growing.
  (snitch--stop-log-prune-timer)
  (let ((buf (get-buffer-create snitch--log-buffer-name)))
    (with-current-buffer buf
      (let ((line-count (count-lines (point-min) (point-max))))
        (when (and (> snitch--log-buffer-max-lines 0)
                   (> line-count snitch--log-buffer-max-lines))
          (setq buffer-read-only nil)
          (buffer-disable-undo)
          (save-excursion
            (goto-char (point-min))
            (forward-line (+ (- line-count snitch--log-buffer-max-lines) 1))
            (delete-region (point-min) (point))
            (goto-char (point-min))
            (insert "[log trimmed]\n")
            (goto-char (point-max)))
          (setq buffer-read-only t))))))

(defun snitch--maybe-start-log-prune-timer ()
  "Start the snitch log pruning timer if it is not already
running."
  (unless snitch--log-prune-timer
    (snitch--start-log-prune-timer)))

(defun snitch--start-log-prune-timer ()
  "Start the snitch log pruning timer.  This is a non-repeating
timer that calls snitch--prune-log-buffer after a period of
idle."
  (setq snitch--log-prune-timer
        (run-with-idle-timer 30 nil #'snitch--prune-log-buffer)))

(defun snitch--stop-log-prune-timer ()
  "Stop the snitch log pruning timer if it is running."
  (when snitch--log-prune-timer
    (cancel-timer snitch--log-prune-timer)
    (setq snitch--log-prune-timer nil)))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;;
;; Log filter ’wizard’
;;
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;;###autoload
(defun snitch-filter-from-log ()
  "Opens an interactive 'wizard' to create a new snitch
whitelist/blacklist rule based on the event log under the cursor.

To use the wizard, move the cursor over an item in the snitch
firewall log buffer (default: ‘*snitch firewall log*’), and run
this command (‘M-x snitch-filter-from-log’).  A window will appear
with contents populated from the selected log line.  Typing the
highlighted mnemonic characters toggles fields on and off.  When
all desired fields are selected, typing ‘C-c C-c’ appends the new
filter to the existing blacklist or whitelist, and saves it
persistently as a customized variable."
  (interactive)
  (let ((cls (get-text-property (point) 'snitch-class))
        (fn (get-text-property (point) 'snitch-src-fn))
        (path (get-text-property (point) 'snitch-src-path))
        (pkg (get-text-property (point) 'snitch-src-pkg))
        (name (get-text-property (point) 'snitch-proc-name)))
    (cond
     ((eq cls 'snitch-network-entry)
      (let ((host (get-text-property (point) 'snitch-host))
            (port (get-text-property (point) 'snitch-port))
            (family (get-text-property (point) 'snitch-family)))
        (snitch--run-log-filter-wizard (snitch-network-entry
                                        :src-fn fn
                                        :src-path path
                                        :src-pkg pkg
                                        :proc-name name
                                        :host host
                                        :port port
                                        :family family))))
     ((eq cls 'snitch-process-entry)
      (let ((exec (get-text-property (point) 'snitch-executable))
            (args (get-text-property (point) 'snitch-args)))
        (snitch--run-log-filter-wizard (snitch-process-entry
                                        :src-fn fn
                                        :src-path path
                                        :src-pkg pkg
                                        :proc-name name
                                        :executable exec
                                        :args args))))
  )))

(defun snitch--run-log-filter-wizard (event)
  "Runs the snitch log filter 'wizard', an interactive popup
window to help a user create a new blacklist or whitelist filter
based on a log entry.  This function sets up the window,
populates it, loops over user keypresses, and eventually saves
the filter to the customization variable if appropriate."
  ;; create buffer if needed
  (when (null snitch--log-filter-buffer)
    (snitch--init-log-filter-buffer))
  ;; set initial contents of buffer so it opens to the correct size
  (snitch--redraw-log-filter-buffer event fields)
  ;; display window
  (snitch--show-log-filter-window)
  ;; read user input continuously until saved or aborted
  (setq finished nil)
  (setq fields '())
  (let ((key-map (snitch--log-filter-map event)))
    (while (not finished)
      ;; redraw to update font properties
      (snitch--redraw-log-filter-buffer event fields)
      (let* ((key (read-key-sequence "Enter field: ")))
        (cond
         ;; ignore, probably a control character (arrow keys, etc)
         ;; must come first to short-circuit before string comparisons
         ((not (stringp key)) nil)
         ;; abort and exit
         ((string-equal key (kbd "C-c C-k")) (setq fields '() finished t))
         ((string-equal key (kbd "C-g")) (setq fields '() finished t))
         ;; save and exit
         ((string-equal key (kbd "C-c C-c")) (setq finished t))
         ;; some other string.  check if string is in field map, and
         ;; if so toggle that slot of the event in the list of slots
         ;; to filter on
         ((stringp key)
          (let ((slot (snitch--log-filter-map-slot-from-key key-map key)))
            (when slot
              (if (member slot fields)
                  (setq fields (delete slot fields))
                (setq fields (cons slot fields))))))))))
  ;; close filter window
  (snitch--hide-log-filter-window snitch--log-filter-buffer)
  ;; generate filter
  (when fields
    (setq slot-value-alist '())
    ;; make an alist of (slot . value) pairs for the filter function
    ;; to match against
    (cl-loop for slot in fields
             do
             (setq slot-value-alist
                   (cons (cons slot (eieio-oref event slot)) slot-value-alist)))
    ;; query user for whether this should go in blacklist or whitelist
    (setq black-white nil)
    (while (null black-white)
      (let* ((key (read-key-sequence "[b]lacklist or [w]hitelist? ")))
        (cond
         ;; ignore, probably a control character (arrow keys, etc)
         ;; must come first to short-circuit before string comparisons
         ((not (stringp key)) nil)
         ((string-equal key "b") (setq black-white "blacklist"))
         ((string-equal key "w") (setq black-white "whitelist")))))
    ;; append the new entry to the correct defcustom list, and
    ;; save as default customization.
    (let* ((filter (cons #'snitch-filter/log-filter slot-value-alist))
           (orig-list (cond
                       ((snitch-network-entry-p event)
                        (intern-soft (format "snitch-network-%s" black-white)))
                       ((snitch-process-entry-p event)
                        (intern-soft (format "snitch-process-%s" black-white)))
                       (t nil)))
           (orig-val (eval orig-list))
           (new-list (cons filter orig-val)))
      (customize-save-variable orig-list new-list))))

(defun snitch--log-filter-map-slot-from-key (map key)
  "Given a map from ‘snitch--log-filter-map’, returns the slot
matching to the given keypress, or nil."
  (cl-loop for (slot . plist) in map
           when (string-equal (plist-get plist 'key) key)
           return slot
           finally return nil))

(defun snitch--log-filter-map (event)
  "Returns an alist of (SLOT . PLIST) pairs, where each PLIST
contains a field name, a key to press to select it, and a
‘mnemonic’ version of the name with the key highlighted in square
brackets.  The correct set of fields is returned based on the
given event type.  All of this stuff is used to display the
fields, and to interpret which field to select when receiving
user keypresses."
  (setq common-alist
        '((src-fn . (key "f" name "function"
                         mnemonic-name "[f]unction"))
          (src-path . (key "p" name "path"
                           mnemonic-name "[p]ath"))
          (src-pkg . (key "k" name "package"
                          mnemonic-name "pac[k]age"))
          (proc-name . (key "n" name "name"
                          mnemonic-name "[n]ame"))))
  (setq network-alist
        '((host . (key "h" name "host"
                       mnemonic-name "[h]ost"))
          (port . (key "o" name "port"
                       mnemonic-name "p[o]rt"))
          (family . (key "m" name "family"
                       mnemonic-name "fa[m]ily"))))
  (setq process-alist
        '((executable . (key "x"name "executable"
                             mnemonic-name "e[x]ecutable"))
          (args . (key "g" name "args"
                       mnemonic-name "ar[g]s"))))
  (cond
   ((snitch-network-entry-p event) (append common-alist network-alist))
   ((snitch-process-entry-p event) (append common-alist process-alist))
   (t common-alist)))

(defun snitch--redraw-log-filter-buffer (evt selected)
  "Draw the text contents of the log-filter menu based on the
given event and list of currently selected fields.  Each field
name is drawn on a separate line, along with its value in the
current event.  The ‘mnemonic’ version of the field name is
displayed, with the character to press surrounded by square
brackets.  Fields that are currently selected display in a
different font."
  (with-current-buffer snitch--log-filter-buffer
    (erase-buffer)
    (let ((evt-type (if (snitch-network-entry-p evt)
                        "network"
                      "process")))
      (insert (format "Creating new snitch %s filter from template:\n" evt-type))
      (cl-loop for (slot . plist) in (snitch--log-filter-map evt)
               do
               (let* ((msg (format "%-12s: %s" (plist-get plist 'mnemonic-name)
                                   (eieio-oref evt slot)))
                      (styled-msg (propertize
                                   msg 'face
                                   (if (member slot selected)
                                       'snitch--log-filter-active-face
                                     'snitch--log-filter-face))))
                 (insert "\n")
                 (insert styled-msg)))
      (insert "\n")
      (insert "\nSave: C-c C-c / Abort: C-c C-k")
      (goto-char (point-min)))))

(defun snitch--init-log-filter-buffer ()
  "Initialize buffer for displaying UI to generate a snitch
filter from an existing log line."
  ;; logic looted from which-key
  (unless (buffer-live-p snitch--log-filter-buffer)
    (setq snitch--log-filter-buffer
          (get-buffer-create snitch--log-filter-buffer-name))
    (with-current-buffer snitch--log-filter-buffer
      (let (message-log-max)
        (toggle-truncate-lines 1)
        (message ""))
      (setq-local cursor-type nil)
      (setq-local cursor-in-non-selected-windows nil)
      (setq-local mode-line-format nil)
      (setq-local word-wrap nil)
      (setq-local show-trailing-whitespace nil))))

(defun snitch--hide-log-filter-window (buffer)
  "Hide snitch log filter window."
  ;; based on which-key
  (when (buffer-live-p buffer)
    (quit-windows-on buffer)
    (run-hooks 'snitch-log-filter-window-close-hook)))

(defun snitch--log-filter-window-size-to-fit (window)
  "Resize log filter window to a reasonable height and maximum
width."
  ;; based on which-key
  ;; cap at 30% of the vertical height
  (let ((fit-window-to-buffer-horizontally t)
        (window-min-height 5)
        (max-height (round (* .3 (window-total-height (frame-root-window))))))
    (fit-window-to-buffer window max-height)))

(defun snitch--show-log-filter-window ()
  "Open or switch focus to the log filter window, resizing it as
necessary."
  ;; based on which-key
  (let* ((alist
          `((window-width . snitch--log-filter-window-size-to-fit)
            (window-height . snitch--log-filter-window-size-to-fit)
            (side . bottom)
            (slot . 0))))
    ;; Comment preserved from which-key:
    ;; Previously used `display-buffer-in-major-side-window' here, but
    ;; apparently that is meant to be an internal function. See emacs bug #24828
    ;; and advice given there.
    (cond
     ((get-buffer-window snitch--log-filter-buffer)
      (display-buffer-reuse-window snitch--log-filter-buffer alist))
     (t
      (display-buffer-in-side-window snitch--log-filter-buffer alist)))
    (run-hooks 'snitch-log-filter-window-open-hook)))

(provide 'snitch-log)

;;; snitch-log.el ends here
