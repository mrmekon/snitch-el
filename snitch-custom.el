;;; snitch-custom.el                       -*- lexical-binding: t; -*-
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
;; This file provides the customizable user options for snitch.el.
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

;;
;;
;; Customizable variables
;;
;;

(defgroup snitch nil
  "Customization options for the snitch firewall"
  :group 'communication
  :prefix "snitch-")


(defgroup snitch-log nil
  "Logging options for snitch firewall"
  :group 'snitch
  :prefix "snitch-")

;;;###autoload
(defcustom snitch-log-policy '(all blocked)
  "Specifies types of actions that snitch should log.  Provided
as a list of symbols defined in snitch-log-policies"
  :type '(repeat (choice (const all)
                         (const blocked)
                         (const allowed)
                         (const whitelisted)
                         (const blacklisted)))
  :group 'snitch-log)

(defcustom snitch-log-verbose nil
  "Whether the log output should be extra verbose (pretty-printed
multi-line event logs)."
  :type 'boolean
  :group 'snitch-log)

(defcustom snitch--log-buffer-max-lines 5000
  "Maximum number of lines to keep in the snitch event log
buffer.  When it grows larger than this, the least recent lines
are periodically truncated by a timer.

Since trimming is timer-based, the log buffer can temporarily
grow larger than the requested value.  It is only trimmed after a
period of emacs idle time.

Set to 0 for unlimited."
  :type 'number
  :group 'snitch-log)

(defcustom snitch-enable-notifications nil
  "Whether snitch should raise notifications for each log
message, in addition to printing them in the log buffer.

This feature requires the ‘alert’ package to be available.

Users can define custom styles for alert with
‘alert-define-style’.  All snitch alerts set ‘category’ to
‘snitch’, provide an ‘id’ field unique to each event, and provide
the event object in ‘data’."
  :type 'boolean
  :group 'snitch-log)


(defgroup snitch-policy nil
  "Default firewall policy options for snitch"
  :group 'snitch
  :prefix "snitch-")

;;;###autoload
(defcustom snitch-process-policy 'allow
  "Default firewall policy for subprocesses.  When set to allow,
exceptions can be specified in snitch-process-blacklist.  When
set to deny, exceptions can be specified in
snitch-process-whitelist."
  :type '(choice (const deny)
                 (const allow))
  :group 'snitch-policy)

;;;###autoload
(defcustom snitch-network-policy 'allow
  "Default firewall policy for network connections.  When set to
allow, exceptions can be specified in snitch-network-blacklist.
When set to deny, exceptions can be specified in
snitch-network-whitelist."
  :type '(choice (const deny)
                 (const allow))
  :group 'snitch-policy)


(defgroup snitch-rules nil
  "Firewall rules for snitch (blacklists/whitelists)"
  :group 'snitch
  :prefix "snitch-")

;;;###autoload
(defcustom snitch-network-blacklist
  '()
  ""
  :group 'snitch-rules
  :type '(alist :key-type function
                :value-type (repeat sexp)))

;;;###autoload
(defcustom snitch-network-whitelist
  '()
  ""
  :group 'snitch-rules
  :type '(alist :key-type function
                :value-type (repeat sexp)))

;;;###autoload
(defcustom snitch-process-blacklist
  '(
    ;; Example: block processes from elfeed
    ;;(snitch-filter/src-pkg . (elfeed))

    ;; Example: block processes from system packages
    ;;(snitch-filter/src-pkg . (site-lisp))

    ;; Example: block processes from emacs built-ins
    ;;(snitch-filter/src-pkg . (built-in))

    ;; Example: block processes from an unknown user package
    ;;(snitch-filter/src-pkg . (user))
    )
  ""
  :group 'snitch-rules
  :type '(alist :key-type function
                :value-type (repeat sexp)))

;;;###autoload
(defcustom snitch-process-whitelist
  '()
  "A list of rules defining which subprocess calls are permitted
when snitch.el is configured to deny subprocesses by default.

If any filter returns true, the process is immediately allowed
without checking any remaining rules.

Format is an alist of filter function and argument lists, in the
form:

   '((filter-fn1 . (arg1))
     (filter-fn2 . (arg2 arg3))
     (filter-fn3 . (arg4 arg5 arg6)))

Each filter function must take a snitch-network-entry eieio
object as its first parameter, and any number of subsequent
arguments which are specified as the arguments in this alist.

In the above example, filter-fn2 might be defined:

  (defun filter-fn2 (net-event fn-arg pkg-arg)
    (or (string-equal (oref net-event :src-fn) fn-arg)
        (string-equal (oref net-event :src-pkg) pkg-arg)))

This allows any arbitrary filtering rules, at the expense of
efficiency.  Keep short-circuiting in mind, and put more general
rules earlier in the list."
  :group 'snitch-rules
  :type '(alist :key-type function
                :value-type (repeat sexp)))


;;
;;
;; Hooks
;;
;;

(defgroup snitch-hooks nil
  "Hooks (callbacks) for snitch firewall events."
  :group 'snitch
  :prefix "snitch-")

;;;###autoload
(defcustom snitch-on-event-functions '()
  "Hooks called for every event that snitch can intercept.

Note that every event that is not blocked by these hooks is sent
twice: once to these hooks on initial reception, and again to one
of the other hooks with snitch's final decision.

Callback functions must take two arguments:

  1) a snitch-actions symbol describing the event type ('event)

  2) an event object, either a snitch-process-entry or
  snitch-network-entry.

Returning nil blocks the event, terminating processing."
  :group 'snitch-hooks
  :type 'hook)

;;;###autoload
(defcustom snitch-on-block-functions '()
  "Hooks called for events that are about to be blocked by policy.

Callback functions must take two arguments:

  1) a snitch-actions symbol describing the event type ('block)

  2) an event object, either a snitch-process-entry or
  snitch-network-entry.

Returning nil interrupts the block, allowing the event to pass."
  :group 'snitch-hooks
  :type 'hook)

;;;###autoload
(defcustom snitch-on-allow-functions '()
  "Hooks called for events that are about to be allowed by policy.

Callback functions must take two arguments:

  1) a snitch-actions symbol describing the event type ('allow)

  2) an event object, either a snitch-process-entry or
  snitch-network-entry.

Returning nil blocks the event, terminating processing."
  :group 'snitch-hooks
  :type 'hook)

;;;###autoload
(defcustom snitch-on-whitelist-functions '()
  "Hooks called for events that are about to be allowed by whitelist.

Callback functions must take two arguments:

  1) a snitch-actions symbol describing the event type ('whitelist)

  2) an event object, either a snitch-process-entry or
  snitch-network-entry.

Returning nil blocks the event, terminating processing."
  :group 'snitch-hooks
  :type 'hook)

;;;###autoload
(defcustom snitch-on-blacklist-functions '()
  "Hooks called for events that are about to be blocked by blacklist.

Callback functions must take two arguments:

  1) a snitch-actions symbol describing the event type ('blacklist)

  2) an event object, either a snitch-process-entry or
  snitch-network-entry.

Returning nil interrupts the block, allowing the event to pass."
  :group 'snitch-hooks
  :type 'hook)

;;;###autoload
(defcustom snitch-log-filter-window-open-hook '()
  "Called immediately after log filter window opens."
  :group 'snitch-hooks
  :type 'hook)

;;;###autoload
(defcustom snitch-log-filter-window-close-hook '()
  "Called immediately after log filter window closes."
  :group 'snitch-hooks
  :type 'hook)


;;
;;
;; Fonts
;;
;;

(defgroup snitch-faces nil
  "Faces for snitch firewall windows"
  :group 'snitch
  :prefix "snitch-")

(defface snitch--log-filter-face
  '((t . (:inherit default)))
  "Face for log filter wizard"
  :group 'snitch-faces)

(defface snitch--log-filter-active-face
  '((t . (:inherit snitch--log-filter-face :inverse-video t :weight bold)))
  "Face for log filter wizard, selected entries"
  :group 'snitch-faces)

(provide 'snitch-custom)

;;; snitch-custom.el ends here
