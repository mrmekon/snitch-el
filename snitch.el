;;; snitch.el --- an emacs firewall        -*- lexical-binding: t; -*-
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; Copyright (C) 2020 Trevor Bentley
;; Author: Trevor Bentley <snitch.el@x.mrmekon.com>
;; Created: 01 Dec 2020
;; Version: 0.1
;;
;; Keywords: processes, comm
;; URL: https://github.com/mrmekon/snitch-el
;;
;; This file is not part of GNU Emacs.
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;;; Commentary:
;;
;; snitch.el (pronounced like schnitzel) is a firewall for emacs.
;;
;; snitch intercepts calls to create network connections or launch
;; subprocesses.  Through user-configured default policies, filter
;; rules, and user hooks it is able to log and potentially block each
;; action.  It can be configured with ‘M-x customize-group <RET>
;; snitch’.
;;
;; Subprocesses and network connections are handled independently,
;; with their own separate default policies, blacklist and whitelist,
;; and logging policies.
;;
;; The main purpose of snitch is network monitoring.  Subprocesses are
;; included because it is extremely common for emacs packages to
;; "shell out" to an external program for network access, commonly to
;; ‘curl’.  As a side effect, snitch can also effectively audit and
;; prevent undesired access to other programs.
;;
;; Notifications can be raised on each logged event by ensuring the
;; ’alert’ package is installed and customizing
;; ‘snitch-enable-notifications’ to t.
;;
;; === MECHANISM ===
;;
;; The underlying ’firewall’ mechanism is built on function advice
;; surrounding emacs’s lowest-level core functions for spawning
;; connections or subprocesses.  When an emacs package or script makes
;; such a request, snitch receives it first, and either passes it
;; through or rejects it based on the current rules.  Once a
;; connection or process is accepted, snitch is no longer involved for
;; the duration of that particular communication stream.
;;
;; For each intercepted call, snitch first builds an event object
;; defining everything snitch knows about the call.  The metadata
;; differs for network connections (host, port, family) and processes
;; (executable and argument list), but all events share a common set:
;; calling function, calling function’s file path, calling package,
;; and request name.
;;
;; Once an event object is created, it is passed to any hooks defined
;; in ‘snitch-on-event-functions’ for early processing.  If a hook
;; returns nil, the event is dropped immediately.  Otherwise, snitch
;; then checks the corresponding whitelist (if the default policy is
;; deny) or the blacklist (if the default policy is allow) and makes
;; its internal decision.  Before executing the decision, it calls the
;; corresponding hook functions to give the user hooks one more
;; opportunity to change the decision.  Finally, only if the decision
;; was ‘allow’, snitch executes the original request and passes the
;; result back to the caller.
;;
;; As the event flows through the decision tree, it also triggers log
;; events.  There are several different types defined in
;; ‘snitch-log-policies’, and users can subscribe to any combination
;; of them by customizing ‘snitch-log-policy’.  Logs are displayed in
;; text format in a dedicated log buffer (by default: ‘*snitch
;; firewall log*’), along with text properties that allow extracting
;; the event information programatically from a log line with
;; ‘get-text-property’.  The text lines can be "pretty printed" by
;; customizing ‘snitch-log-verbose’.
;;
;;
;; === USAGE ===
;;
;; Enabling snitch is as simple as calling ‘(snitch-init)’.
;; Initialization does very little, so this is safe to call in your
;; emacs init without worrying about deferral or negative consequences
;; on startup time.
;;
;; An example initialization using ‘use-package’ might look like so:
;;
;;   (use-package snitch
;;     :ensure t
;;     :init
;;     (snitch-init))
;;
;; snitch then runs in the background, performing its duties according
;; to your configuration, and logging in its dedicated buffer.
;;
;; You may add firewall exception rules manually, as covered in the
;; CONFIGURATION section below.  Alternatively, you can also build
;; filters with a guided UI by switching to the firewall log buffer
;; (‘*snitch firewall log*’), highlighting an entry that you wish to
;; filter on, and execute ‘M-x snitch-filter-from-log’.  This launches
;; a popup window that allows you to configure a new filter based on
;; one or more fields of the selected log line, and add it to either
;; your blacklist or whitelist.
;;
;; To disable snitch, call ‘(snitch-deinit)’.
;;
;;
;; === CONFIGURATION ===
;;
;; Customize snitch with ‘M-x customize-group <RET> snitch’, or
;; manually in your emacs initialization file.
;;
;; Most users will have five variables that need to be configured
;; before use:
;;
;;  - ‘snitch-network-policy’ -- whether to allow or deny network
;; connections by default.
;;
;;  - ‘snitch-process-policy’ -- whether to allow or deny subprocesses
;; by default.
;;
;;  - ‘snitch-log-policy’ -- which events to log (to see the options,
;; run ‘M-x describe-variable <RET> snitch-log-policies’)
;;
;;  - ‘snitch-network-*list’ -- filter rules containing exceptions to
;; the default network policy.  See FILTER RULES below.  Use
;; ‘-whitelist’ if the default policy is ‘deny’, or ‘-blacklist’ if
;; the default policy is ‘allow’
;;
;;  - ‘snitch-process-*list’ -- filter rules containing exceptions to
;; the default process policy.  See FILTER RULES below.  Use
;; ‘-whitelist’ if the default policy is ‘deny’, or ‘-blacklist’ if
;; the default policy is ‘allow’
;;
;;
;; ==== COMMON CONFIG: DENY ====
;;
;; A useful configuration is to deny all external communication by
;; default, but allow certain packages to communicate.  This example
;; demonstrates permitting only the ’elfeed’ package to create network
;; connections:
;;
;;   (use-package snitch
;;     :ensure t
;;     :init
;;     (setq snitch-network-policy 'deny)
;;     (setq snitch-process-policy 'deny)
;;     (setq snitch-log-policy '(blocked whitelisted allowed))
;;     (add-to-list 'snitch-network-whitelist
;;                   (cons #'snitch-filter/src-pkg '(elfeed)))
;;     (snitch-init))
;;
;;
;; ==== COMMON CONFIG: ALLOW + AUDIT ====
;;
;; Another useful configuration is to allow all accesses, but log them
;; to keep an audit trail.  This might look like so:
;;
;;   (use-package snitch
;;     :ensure t
;;     :init
;;     (setq snitch-network-policy 'allow)
;;     (setq snitch-process-policy 'allow)
;;     (setq snitch-log-policy '(allowed blocked whitelisted blacklisted))
;;     (setq snitch-log-verbose t)
;;     (snitch-init))
;;
;;
;; ==== FILTER RULES ====
;;
;; Filter rules, as specified in ‘snitch-(process|network)-*list’
;; variables, are specified as cons cells where the car is a filtering
;; function, and the cdr is a list of arguments to pass to the
;; function in addition to the event object:
;;
;; (setq snitch-network-whitelist
;;   '(
;;      (filter-fn1 . (argQ argL))
;;      (filter-fn2 . (argN argP))
;;    ))
;;
;; Each filter function should have a prototype accepting EVENT as the
;; snitch event object in consideration, and ARGS as the list of
;; arguments from the cdr of the rules entry:
;;
;;   (defun filter-fn1 (event &rest args))
;;
;; A trivial function which matches if a single string in the event
;; object matches a known value might look like so:
;;
;;   (defun filter-fn1 (event name)
;;     (string-equal (oref event proc-name) name))
;;
;; While a more complex filter function might treat ARGS as an
;; associative list of key/value pairs:
;;
;;   (defun filter-fn2 (event &rest alist)
;;     (cl-loop for (aslot . avalue) in alist with accept = t
;;              do
;;              (let ((evalue (eieio-oref event aslot))
;;                    (val-type (type-of avalue)))
;;                (unless (cond
;;                         ((eq val-type 'string) (string-equal avalue evalue))
;;                         (t (eq avalue evalue)))
;;                  (setq accept nil)))
;;              when (null accept)
;;              return nil
;;              finally return accept))
;;
;; The return value of a filter function determines whether the filter
;; should take effect.  t means "take effect" and nil means "do not
;; take effect".  What that means for the event depends on which list
;; the filter rule is in.  If the rule is in a whitelist, t means
;; allow and nil means block.  If it is in a blacklist, t means block
;; and nil means allow.
;;
;;
;; ==== HOOKS ====
;;
;; Events are passed to user-provided hook functions, if specified.
;; These hooks can subscribe to receive events either immediately on
;; arrival, upon a final decision, or both.  The hooks can change
;; snitch’s final decision.
;;
;; Hook functions take a single argument, the event object:
;;
;;   (defun snitch-hook (event))
;;
;; Hooks should return t to allow snitch to continue processing as it
;; would have, or return nil to reverse snitch’s decision.  For hooks
;; in ‘snitch-on-event-functions’, returning nil cancels all further
;; processing of the event and blocks it immediately.  For other hook
;; lists, returning nil reverses the action implied by the list name:
;; returning nil in a ‘snitch-on-allow-functions’ hook causes the
;; event to be blocked, returning nil in a ‘snitch-on-block-functions’
;; hook causes it to be allowed.
;;
;;
;; === SECURITY ===
;;
;; snitch provides, effectively, zero security.
;;
;; If you were to ask your Principal Security Engineer friends, they
;; might say that an effective security boundary must be
;; "tamper-proof" and provide "complete mediation."  snitch does
;; neither.
;;
;; Tamper-proof: none at all.  Any other emacs package can simply
;; disable snitch, or modify it to pass malicious traffic undetected.
;;
;; Complete mediation: no attempt has been made to verify that *all*
;; network and subprocess accesses must go through the functions that
;; snitch hooks.  Given the complexity of emacs, it is extremely
;; unlikely that they do.
;;
;; However, your Principal Security Engineer friends also like to
;; blather on about ’defining your security model’, and a fun game to
;; play with them is to define your security model such that none of
;; the insecurities are in it.  As so:
;;
;; Security model: includes malicious adversaries
;; snitch effectiveness: zero.
;;
;; Security model: includes no malicious adversaries
;; snitch effectiveness: great!
;;
;; snitch is useful for auditing and blocking unwanted features in an
;; otherwise well-behaving ecosystem.  It is handy for getting a
;; record of exactly what your emacs is doing, and for fine-tuning
;; accesses beyond emacs’s boundaries a little bit better.  It will
;; not, however, save you from the bad guys.
;;
;;
;; === KNOWN LIMITATIONS ===
;;
;; snitch does not intercept domain name resolution (DNS).
;;
;; snitch has a strong preference for identifying user-provided
;; packages as the "originating source" of events.  Events that you
;; may consider as originated in built-in/site-lisp code may be
;; attributed to a user package instead, if one is higher up in the
;; backtrace.  For instance, `helm' may often show up as the source if
;; installed, since `helm-M-x-execute-command' is often somewhere in
;; the stack.
;;
;;
;; === TODO ===
;;
;;  - send notifications in batches?
;;  - interactive prompts?
;;  - handle service strings as port numbers
;;  - ensure the inverted negation rules make sense
;;  - automated test suite
;;  - publish on gitwhatever
;;  - publish on MELPA?
;;  - profit!
;;
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

(require 'eieio) ; class objects
(require 'cl-macs) ; cl loops
(require 'package) ; backtrace package sources

(require 'snitch-backtrace)
(require 'snitch-custom)
(require 'snitch-filter)
(require 'snitch-log)

;;
;;
;; Classes
;;
;;

(defclass snitch-source ()
  ((timestamp :initarg :timestamp :type number :initform 0)
   (src-fn :initarg :src-fn :type (or null symbol) :initform nil)
   (src-path :initarg :src-path :type (or null string) :initform nil)
   (src-pkg :initarg :src-pkg :type (or null symbol) :initform nil))
  "Common base class for snitch entries.  Supplies information
about snitch's best guess for which emacs function/file/package
is ultimately responsible for the event that snitch is
considering.")

(defclass snitch-process-entry (snitch-source)
  ((proc-name :initarg :proc-name :type (or null string) :initform nil)
   (executable :initarg :executable :type (or null string) :initform nil)
   (args :initarg :args :type list :initform ()))
  "snitch entry for events attempting to spawn a
subprocess. Supplies information about the name, executable
binary, and arguments being provided to the subprocess that
snitch is considering.")

(defclass snitch-network-entry (snitch-source)
  ((proc-name :initarg :proc-name :type (or null string) :initform nil)
   (host :initarg :host :type (or null string symbol) :initform nil)
   (port :initarg :port :type (or null number symbol) :initform nil)
   (family :initarg :family :type (or null symbol) :initform nil))
  "snitch entry for events attempting to create a network
connection.  Supplies information about the name, host, port, and
protocol family of the connection that snitch is considering.")


;;
;;
;; Constants
;;
;;

(defconst snitch-source-package-types
  '(built-in site-lisp user)
  "Possible types for a snitch event's package source, as found
in the ‘src-pkg’ field of each event object.  In addition to
these pre-defined types, any loaded package name (as a symbol) is
a permitted type as well.

  'built-in' -- package provided by emacs, and responds true to
the ‘package-built-in-p’ function.

  'site-lisp' -- package is found in one of the emacs common
directories (i.e. a system-wide shared elisp directory), but does
not report itself as a built-in.

  'user' -- a package from an unknown source, possibly manually
installed by the user.

  anything else -- a package registered in ‘package--alist’,
typically including those installed by package managers.")

(defconst snitch-hook-types
  '(event block allow whitelist blacklist)
  "Types provided to user-defined hooks registered with snitch.

The types match with the hook callbacks that can receive
them (i.e. ‘snitch-on-event-functions’), but are also provided as
arguments so the same function can be used for multiple hook
types.

  'event' -- any event type

  'block' -- log events that are blocked by policy

  'allow' -- log events that are permitted by policy

  'whitelist' -- log events that would have been blocked, but
were permitted by a whitelist rule

  'blacklist' -- log events that would have been allowed, but
were blocked by a blacklist rule")

(defconst snitch-log-policies
  '(
    ;; log absolutely everything
    all

    ;; log actions for both subprocesses and networks
    blocked
    allowed
    whitelisted
    blacklisted

    ;; log actions for only subprocesses
    process-blocked
    process-allowed
    process-whitelisted
    process-blacklisted

    ;; log actions for only network connections
    network-blocked
    network-allowed
    network-whitelisted
    network-blacklisted
    )
  "All of the logging policies for snitch.  Provide a list of
these symbols to ‘snitch-log-policy’ to enable logging of events of
the corresponding type.

  'all' -- logs every event, before a decision is made.

  'blocked' -- log events that are blocked by policy

  'allowed' -- log events that are permitted by policy

  'whitelisted' -- log events that would have been blocked, but
were permitted by a whitelist rule

  'blacklisted' -- log events that would have been allowed, but
were blocked by a blacklist rule

  'process-*' -- only log subprocess events of the matching type

  'network-*' -- only log network connection events of the
matching type")

(defconst snitch-firewall-policies
  '(deny allow)
  "Default firewall policies.

  'allow' -- allow all processes/connections unless overridden by
a blacklist rule or registered hook.

  'deny' -- deny all processes/connections unless overridden by a
whitelist rule or registered hook.")


;;
;;
;; Internal functions
;;
;;

(defun snitch--service-to-port (service)
  "Convert SERVICE argument of ‘make-network-process’ into a symbol
or number."
  (cond
   ((symbolp service) service)
   ;; TODO: handle special service names, ex: "https"
   ((stringp service) (string-to-number service))
   ((numberp service) service)
   (t (progn
        (message "ERROR: unknown network service: %s" service)
        nil))))

(defun snitch--decide (event
                       decision-list
                       list-evt-type
                       list-hook-fns
                       default-evt-type
                       default-hook-fns)
  "Return t if EVENT is to be filtered differently from the
default policy, nil if default action is to be taken.  The choice
of DECISION-LIST (whitelist or blacklist) and the event types
(LIST-EVT-TYPE and DEFAULT-EVT-TYPE) determines whether default
is block/allow.  Registered user hooks are called, and potentially
alter the decision.

This function only generates a decision.  It does not perform the
actual block or pass action.

Example: if DEFAULT-EVT-TYPE is ‘block’ and DECISION-LIST is
‘snitch-network-whitelist’, this function will check each entry
in the network whitelist for an exception.  If no exception is
found, it will call the user hooks in
‘snitch-on-block-functions’.  If one of those hooks returns nil,
‘snitch--decide’ returns t, indicating that the user hook has
changed the default behavior for this event (it should allow
instead of block).  On the other hand, if every user hook returns
t, ‘snitch--decide’ returns nil, indicating that the default
block action should be taken."
  (cl-loop for (f-fn . f-args) in decision-list
           ;; when event is in the white/blacklist, and no
           ;; hooks override the list, return t.
           when (and (apply f-fn (cons event f-args))
                     (run-hook-with-args-until-failure list-hook-fns
                                                        'list-evt-type
                                                        event))
           return t
           ;; otherwise fall back on default policy
           finally return
           (if (run-hook-with-args-until-failure default-hook-fns
                                                 default-evt-type
                                                 event)
               nil
             t)))

(defun snitch--wrap-internal (event prefix orig-fun args)
  "Execute the wrapped function, ORIG-FUN with its original
arguments ARGS if EVENT is allowed by default policy or
whitelist.  PREFIX is the string 'process' or 'network' to
indicate the type of event.  Registered hooks are called before
making the final decision, and the decision is logged based on
the globally configured log filters."
  (when (run-hook-with-args-until-failure snitch-on-event-functions
                                          'event
                                          event)
    (snitch--log 'all event)
    (let* ((policy (symbol-value (intern-soft
                                  (format "snitch-%s-policy" prefix))))
           (wl (symbol-value (intern-soft
                              (format "snitch-%s-whitelist" prefix))))
           (bl (symbol-value (intern-soft
                              (format "snitch-%s-blacklist" prefix))))
           (wled (intern-soft (format "%s-whitelisted" prefix)))
           (bled (intern-soft (format "%s-blacklisted" prefix)))
           (alw (intern-soft (format "%s-allowed" prefix)))
           (blk (intern-soft (format "%s-blocked" prefix)))
           (decision (cond ((eq policy 'deny)
                            (snitch--decide event
                                            wl
                                            'whitelist
                                            snitch-on-whitelist-functions
                                            'block
                                            snitch-on-block-functions))
                           (t ;; policy allow
                            (snitch--decide event
                                            bl
                                            'blacklist
                                            snitch-on-blacklist-functions
                                            'allow
                                            snitch-on-allow-functions)))))
      (cond ((eq policy 'deny)
             (progn
               (snitch--log (if decision wled blk) event)
               (when decision (apply orig-fun args))))
            (t ;; policy allow
             (progn
               (snitch--log (if decision bled alw) event)
               (unless decision (apply orig-fun args))))))))


(defun snitch--wrap-make-process (orig-fun &rest args)
  "Wrap a call to make-process in the snitch firewall decision
engine.  ORIG-FUN is called only if the snitch firewall rules
permit it."
  (let* ((caller (snitch--responsible-caller (snitch--backtrace)))
         (event (snitch-process-entry
                 :timestamp (time-to-seconds (current-time))
                 :src-fn (nth 0 caller)
                 :src-path (nth 1 caller)
                 :src-pkg (nth 2 caller)
                 :proc-name (plist-get args :name)
                 :executable (car (plist-get args :command))
                 :args (cdr (plist-get args :command)))
                ))
    (snitch--wrap-internal event "process" orig-fun args)))

(defun snitch--wrap-make-network-process (orig-fun &rest args)
  "Wrap a call to make-network-process in the snitch firewall
decision engine.  ORIG-FUN is called only if the snitch firewall
rules permit it."
  (let* ((caller (snitch--responsible-caller (snitch--backtrace)))
         (event (snitch-network-entry
                 :timestamp (time-to-seconds (current-time))
                 :src-fn (nth 0 caller)
                 :src-path (nth 1 caller)
                 :src-pkg (nth 2 caller)
                 :proc-name (plist-get args :name)
                 :host (plist-get args :host)
                 :port (snitch--service-to-port (plist-get args :service))
                 :family (plist-get args :family))))
    (snitch--wrap-internal event "network" orig-fun args)))

(defun snitch--register-wrapper-fns ()
  "Add snitch decision engine around the lowest-level emacs
functions responsible for launching subprocesses and opening
network connections."
  ;; lowest-level functions, implemented in C
  (add-function :around (symbol-function 'make-network-process)
                #'snitch--wrap-make-network-process)
  (add-function :around (symbol-function 'make-process)
                #'snitch--wrap-make-process)
  ;; TODO: are all of these covered?
  ;;   call-process
  ;;   start-process
  ;;   url-retrieve
  ;;   open-network-stream
  )

(defun snitch-unload-function ()
  "Unload the snitch decision engine wrapping functions."
  (remove-function (symbol-function 'make-network-process)
                   #'snitch--wrap-make-network-process)
  (remove-function (symbol-function 'make-process)
                   #'snitch--wrap-make-process))


;;;###autoload
(defun snitch-init ()
  "Initialize snitch.el firewall, enabling globally."
  (interactive)
  (when (snitch--register-wrapper-fns) t))

(defun snitch-deinit ()
  "Unload snitch.el firewall, disabling globally."
  (interactive)
  (snitch--stop-log-prune-timer)
  (unload-feature 'snitch t)
  (when (require 'snitch) t))

(defun snitch-restart ()
  "Unload snitch.el and re-launch snitch firewall."
  (interactive)
  (when (snitch-deinit)
    (snitch-init)))

(provide 'snitch)

;;; snitch.el ends here
