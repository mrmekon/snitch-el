;;; snitch.el --- An emacs firewall        -*- lexical-binding: t; -*-
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; Copyright (C) 2020 Trevor Bentley
;; Author: Trevor Bentley <snitch.el@x.mrmekon.com>
;; Created: 01 Dec 2020
;; Version: 0.3.0
;; Package-Requires: ((emacs "27.1"))
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
;; snitch.el (pronounced like schnitzel) is a firewall for Emacs.
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
;; included because it is extremely common for Emacs packages to
;; "shell out" to an external program for network access, commonly to
;; ‘curl’.  As a side effect, snitch can also effectively audit and
;; prevent undesired access to other programs.
;;
;; Notifications can be raised on each logged event by ensuring the
;; ’alert’ package is installed and customizing
;; ‘snitch-enable-notifications’ to t.
;;
;;
;; === WHY? ===
;;
;; Emacs is a general-purpose execution environment, executing with
;; the full privileges of whichever user launched it.  It can read and
;; create files, obviously, but also spawn external programs, open
;; network connections, and communicate through pipes.  In modern
;; times, most users manage large collections of third-party packages
;; through intelligent package managers that automatically pull in any
;; number of dependencies, updated periodically.  Any and all of these
;; could be a bit naughty, and the sheer quantity of Lisp code in a
;; modern Emacs install makes it un-auditable.
;;
;; An Emacs firewall, thus, makes sense.  Does *snitch* make sense?
;; Not really... see the SECURITY section below.  But we currently
;; have nothing, and snitch is better than nothing.
;;
;; Also, to answer the question: "I wonder if I can make an Emacs
;; firewall?"  Yes! ...well, sort of.
;;
;;
;; === MECHANISM ===
;;
;; The underlying ’firewall’ mechanism is built on function advice
;; surrounding Emacs’s lowest-level core functions for spawning
;; connections or subprocesses.  When an Emacs package or script makes
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
;; An example log entry is below, split to several lines for display.
;; In the actual log, non-verbose logs are a single line.
;;
;; >  [2020-12-03 00:16:50] (whitelisted) -- #s(snitch-network-entry \
;; >       1606951010.2966838 helm-M-x-execute-command \
;; >       /home/trevor/.emacs.d/elpa/helm-20201019.715/helm-command.el \
;; >       helm 127.0.0.1 127.0.0.1 64222 nil)
;;
;; With `snitch-log-verbose' enabled, log entries actually do take
;; several lines:
;;
;; >  [2020-12-03 01:11:27] (blocked) --
;; >  (snitch-network-entry "snitch-network-entry-157d34506664"
;; >
;; >    :timestamp 1606954287.770638
;; >    :src-fn snitch--wrap-make-network-process
;; >    :src-path "/home/trevor/.emacs.d/snitch/snitch.el"
;; >    :src-pkg user
;; >    :proc-name "google.com"
;; >    :host "google.com"
;; >    :port 80)
;;
;;
;; === GETTING SNITCH ===
;;
;; snitch is not currently published in any package repositories
;; (*ELPA).  It can be installed by any package manager that supports
;; git repositories, or manually.
;;
;; quelpa:
;;
;; >  (quelpa '(snitch :repo "mrmekon/snitch-el" :fetcher github))
;;
;; use-package + quelpa + quelpa-use-package:
;;
;; >  (use-package snitch
;; >    :quelpa (snitch :repo "mrmekon/snitch-el" :fetcher github))
;;
;; el-get:
;;
;; >  (el-get-bundle mrmekon/snitch-el)
;;
;; straight.el:
;;
;; >  (straight-use-package
;; >    '(snitch :type git :host github :repo "mrmekon/snitch-el"))
;;
;; manual:
;;
;; >  (package-install-file "/path/to/snitch-x.y.z.tar")
;;
;;
;; === USAGE ===
;;
;; Enabling snitch is as simple as calling ‘snitch-mode’
;; interactively, or ‘(snitch-mode +1)’ from your init file.
;; Initialization does very little, so this is safe to call in your
;; Emacs init without worrying about deferral or negative consequences
;; on startup time.
;;
;; The minimum required initialization is simply:
;;
;; >  (require 'snitch)
;; >  (snitch-mode +1)
;;
;; An example initialization using ‘use-package’ might look like so:
;;
;; >  (use-package snitch
;; >    :config
;; >    (snitch-mode +1))
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
;; To disable snitch, call ‘snitch-mode’ interactively, or
;; ‘(snitch-mode -1)’ programmatically.  You can restart snitch with
;; ‘snitch-restart’.
;;
;;
;; === CONFIGURATION ===
;;
;; Customize snitch with ‘M-x customize-group <RET> snitch’, or
;; manually in your Emacs initialization file.
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
;; Have a look in ‘snitch-filter.el’ for examples of black/whitelist
;; filters, and in ‘snitch-test.el’ for contrived examples of pretty
;; much everything.
;;
;;
;; ==== COMMON CONFIG: DENY ====
;;
;; A useful configuration is to deny all external communication by
;; default, but allow certain packages to communicate.  This example
;; demonstrates permitting only the ’elfeed’ package to create network
;; connections:
;;
;; >  (use-package snitch
;; >    :config
;; >    (setq snitch-network-policy 'deny)
;; >    (setq snitch-process-policy 'deny)
;; >    (setq snitch-log-policy '(blocked whitelisted allowed))
;; >    (add-to-list 'snitch-network-whitelist
;; >                  (cons #'snitch-filter-src-pkg '(elfeed)))
;; >    (snitch-mode +1))
;;
;;
;; ==== COMMON CONFIG: ALLOW + AUDIT ====
;;
;; Another useful configuration is to allow all accesses, but log them
;; to keep an audit trail.  This might look like so:
;;
;; >  (use-package snitch
;; >    :config
;; >    (setq snitch-network-policy 'allow)
;; >    (setq snitch-process-policy 'allow)
;; >    (setq snitch-log-policy '(allowed blocked whitelisted blacklisted))
;; >    (setq snitch-log-verbose t)
;; >    (snitch-mode +1))
;;
;;
;; ==== FILTER RULES ====
;;
;; Filter rules, as specified in ‘snitch-(process|network)-*list’
;; variables, are specified as cons cells where the car is a filtering
;; function, and the cdr is a list of arguments to pass to the
;; function in addition to the event object:
;;
;; > (setq snitch-network-whitelist
;; >   '(
;; >      (filter-fn1 . (argQ))
;; >      (filter-fn2 . (argN argP))
;; >    ))
;;
;; Each filter function should have a prototype accepting EVENT as the
;; snitch event object in consideration, and ARGS as the list of
;; arguments from the cdr of the rules entry:
;;
;; >  (defun filter-fn1 (event &rest args))
;;
;; EVENT is an eieio object defined by ‘snitch-network-entry’ or
;; ‘snitch-process-entry’, and inheriting from ‘snitch-source’.
;;
;; A trivial function which matches if a single string in the event
;; object matches a known value might look like so:
;;
;; >  (defun filter-fn1 (event name)
;; >    (string-equal (oref event proc-name) name))
;;
;; While a more complex filter function might treat ARGS as an
;; associative list of key/value pairs:
;;
;; >  (defun filter-fn2 (event &rest alist)
;; >    (cl-loop for (aslot . avalue) in alist with accept = t
;; >             do
;; >             (let ((evalue (eieio-oref event aslot))
;; >                   (val-type (type-of avalue)))
;; >               (unless (cond
;; >                        ((eq val-type 'string) (string-equal avalue evalue))
;; >                        (t (eq avalue evalue)))
;; >                 (setq accept nil)))
;; >             when (null accept)
;; >             return nil
;; >             finally return accept))
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
;; Hook functions take two arguments, the type and the event object:
;;
;; >  (defun snitch-hook (type event))
;;
;; TYPE is one of `snitch-hook-types', and corresponds with the names
;; of the hook lists.  This argument is provided so you can define one
;; function which can be used in several hooks.
;;
;; EVENT is an eieio object defined by ‘snitch-network-entry’ or
;; ‘snitch-process-entry’, and inheriting from ‘snitch-source’.
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
;; snitch also supports filtering log entries with hooks via
;; ‘snitch-log-functions’.  These hooks can pass, block, or modify
;; entries before they are printed in the snitch log.  See ‘M-x
;; describe-variable <RET> snitch-log-functions’ for details.
;;
;; snitch also calls hooks when it starts (‘snitch-init-hook’), shuts
;; down (‘snitch-deinit-hook’), or opens or closes the log filter
;; window (‘snitch-log-filter-window-open-hook’,
;; ‘snitch-log-filter-window-close-hook’).
;;
;;
;; === PERFORMANCE ===
;;
;; Performance has not been measured, and should not be assumed to be
;; particularly good.  Nothing is currently optimized.
;;
;; Memory usage should not be particularly high, as events are
;; ephemeral and only contain a small amount of metadata.  The largest
;; use of memory is the audit log, which does keep copies of all
;; events in the log.  This can be controlled via
;; ‘snitch-log-buffer-max-lines’.
;;
;; Firewall rules are traversed linearly, and short-circuit (if an
;; early rule terminates processing, the subsequent rules will not be
;; considered).  To optimize for performance, the total number of
;; rules should be kept to a minimum, and most likely to match rules
;; should be added earlier in the lists.
;;
;;
;; === TIMER TRACING ===
;;
;; Since snitch’s usefulness is highly dependent on the ability to
;; trace back to the original source that triggered an event, Emacs
;; timers pose a bit of a challenge.  Timers are used to trigger
;; network requests asynchronously, but have the side effect of losing
;; the stack trace back to the function or package that initiated it.
;;
;; To deal with this, snitch optionally supports timer tracing.  When
;; tracing is enabled, by customizing ‘snitch-trace-timers’ to t,
;; snitch hooks into Emacs’s timer functions, and records backtraces
;; whenever a timer is registered.  If a timer later generates a
;; snitch-relevant event, snitch concatenates the regular backtrace
;; with the cached timer backtrace to get a full call stack for the
;; event.
;;
;; As an example, here are two snitch log entries when opening RSS
;; feeds with the elfeed package, which uses timers for web requests:
;;
;; With ‘snitch-trace-timers’ set to nil (tracing disabled):
;;
;; >  [2020-12-07 21:32:56] (allowed) -- #s(snitch-network-entry \
;; >    1607373176.6757963 \
;; >    timer-event-handler \
;; >    /usr/share/emacs/27.1/lisp/emacs-lisp/timer.el \
;; >    site-lisp \
;; >    www.smbc-comics.com www.smbc-comics.com 443 nil)
;;
;; Notice how the source is the function ‘timer-event-handler’ in
;; ‘timer.el’, part of the special ‘site-lisp’ package?  *All*
;; timer-originated network calls appear to originate from that
;; function, since it is the lowest level Emacs timer dispatch
;; function.  It is impossible to filter on the true source.
;;
;; Now with ‘snitch-trace-timers’ set to t (tracing enabled):
;;
;; >  [2020-12-07 21:33:06] (allowed) -- #s(snitch-network-entry \
;; >    1607373186.6863618 \
;; >    elfeed-insert-html
;; >    /home/trevor/.emacs.d/elpa/elfeed-20200910.239/elfeed-show.el \
;; >    elfeed \
;; >    www.smbc-comics.com www.smbc-comics.com 443 nil)
;;
;; For this event, snitch has successfully traced through the timer to
;; find the true source, ‘elfeed-insert-html’ in the ‘elfeed’ package!
;;
;; Timer tracing comes with a cost: snitch has to generate metadata
;; for every single timer event.  If your Emacs usage involves a very
;; large number of timers, or very high-frequency timers, snitch’s
;; tracing could lead to delays and inflated memory usage.  Consider
;; carefully whether this is a feature you need, and leave it disabled
;; if you will not use it, or if you experience any performance issues
;; while running snitch.
;;
;; You can run ‘snitch-monitor-unique-timer-fns’ to get a sense of
;; which timers are currently active.  After running that function,
;; there will be a 60 second delay, followed by printing the names of
;; all timers that were active during the minute and the number of
;; times they fired.
;;
;; Similarly, if you run with timer tracing enabled for a while, you
;; can use ‘snitch--debug-print-timer-state’ to print a summary of how
;; many timers snitch has intercepted, and how many saved backtraces
;; are currently active in memory.
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
;; Tamper-proof: none at all.  Any other Emacs package can simply
;; disable snitch, or modify it to pass malicious traffic undetected.
;;
;; Complete mediation: no attempt has been made to verify that *all*
;; network and subprocess accesses must go through the functions that
;; snitch hooks.  Given the complexity of Emacs, it is extremely
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
;; record of exactly what your Emacs is doing, and for fine-tuning
;; accesses beyond Emacs’s boundaries a little bit better.  It will
;; not, however, save you from the bad guys.
;;
;;
;; === KNOWN LIMITATIONS ===
;;
;; When snitch blocks events, some Emacs functions that seldom throw
;; errors in normal use will throw errors because of snitch.  It is
;; very likely that blocked connections will cause errors to bubble up
;; in strange and unexpected ways, as many package authors have not
;; handled these exceptional cases.
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
;; snitch has not been tested with IPv6.
;;
;; snitch has not been tested with inbound connections.  In theory, it
;; can prevent the creation of a listening socket.  Once a socket is
;; open, though, it would not be able to monitor incoming connections
;; to the socket.
;;
;;
;; === TODO ===
;;
;;  - send notifications in batches?
;;  - interactive prompts?
;;  - handle service strings as port numbers
;;  - ensure the inverted negation rules make sense
;;  - add blacklist for timer functions
;;  - publish on MELPA?
;;  - profit!
;;
;;
;; === VERSION HISTORY ===
;;
;; v0.3.0 (development)
;;
;;   - make snitch a global minor mode
;;     - introduce (snitch-mode)
;;     - make (snitch-init) private (snitch--init)
;;     - make (snitch-deinit) private (snitch--deinit)
;;   - add init and deinit hooks
;;
;; v0.2.0 (2020-12-09)
;;
;;   - first published version
;;
;; v0.1.0 (before 2020-12-09)
;;
;;   - Initial development and testing
;;   - Network and process firewall functionality
;;   - Audit logging
;;   - Whitelist + blacklist filtering
;;   - Backtrace processing
;;   - Timer backtrace expansion
;;   - User event and logging hooks
;;   - ert test framework
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
(require 'cl-lib) ; cl loops
(require 'package) ; backtrace package sources
(require 'backtrace)

(require 'snitch-backtrace)
(require 'snitch-custom)
(require 'snitch-filter)
(require 'snitch-timer)
(require 'snitch-log)

;;
;;
;; Classes
;;
;;

;;;###autoload
(defclass snitch-source ()
  ((timestamp :initarg :timestamp :type number :initform 0)
   (src-fn :initarg :src-fn :type (or null symbol) :initform nil)
   (src-path :initarg :src-path :type (or null string) :initform nil)
   (src-pkg :initarg :src-pkg :type (or null symbol) :initform nil))
  "Common base class for snitch entries.  Supplies information
about snitch's best guess for which emacs function/file/package
is ultimately responsible for the event that snitch is
considering.")

;;;###autoload
(defclass snitch-process-entry (snitch-source)
  ((proc-name :initarg :proc-name :type (or null string) :initform nil)
   (executable :initarg :executable :type (or null string) :initform nil)
   (args :initarg :args :type list :initform ()))
  "snitch entry for events attempting to spawn a
subprocess. Supplies information about the name, executable
binary, and arguments being provided to the subprocess that
snitch is considering.")

;;;###autoload
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

(defconst snitch--version "0.3.0"
  "Snitch version as a string.")

(defconst snitch-source-package-types
  '(built-in site-lisp user)
  "Possible types for a snitch event's package source, as found
in the ‘src-pkg’ field of each event object.  In addition to
these pre-defined types, any loaded package name (as a symbol) is
a permitted type as well.

  nil -- unknown source, including lambdas, closures, and
compiled functions.

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
    network-blacklisted)
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
           when (apply f-fn (cons event f-args))
           return (run-hook-with-args-until-failure list-hook-fns
                                                    list-evt-type
                                                    event)
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
  (when (run-hook-with-args-until-failure 'snitch-on-event-functions
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
                                            'snitch-on-whitelist-functions
                                            'block
                                            'snitch-on-block-functions))
                           (t ;; policy allow
                            (snitch--decide event
                                            bl
                                            'blacklist
                                            'snitch-on-blacklist-functions
                                            'allow
                                            'snitch-on-allow-functions)))))
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
  (let* ((bt (snitch--backtrace t))
         (caller (snitch--responsible-caller bt))
         (event (snitch-process-entry
                 :timestamp (time-to-seconds (current-time))
                 :src-fn (nth 0 caller)
                 :src-path (nth 1 caller)
                 :src-pkg (nth 2 caller)
                 :proc-name (plist-get args :name)
                 :executable (car (plist-get args :command))
                 :args (cdr (plist-get args :command)))))
    (snitch--wrap-internal event "process" orig-fun args)))

(defun snitch--wrap-make-network-process (orig-fun &rest args)
  "Wrap a call to make-network-process in the snitch firewall
decision engine.  ORIG-FUN is called only if the snitch firewall
rules permit it."
  (let* ((bt (snitch--backtrace t))
         (caller (snitch--responsible-caller bt))
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

(defun snitch--unregister-wrapper-fns ()
  "Unload the snitch decision engine wrapping functions."
  (remove-function (symbol-function 'make-network-process)
                   #'snitch--wrap-make-network-process)
  (remove-function (symbol-function 'make-process)
                   #'snitch--wrap-make-process))


(defun snitch--init ()
  "Initialize snitch.el firewall, enabling globally."
  (interactive)
  (when snitch-mode
      (snitch--deinit))
  (when snitch-trace-timers (snitch--activate-timer-trace))
  (when (snitch--register-wrapper-fns) t)
  (run-hooks 'snitch-init-hook))

(defun snitch--deinit (&optional rerequire)
  "Unload snitch.el firewall, disabling globally.

When the optional argument REREQUIRE is t, the snitch feature is
completely unloaded and re-loaded into Emacs.  Autoloaded symbols
may be lost in this process."
  (interactive)
  (snitch--deactivate-timer-trace)
  (snitch--stop-log-prune-timer)
  (snitch--unregister-wrapper-fns)
  (run-hooks 'snitch-deinit-hook)
  (when rerequire
    (unload-feature 'snitch t)
    (when (require 'snitch) t)))

;;;###autoload
(defun snitch-restart ()
  "Restart the snitch firewall, unloading and reloading all
hooks."
  (interactive)
  (when (snitch--deinit)
    (snitch--init)))

;;;###autoload
(defun snitch-version ()
  "Return loaded snitch’s version number as a string."
  snitch--version)

;;;###autoload
(define-minor-mode snitch-mode
  "Toggle snitch firewall on and off.

The snitch firewall is enabled as a global minor mode, and
monitors network connections and subprocesses in the background.

For more information, use ‘M-x describe-package <RET> snitch’.

To customize, use ‘M-x customize-group <RET> snitch’.

No mode-line annotation is displayed by default, but this can be
changed by customizing ‘snitch-lighter’.  To add custom code
after start or shutdown, add hooks to ‘snitch-init-hook’ or
‘snitch-deinit-hook’."
  :global t
  :lighter snitch-lighter
  :group 'snitch
  (if snitch-mode
      (snitch--init)
    (snitch--deinit)))

(provide 'snitch)

;;; snitch.el ends here
