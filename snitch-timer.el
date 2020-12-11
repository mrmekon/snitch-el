;;; snitch-timer.el -- part of snitch      -*- lexical-binding: t; -*-
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
;; This file hooks Emacs timers to save backtrace information.  It is
;; used by the snitch-backtrace functions to reproduce full backtraces
;; for functions initiated by timers.  This is required to provide a
;; more accurate guess as to which function/package originated a call
;; intercepted by snitch, since functions started by timers lose their
;; original backtrace.
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
(require 'snitch-backtrace)
(require 'snitch-custom)

(defvar snitch--timer-alist '()
  "Cache of Emacs timers tracked by snitch.

Cache all timers registered with Emacs, along with their
backtrace and a timeout.  Stored as a list of (TIMER . METADATA)
cons cell entries, where each METADATA item is a (BACKTRACE
. TIMEOUT) cons cell.  TIMER is a standard Emacs timer object,
BACKTRACE is a snitch backtrace, and TIMEOUT is a standard Emacs
time object.")

(defvar snitch--timer-removal-queue '()
  "List of Emacs timers to be removed from snitch’s tracking.

List of timers to be removed from snitch’s backtrace tracking
when the timer call stack is empty.  Timers are queued to be
removed instead of removed immediately because of the (likely)
possibility of recursive removals.  If the timer is removed deep
in a recursive stack, the outer calls are unable to decorate the
backtraces as the stack unwinds because the timer is already
gone.")

(defvar snitch--timer-count 0
  "Total number of timers snitch has tracked.

Total number of timers snitch has saved (timers registered with
Emacs and intercepted by snitch).")

(defvar snitch--timer-removed-count 0
  "Total number of timers snitch has finished tracking.

Total number of timers snitch has removed (timers fired or
cancelled that snitch knew about).")

(defvar snitch--timer-missed-count 0
  "Total number of timers that snitch failed to track.

Total number of timers snitch has missed.  This is timers that
are removed (cancelled or triggered) while not currently tracked
in ‘snitch--timer-alist’.  This can happen naturally if snitch is
started when timers already exist, but could also indicate bugs
causing snitch to lose track of timers.")

(defvar snitch--wrap-timer-depth 0
  "Tracks current recursive depth of calls to remove timers.
Timer handlers often attempt to manually remove themselves,
resulting in several calls to remove the same timer.")

(defvar snitch--max-timer-backtraces 1000
  "Max number of timer backtrace snitch tracks at a time.

Maximum number of timer backtraces that snitch should keep
track of.  If more timers than this are started without ending,
new timers are ignored.")

(defvar snitch--save-unique-timer-fns nil
  "Whether snitch saves names of timers tracked.

While t, snitch saves a list of the unique functions
registered as timers, along with a count of how many times they
were seen.  This allows tracking which high-frequency timers are
common in your Emacs, so they can be added to the timer
blacklist.")

(defvar snitch--unique-timer-fns '()
  "List of unique timer functions snitch has tracked.

A list of unique timer functions encountered, and how many
times they were seen during the period that
‘snitch--save-unique-timer-fns’ was t.")

(defun snitch-monitor-unique-timer-fns (&optional time no-reset)
  "Print names of timer functions snitch recently tracked.

Keeps a running count of each unique timer function that arrives
during time period TIME.  After TIME has elapsed, prints all
timers seen along with the number of times each was seen during
the monitoring time period.

Each call to this function resets the seen timer list to empty.
To continue capturing without clearing the list, set NO-RESET to
t."
  (interactive)
  (unless time (setq time 60))
  (unless no-reset
    (setq snitch--unique-timer-fns '()))
  (setq snitch--save-unique-timer-fns t)
  (run-with-timer
   time nil
   (lambda ()
     (setq snitch--save-unique-timer-fns nil)
     (message "*** SNITCH -- UNIQUE TIMERS DETECTED IN %d s ***" time)
     (cl-loop for (timer . count) in snitch--unique-timer-fns
              do (message "%s: %d" timer count)))))

(defun snitch--timer-test-idle-timeout (time)
  "Whether a tracked idle timer has timed out.

Return t if an idle timer has timed out (current idle time
greater than TIME)."
  (let ((idle (current-idle-time)))
    (when idle
      (time-less-p time idle))))

(defun snitch--timer-test-timeout (time)
  "Whether a tracked normal timer has timed out.

Return t if a regular timer has timed out (current absolute time
greater than TIME)."
  (time-less-p time (current-time)))

(defun snitch--timer-timeout (timer)
  "Calculate timeout period for a tracked timer.

Calculate a timeout for a timer, TIMER, a few minutes longer than
it is originally scheduled to fire."
  (time-add (timer--time timer) (time-convert (* 60 5))))

(defun snitch--fn-repr (fn)
  "Output function in human-readable format.

Encode FN in a semi-human-readable form if it is a compiled
function."
  (cond
   ((byte-code-function-p fn)
    ;; sxhash would be a nice alternative, but it isn't guaranteed
    ;; to be consistent across sessions.
    ;;
    ;; (base64-encode-string (gnutls-hash-digest "SHA1" (aref fn 1)))
    ;; (sxhash (aref fn 1))
    (secure-hash 'sha1 (aref fn 1)))
   ((and (listp fn)
         (or (eq (car fn) 'lambda)
             (eq (car fn) 'closure)))
    (secure-hash 'sha1 (prin1-to-string fn)))
   (t fn)))

(defun snitch--save-timer-function (fn)
  "Save recently tracked timer in cache.

Save timer function FN in SNITCH--UNIQUE-TIMER-FNS if it does
not already exist, otherwise increment its counter.  Byte
compiled functions are stored as a hash, since their names are
unknown."
  (let* ((fn-rep (snitch--fn-repr fn))
         (entry (assoc fn-rep snitch--unique-timer-fns)))
    (if entry
        (setcdr entry (+ (cdr entry) 1))
      (setq snitch--unique-timer-fns
            (cons (cons fn-rep 1) snitch--unique-timer-fns)))))

(defun snitch--save-timer-backtrace (orig-fn &rest args)
  "Save timer and its backtrace in snitch’s timer cache.

Cache a timer and its associated backtrace.  This function is
hooked around all functions that register new timers with Emacs.
It saves the backtrace and a timeout period for when snitch
should stop listening for it in case the timer is somehow lost.
It calls the original Emacs timer registration function without
modification and returns the result.

Always calls the original function ORIG-FN is called with its
arguments ARGS unmodified."
  (let* ((bt (snitch--backtrace))
         (timer (nth 0 args))
         (idle (nth 3 args))
         (expire-time (snitch--timer-timeout timer))
         (timeout-fn
          (if idle
              (lambda () (snitch--timer-test-idle-timeout expire-time))
            (lambda () (snitch--timer-test-timeout expire-time))))
         (result (apply orig-fn args)))
    (when snitch--save-unique-timer-fns
      (snitch--save-timer-function (timer--function timer)))
    (if (>= (length snitch--timer-alist) snitch--max-timer-backtraces)
        (when snitch-print-timer-warnings
          (message "*snitch warning* too many timers, discarding: %s"
                   (snitch--fn-repr (timer--function timer))))
      (progn
        (setq snitch--timer-alist
              (cons (cons timer (cons bt timeout-fn)) snitch--timer-alist))
        (setq snitch--timer-count (+ snitch--timer-count 1))))
    result))

(defun snitch--remove-timed-out-timers ()
  "Remove tracked timers that have timed out.

Iterate of all of snitch's saved timer backtraces and remove
any that have timed out."
  (cl-loop for (timer . (_bt . timeout-fn)) in snitch--timer-alist
           when (funcall timeout-fn)
           do
           (let ((match (assq timer snitch--timer-alist)))
             (when match
               (when snitch-print-timer-warnings
                 (message "*snitch warning* timer timed out: %s"
                          (snitch--fn-repr (timer--function timer))))
               (setq snitch--timer-removed-count
                     (+ snitch--timer-removed-count 1))
               (setq snitch--timer-alist
                     (delq match snitch--timer-alist))))))

(defun snitch--remove-timers (timers)
  "Remove a list of timers from snitch’s tracking.

Remove all timers in TIMERS from the timer backtrace cache, if
present."
  (let ((total-timers (length timers))
        (removed-timers 0))
    (cl-loop
     for timer in timers
     do (let ((match (assq timer snitch--timer-alist)))
          (when (and (null match)
                     snitch-print-timer-warnings)
            (message "*snitch warning* remove unknown timer: %s"
                     (snitch--fn-repr (timer--function timer)))
            (setq snitch--timer-missed-count
                  (+ snitch--timer-missed-count 1)))
          (when match
            (setq snitch--timer-removed-count
                  (+ snitch--timer-removed-count 1))
            (setq removed-timers (1+ removed-timers))
            (setq snitch--timer-alist
                  (delq match snitch--timer-alist)))))
    ;;(message "removed %d of %d timers" removed-timers total-timers)
    (list removed-timers total-timers)))

(defun snitch--remove-timer-backtrace (orig-fn timer)
  "Remove a timer from snitch’s tracking cache.

Remove a timer from snitch’s cache.  This function is wrapped
around ‘timer-event-handler’ and ‘cancel-timer’, triggering
whenever a timer either fires or is explicitly cancelled.  It
removes snitch’s decorated copy and calls the originally
requested function as normal.

Always calls the original function ORIG-FN with its original
argument, TIMER."
  (setq snitch--wrap-timer-depth (+ snitch--wrap-timer-depth 1))
  (let* ((result (apply orig-fn (list timer))))
    ;; TODO: this is probably wrong.  What if one timer removed a
    ;; different timer?  That would also be at a lower depth.
    ;; Disabled depth test for now, but that triggers the ’unknown
    ;; timer’ warning all the time, so that is also disabled.
    ;;
    ;; TODO: reverted back to only removing at top, but need to fix
    ;; this.  When recursive removals are allowed, it gets removed
    ;; from the alist during a deeper cancel-timer call before the
    ;; outer logic finishes running and actually triggers the snitch
    ;; path that needs the backtrace.  We should queue up removals in
    ;; a list and remove them all at once when wrap-depth falls to 0.
    (add-to-list 'snitch--timer-removal-queue timer)
    (setq snitch--wrap-timer-depth
          (- snitch--wrap-timer-depth 1))
    ;; as we exit the last removal attempt in the potentially
    ;; recursive stack, actually remove the timers from snitch’s cache
    ;; and check for any timed out ones
    (when (eq snitch--wrap-timer-depth 0)
        (snitch--remove-timers snitch--timer-removal-queue)
        (setq snitch--timer-removal-queue '())
        (snitch--remove-timed-out-timers))
    result))

(defun snitch--get-timer-backtrace (timer)
  "Return backtrace for TIMER if it is currently known."
  (let ((match (assq timer snitch--timer-alist)))
    (when match
      (car (cdr match)))))

(defun snitch--remove-timer-hooks ()
  "Remove snitch’s timer hooks, disabling timer backtraces."
  (remove-function (symbol-function 'timer--activate)
                   #'snitch--save-timer-backtrace)
  (remove-function (symbol-function 'timer-event-handler)
                   #'snitch--remove-timer-backtrace)
  (remove-function (symbol-function 'cancel-timer)
                   #'snitch--remove-timer-backtrace)
  (remove-function (symbol-function 'cancel-timer-internal)
                   #'snitch--remove-timer-backtrace))

(defun snitch--register-timer-hooks ()
  "Register snitch’s timer tracing hooks.

Add timer hooks so snitch can provide backtraces all the way
to the source of whichever function registered the timer."
  (setq snitch--timer-alist '()
        snitch--timer-removal-queue '()
        snitch--wrap-timer-depth 0
        snitch--timer-count 0
        snitch--timer-removed-count 0
        snitch--timer-missed-count 0
        snitch--unique-timer-fns '())
  (add-function :around (symbol-function 'timer--activate)
                #'snitch--save-timer-backtrace)
  (add-function :around (symbol-function 'timer-event-handler)
                #'snitch--remove-timer-backtrace)
  (add-function :around (symbol-function 'cancel-timer)
                #'snitch--remove-timer-backtrace)
  (add-function :around (symbol-function 'cancel-timer-internal)
                #'snitch--remove-timer-backtrace))

(defun snitch--debug-print-timer-state (&optional alist)
  "Print state of snitch’s timer tracing.

Print current state of snitch’s timer tracing to the messages
log.  If ALIST is t, also prints the currently cached timers."
  (interactive)
  (message "%s" (current-time-string))
  (message "timer active: %d" (length snitch--timer-alist))
  (message "timer saved: %d" snitch--timer-count)
  (message "timer removed: %d" snitch--timer-removed-count)
  (message "timer missed: %d" snitch--timer-missed-count)
  (when alist
    (message "timer alist: %s" snitch--timer-alist)
    (cl-loop for (_timer . (_bt . timeout-fn)) in snitch--timer-alist
             do (message "timeout? %s" (funcall timeout-fn)))))

(defun snitch--activate-timer-trace ()
  "Activate snitch timer tracing.

Activate snitch timer tracing by hooking the appropriate
functions."
  (interactive)
  (snitch--register-timer-hooks))

(defun snitch--deactivate-timer-trace ()
  "Deactivate snitch timer tracing."
  (interactive)
  (snitch--remove-timer-hooks))

(defun snitch--debug-test-print-timers ()
  "Print snitch’s cached timer state.

Print snitch’s cached timers, and all of Emacs’ currently
registered timers."
  (cl-loop for (timer . meta) in snitch--timer-alist
           do
           (message "timer fn: %s" (timer--function timer)))
  (cl-loop for timer in timer-list
           do
           (message "timer fn: %s" (timer--function timer)))
  (cl-loop for timer in timer-idle-list
           do
           (message "timer fn: %s" (timer--function timer))))


(provide 'snitch-timer)

;;; snitch-timer.el ends here
