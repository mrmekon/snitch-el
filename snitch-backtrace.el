;;; snitch-backtrace.el -- part of snitch  -*- lexical-binding: t; -*-
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
;; This file provides backtrace analysis for snitch.el.  It is used to
;; attempt to determine the most likely original source of an event.
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
(require 'cl-lib) ; cl loops
(require 'package) ; backtrace package sources
(require 'backtrace)

(require 'snitch-timer)

;; Since the backtrace functions might be called extremely often,
;; particularly when timer tracing is enabled, much of the metadata
;; needed to flesh out backtraces is cached on first use.  This
;; optimization brought execution time for (snitch--backtrace) down
;; from 20ms to 1ms on my (quite fast) machine.
;;
;; TODO: invalidate, refresh, or limit size of these caches?
;; snitch--package-dirs-cache might grow unbounded.

(defvar snitch--site-lisp-dir-cache nil
  "Cache a list of the Emacs site-lisp directories.")

(defvar snitch--site-lisp-root-cache nil
  "Cache a list of the Emacs site-lisp root directories.")

(defvar snitch--function-to-file-cache nil
  "Cache of function-to-file mappings.

Hash table cache of function names to the file the functions are
defined in.")

(defvar snitch--package-dirs-cache '()
  "Cache of elisp package directories.

Hash table cache mapping elisp directories to active packages.")


(defun snitch--fn-hash-cmp (a b)
  "Hash comparison for function/package cache.

Hash comparison function for function/package hash table,
since functions can be either function objects or strings and
require different comparisons.

Return t if A equals B."
  (if (and (functionp a) (functionp b))
      (eq a b)
    (equal a b)))

(defun snitch--find-function-file (fn)
  "Find file owning function FN.

Look up the file a function is defined in, caching it in a
hash table for quicker subsequent accesses."
  (unless snitch--function-to-file-cache
    (define-hash-table-test 'snitch-fn-hash-cmp
      #'snitch--fn-hash-cmp #'sxhash-equal)
    (setq snitch--function-to-file-cache
          (make-hash-table :test 'snitch-fn-hash-cmp)))
  (let ((stored-file (gethash fn snitch--function-to-file-cache)))
    (if stored-file (if (eq stored-file 'notfound) nil
                      stored-file)
      (let ((file (find-lisp-object-file-name fn 'defun)))
        (if file
            (puthash fn file snitch--function-to-file-cache)
          (progn
            (puthash fn 'notfound snitch--function-to-file-cache)
            nil))))))

(defun snitch--site-lisp-dirs ()
  "Find site-lisp directories.

Find all directories in elisp load path that are not in the user
dir."
  (if (not snitch--site-lisp-dir-cache)
      (let* ((user-dir (expand-file-name user-emacs-directory))
             (pkg-dir (expand-file-name package-user-dir))
             (dirs
              (cl-loop for dir in (elisp-load-path-roots)
                       unless (or
                               (string-prefix-p user-dir dir)
                               (string-prefix-p pkg-dir dir)
                               (string-prefix-p package-user-dir dir)
                               (string-prefix-p user-emacs-directory dir))
                       collect dir)))
        (setq snitch--site-lisp-dir-cache dirs)
        dirs)
    snitch--site-lisp-dir-cache))

(defun snitch--site-lisp-roots ()
  "Find the root site-lisp directories.

Find the 'root' directories, hopefully a list of
system-wide/non-user base directories containing elisp files."
  (if (not snitch--site-lisp-root-cache)
      (let ((dirs
             (cl-loop for dir in (snitch--site-lisp-dirs)
                      if (or (string-equal "lisp" (file-name-base dir))
                             (string-equal "site-lisp" (file-name-base dir)))
                      collect dir)))
        (setq snitch--site-lisp-root-cache dirs)
        dirs)
    snitch--site-lisp-root-cache))

(defun snitch--dir-in-site-lisp (dir)
  "Check if DIR is in a site-lisp directory.

Check if directory DIR is a subdirectory of one of the
system-wide elisp directories found by
`snitch--site-lisp-roots'."
  (not (null (cl-loop for site-dir in (snitch--site-lisp-roots)
                      if (string-prefix-p site-dir dir)
                      collect site-dir))))

(defun snitch--fill-package-dirs-cache ()
  "Fill package directory cache.

Cache package directories in a hash table for faster subsequent
accesses."
  (setq snitch--package-dirs-cache
        (make-hash-table :test 'equal :size (length (package--alist))))
  (cl-loop for (pkgname . pkgdesc) in (package--alist)
           do
           (puthash (file-name-as-directory (package-desc-dir (car pkgdesc)))
                    pkgname
                    snitch--package-dirs-cache))
  (hash-table-count snitch--package-dirs-cache))

(defun snitch--package-from-dir (dir)
  "Find package that owns directory DIR.

Given a directory DIR, returns a package that owns the files in
that directory."
  (when (null snitch--package-dirs-cache)
    (snitch--fill-package-dirs-cache))
  (gethash (file-name-as-directory dir) snitch--package-dirs-cache))

(defun snitch--package-from-path (path)
  "Try to guess a package name for PATH, a full path to a file.
Returns a symbol, which is either an installed package name, or
one of the following special values:

 - `built-in' -- registered as a built-in package
 - `site-lisp' -- found in a system-wide elisp directory
 - `user' -- unknown source"
  (let* ((dir (file-name-directory path))
         ;; twice to handle .el.gz
         (base (file-name-base (file-name-base path)))
         (package (snitch--package-from-dir dir)))
    (if package
        package
      (if (package-built-in-p (intern base))
          'built-in
        (if (snitch--dir-in-site-lisp dir)
            'site-lisp
          'user)))))

(defun snitch--maybe-add-timer-backtrace (bt timer)
  "Try to add a saved timer backtrace to current backtrace.

If the given backtrace BT terminates in the timer execution
handler, check if snitch has cached the backtrace for the
executing timer, TIMER, and append that backtrace to BT."
  (let ((last-fn (nth 0 (car bt)))
        (reverse-bt (nreverse bt)))
    (if (eq last-fn #'timer-event-handler)
        ;; timer event, concatenate backtraces
        (let ((t-bt (snitch--get-timer-backtrace timer)))
          (nconc reverse-bt t-bt))
      ;; not a timer event
      reverse-bt)))

(defun snitch--backtrace (&optional follow-timer)
  "Return a backtrace usable by snitch.

Return a full list of backtrace entries (the full function call
stack) where each entry is a list containing (FUNCTION PATH
PACKAGE).  Entries related to the snitch callstack are filtered
out.

FUNCTION is a function symbol if available, or one of the special
symbols ‘lambda’, ‘macro’, or ‘compiled-function’ otherwise.

PATH is the full path to the file FUNCTION is defined in, if
known.

PACKAGE is the package that FUNCTION is defined in, or one of the
special symbols ‘built-in’, ‘site-lisp’, ‘user’, or nil if
unknown.

FOLLOW-TIMER tells snitch to attempt to reconstruct a longer
backtrace if this one originated from a timer callback.
‘snitch-trace-timers’ must be t for this to have any effect.  If
it is enabled, and a matching timer is found, the backtraces are
concatenated together."
  (let* ((stack '())
         (timer-args nil)
         (frames (backtrace-get-frames))
         ;; 5 is the magic number of frames to skip out of the
         ;; snitch-related calls (0 indexed, so idx > 4):
         ;;
         ;; 1) backtrace-get-frames
         ;; 2) let (here in snitch--backtrace)
         ;; 3) snitch--backtrace
         ;; 4) let* (in snitch wrapper functions)
         ;; 5) snitch wrapper fn (ex: snitch--wrap-make-network-process)
         ;;
         ;; This only works correctly if all of snitch’s hooking
         ;;functions immediately call (snitch-backtrace) in a let block.
         ;;
         ;; The second frame, ’let’, is mysteriously absent when this
         ;; package is byte-compiled.
         (skip-frames (if (eq 'let* (backtrace-frame-fun (nth 1 frames)))
                          4
                        3)))
    (dotimes (idx (length frames))
      (if (> idx skip-frames)
          (let* ((frame (nth idx frames))
                 (fun (backtrace-frame-fun frame))
                 ;; if function is a lambda, just send back the
                 ;; 'lambda symbol instead of the entire function
                 ;; definition.  likewise for closures, which are what
                 ;; lambdas become when lexical-binding is t.
                 ;;
                 ;; compiled functions are returned as
                 ;; 'compiled-function, as they do not contain their
                 ;; own names.
                 (clean-fun (cond
                             ((and (listp fun)
                                   (eq (car fun) 'lambda))
                              'lambda)
                             ((and (listp fun)
                                   (eq (car fun) 'closure))
                              'lambda)
                             ((macrop fun) 'macro)
                             ((byte-code-function-p fun)
                              'compiled-function)
                             (t fun)))
                 (path (snitch--find-function-file fun))
                 (package (if path (snitch--package-from-path path) nil)))
            ;; if function is the timer handler, save its timer object
            ;; to lookup the backtrace for that timer later
            (if (eq fun #'timer-event-handler)
                (setq timer-args (car (backtrace-frame-args frame))))
            ;;(message "frame %d: %s (%s) [%s]" idx fun path package)
            (push (list clean-fun path package) stack))))
    (if follow-timer
        (snitch--maybe-add-timer-backtrace stack timer-args)
      (nreverse stack))))

(defun snitch--package-type-more-important (a b)
  "Determine if A is a more important package than B.

Return t if package type of 'a' is more important than the
package type of b, where:

- nil > nil
- built-in > nil, built-in
- site-lisp > nil, built-in, site-lisp
- user > nil, built-in, site-lisp
- package > nil, built-in, site-lisp, user

Noting that the first three are more important than themselves.
This is due to long chains of nil/built-in/site-lisp packages in
every backtrace, where typically the earliest one is the one that
started the chain.

On the other hand, for packages, we really want to focus on the
very last function that was responsible for triggering the rest
of the Emacs internal activity."
  (cond
   ;; nil only greater than nil
   ((null a) (member b (list nil)))
   ;; built-in more important than nil, and itself
   ((eq 'built-in a) (member b (list nil 'built-in)))
   ;; site-lisp more important than nil, built-in, and itself
   ((eq 'site-lisp a) (member b (list nil 'built-in 'site-lisp)))
   ;; user more important than earlier, but not more important
   ;; than itself.
   ((eq 'user a) (member b (list nil 'site-lisp 'built-in)))
   ;; installed package is most important, traversal stops here.
   ((symbolp a) (member b (list nil 'site-lisp 'built-in 'user)))
   ;; anything else is unknown
   (t nil)))


(defun snitch--responsible-caller (backtrace)
  "Determine entry in backtrace responsible for the event.

Return a single entry from BACKTRACE which is snitch’s best guess
for which function on the stack frame should be considered
’responsible’ for causing this event.  snitch uses this to assign
one single function/file/package as the responsible party for an
event, for use in filtering.

This is inherently fallible, based on prioritizing certain
function types and locations over others with some very primitive
heuristics.  It is, however, deterministic."
  (cl-loop for caller in backtrace with result = nil
           when (and (snitch--package-type-more-important
                      (nth 2 caller)
                      (if (null result) nil
                        (nth 2 (car result))))
                     ;; as a special case, ignore functions in
                     ;; startup.el since it doesn't really make sense
                     ;; for them to be the resposible caller
                     (not (and (eq (nth 2 caller) 'site-lisp)
                               (string-suffix-p "/startup.el" (nth 1 caller)))))
           do
           (push caller result)
           finally return (car result)))

(provide 'snitch-backtrace)

;;; snitch-backtrace.el ends here
