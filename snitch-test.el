;;; snitch-test.el                         -*- lexical-binding: t; -*-
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
;; This file provides manual and automated test routines for
;; validating the functionality of snitch.el.
;;
;; The automated tests are best run from the command line using
;; something like this:
;;
;; $ emacs -batch \
;;         --eval "(add-to-list 'load-path \"~/.emacs.d/snitch/\")" \
;;         --eval "(package-initialize)" \
;;         -l ert -l snitch-test.el \
;;         -f ert-run-tests-batch-and-exit
;;
;; Replace the path to snitch with your own, or leave it out if snitch
;; is already installed as a package.
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
(require 'ert)
(require 'snitch)
(require 'use-package)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;;
;; Helper functions
;;
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun snitch-test--save-vars (&optional deinit)
  "save all snitch globals so they can be restored after a test"
  (when deinit
    (snitch-test--cleanup))
  (list snitch-network-policy
        snitch-network-blacklist
        snitch-network-whitelist
        snitch-process-policy
        snitch-process-blacklist
        snitch-process-whitelist
        snitch-log-policy
        snitch-log-verbose
        snitch-log-buffer-max-lines
        snitch-on-event-functions
        snitch-on-allow-functions
        snitch-on-block-functions
        snitch-on-whitelist-functions
        snitch-on-blacklist-functions
        snitch-log-functions))

(defun snitch-test--restore-vars (vars)
  "restore saved vars after a test"
  (setq snitch-network-policy (nth 0 vars))
  (setq snitch-network-blacklist (nth 1 vars))
  (setq snitch-network-whitelist (nth 2 vars))
  (setq snitch-process-policy (nth 3 vars))
  (setq snitch-process-blacklist (nth 4 vars))
  (setq snitch-process-whitelist (nth 5 vars))
  (setq snitch-log-policy (nth 6 vars))
  (setq snitch-log-verbose (nth 7 vars))
  (setq snitch-log-buffer-max-lines (nth 8 vars))
  (setq snitch-on-event-functions (nth 9 vars))
  (setq snitch-on-allow-functions (nth 10 vars))
  (setq snitch-on-block-functions (nth 11 vars))
  (setq snitch-on-whitelist-functions (nth 12 vars))
  (setq snitch-on-blacklist-functions (nth 13 vars))
  (setq snitch-log-functions (nth 14 vars)))

(defun snitch-test--clear-vars (net-policy proc-policy &optional init)
  "set global vars to known defaults for duration of a test"
  (setq snitch-network-policy net-policy)
  (setq snitch-network-blacklist '())
  (setq snitch-network-whitelist '())
  (setq snitch-process-policy proc-policy)
  (setq snitch-process-blacklist '())
  (setq snitch-process-whitelist '())
  (setq snitch-log-policy '())
  (setq snitch-log-verbose nil)
  (setq snitch-log-buffer-max-lines 1000)
  (setq snitch-on-event-functions '())
  (setq snitch-on-allow-functions '())
  (setq snitch-on-block-functions '())
  (setq snitch-on-whitelist-functions '())
  (setq snitch-on-blacklist-functions '())
  (setq snitch-log-functions '())
  (when init
    (snitch-mode +1)))

(defun snitch-test--cleanup ()
  "kill any spawned processes and restart snitch"
  (cl-loop for proc in (process-list)
           do (delete-process proc))
  (snitch-mode -1))

(defun snitch-test--server (port)
  "launch a TCP server to receive connections"
  (make-network-process :name (format "ert-test-server-%s" port)
                        :server t
                        :host "127.0.0.1"
                        :service port
                        :family 'ipv4))


(defun snitch-test--net-client (port expect-success)
  "Make a network request to a TCP port.  Assert t if allowed
through the firewall, nil if blocked.  Note that a refused
connection still returns t, as it was allowed to pass."
  (let ((res (condition-case nil
                 ;; returns nil if snitch blocks it, t if it makes a
                 ;; connection
                 (make-network-process :name "ert-test-net"
                                       :host "127.0.0.1"
                                       :service port
                                       :family 'ipv4)
               ;; error is success, because it means the connection
               ;; was allowed through the firewall and just failed to
               ;; reach a real host
               (error t))))
    (should (if expect-success res (null res)))))

(defun snitch-test--url-client (url expect-success)
  "Make a network request to a URL.  Assert t if allowed through
the firewall, nil if blocked.  Note that a refused connection
still returns t, as it was allowed to pass."
  ;; note: url-retrieve succeeds even if the server is not up, but
  ;; errors if snitch blocks it
  (let ((res (condition-case nil
                 (url-retrieve url #'identity)
               (error nil))))
  (should (if expect-success res (null res)))))

(defun snitch-test--process (exe expected-success)
  "Launch a processes EXE.  Assert that the firewall result
matches EXPECTED-SUCCESS: t if allowed through, nil if blocked."
  (let ((res (make-process :name "ert-test-proc" :command (list exe))))
    (should (if expected-success res (null res)))))

(defun snitch-test--clear-logs ()
  "clear the snitch log buffer"
  (with-current-buffer (get-buffer-create snitch--log-buffer-name)
    (setq buffer-read-only nil)
    (erase-buffer)
    (setq buffer-read-only t)))

(defun snitch-test--get-log-entry (line)
  "get a single line from the log buffer (non-verbose)"
  (with-current-buffer (get-buffer-create snitch--log-buffer-name)
    (let ((line-count (count-lines (point-min) (point-max))))
      (when (> line-count line)
        (goto-char (point-min))
        (forward-line line)
        (beginning-of-line)
        (let* ((line (thing-at-point 'line))
               (match (string-match "(\\([a-zA-Z]*\\)) -- #s(\\([a-zA-Z-]*\\)" line))
               (event (match-string-no-properties 1 line))
               (class (match-string-no-properties 2 line))
               (props (text-properties-at (point))))
          (list event class props))))))

(defun snitch-test--get-log-line-raw (line)
  "get a single line from the log buffer, unparsed"
  (with-current-buffer (get-buffer-create snitch--log-buffer-name)
    (let ((line-count (count-lines (point-min) (point-max))))
      (when (> line-count line)
        (goto-char (point-min))
        (forward-line line)
        (beginning-of-line)
        (thing-at-point 'line)))))

(defun snitch-test--log-lines ()
  "get the total number of lines in the snitch log buffer."
  (with-current-buffer (get-buffer-create snitch--log-buffer-name)
    (count-lines (point-min) (point-max))))

(defun snitch-test--get-verbose-log-entry ()
  "Get the first verbose log in the log buffer.  Only supports
first entry in log buffer."
  (with-current-buffer (get-buffer-create snitch--log-buffer-name)
    (goto-char (point-min))
    (forward-line 1)
    (let* ((start (point-min))
           (end (search-forward-regexp "^\\["))
           (line (replace-regexp-in-string "\n" "" (buffer-substring start (- end 1))))
           (match (string-match "(\\([a-zA-Z]*\\)) --(\\([a-zA-Z-]*\\)" line))
           (event (match-string-no-properties 1 line))
           (class (match-string-no-properties 2 line))
           (props (text-properties-at (point))))
      (list event class props))))

(defun snitch-test--proc-entry (exe)
  "create a dummy process event"
  (snitch-process-entry
   :src-fn #'identity
   :src-path "~/.emacs.d/dummy/dummy.el"
   :src-pkg 'use-package
   :proc-name "ert-test-net"
   :executable exe
   :args '()))

(defun snitch-test--net-entry (host)
  "create a dummy network event"
  (snitch-network-entry
   :src-fn #'identity
   :src-path "~/.emacs.d/dummy/dummy-net.el"
   :src-pkg 'use-package
   :proc-name "ert-test-proc"
   :host host
   :port 80
   :family 'ipv4))

(defun snitch-test--verify-mnemonic (plist)
  "verify that the fields of the mnemonic map match.  That is,
MNEMONIC-NAME equals NAME when the square brackets are removed,
and KEY is the character in the square brackets."
  (let ((key (plist-get plist 'key))
        (name (plist-get plist 'name))
        (mnem-name (plist-get plist 'mnemonic-name)))
    (and (string-match (format "\\[%s\\]" key) mnem-name)
         (string-equal name
                       (replace-regexp-in-string
                        "\\(\\[\\|\\]\\)" "" mnem-name)))))

(defun snitch-test--deepen-backtrace ()
  "call snitch--backtrace from a slightly deeper function stack."
  (let ((lamb (lambda () (snitch--backtrace))))
    (funcall lamb)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;;
;; Test cases: backtrace
;;
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(ert-deftest snitch-test-backtrace ()
  "Test that backtraces directly triggered by ert have the
correct most-recent frames."
  ;; Running from ert triggers a backtrace like this:
  ;;
  ;;((lambda nil nil)
  ;; (ert--run-test-internal "/../emacs/28.0.50/lisp/emacs-lisp/ert.el" built-in)
  ;; (ert-run-test "/../emacs/28.0.50/lisp/emacs-lisp/ert.el" built-in)
  ;; (ert-run-or-rerun-test "/../emacs/28.0.50/lisp/emacs-lisp/ert.el" built-in)
  ;; (ert-run-tests "/../emacs/28.0.50/lisp/emacs-lisp/ert.el" built-in)
  ;; (ert "/../emacs/28.0.50/lisp/emacs-lisp/ert.el" built-in)
  ;; ...)
  ;;
  ;; The total backtrace can be 15+ deep, and the remaining ones
  ;; depend on how ert was initiated.
  ;;

  (let* ((backtrace (snitch--backtrace))
         (frames (length backtrace)))
    (should (> frames 5))
    ;; second frame: ert--run-test-internal
    (should (equal (nth 0 (nth 0 backtrace)) #'ert--run-test-internal))
    (should (string-suffix-p "/emacs-lisp/ert.el" (nth 1 (nth 0 backtrace))))
    (should (equal (nth 2 (nth 0 backtrace)) 'built-in))
    ;; third frame: ert-run-test
    (should (equal (nth 0 (nth 1 backtrace)) #'ert-run-test))
    (should (string-suffix-p "/emacs-lisp/ert.el" (nth 1 (nth 1 backtrace))))
    (should (equal (nth 2 (nth 1 backtrace)) 'built-in))
    ;; fourth frame: ert-run-or-rerun-test
    (should (equal (nth 0 (nth 2 backtrace)) #'ert-run-or-rerun-test))
    (should (string-suffix-p "/emacs-lisp/ert.el" (nth 1 (nth 2 backtrace))))
    (should (equal (nth 2 (nth 2 backtrace)) 'built-in))
    ;; fifth frame: ert-run-tests
    (should (equal (nth 0 (nth 3 backtrace)) #'ert-run-tests))
    (should (string-suffix-p "/emacs-lisp/ert.el" (nth 1 (nth 3 backtrace))))
    (should (equal (nth 2 (nth 3 backtrace)) 'built-in))))

(ert-deftest snitch-test-backtrace-lambdas ()
  "Test that backtraces get appropriately deeper when lambdas and
functions are added to the call stack."
  (let* ((outer-backtrace (snitch--backtrace))
         (middle-backtrace (funcall (lambda () (snitch--backtrace))))
         (inner-backtrace (funcall (lambda () (snitch-test--deepen-backtrace))))
         (outer-frames (length outer-backtrace))
         (middle-frames (length middle-backtrace))
         (inner-frames (length inner-backtrace)))
    (should (> inner-frames middle-frames))
    (should (> middle-frames outer-frames))
    ;; verify middle backtrace adds a lambda+funcall
    (should (equal (nth 0 (nth 0 middle-backtrace)) #'let*))
    (should (equal (nth 0 (nth 1 middle-backtrace)) 'lambda))
    (should (equal (nth 0 (nth 2 middle-backtrace)) #'ert--run-test-internal))

    ;; verify inner backtrace adds a lambda+deepen+funcall
    (should (equal (nth 0 (nth 0 inner-backtrace)) #'let))
    (should (equal (nth 0 (nth 1 inner-backtrace)) #'snitch-test--deepen-backtrace))
    (should (equal (nth 0 (nth 2 inner-backtrace)) 'lambda))
    (should (equal (nth 0 (nth 3 inner-backtrace)) #'funcall))
    (should (equal (nth 0 (nth 4 inner-backtrace)) #'let*))
    (should (equal (nth 0 (nth 5 inner-backtrace)) 'lambda))
    (should (equal (nth 0 (nth 6 inner-backtrace)) #'ert--run-test-internal))))

(ert-deftest snitch-test-backtrace-timer ()
  "Test that backtraces show correct details when sourced from a
timer."
  (setq timer-bt nil)
  (run-with-timer 0 nil (lambda () (setq timer-bt (snitch--backtrace))))
  (while (null timer-bt) (sleep-for 0.1))
  (should (equal (nth 0 (nth 1 timer-bt)) #'timer-event-handler))
  (should (string-suffix-p "/emacs-lisp/timer.el" (nth 1 (nth 1 timer-bt))))
  (should (equal (nth 2 (nth 1 timer-bt)) 'site-lisp))
  ;; TODO: test timer expansion
  )

(ert-deftest snitch-test-backtrace-use-package ()
  "Test that backtraces show correct package source, in this case
by wrapping error and calling a function that triggers it, so
snitch--backtrace's caller originates in use-package."
  (setq bt nil)
  (let ((fn (lambda (&rest args) (setq bt (snitch--backtrace)))))
    (add-function :around (symbol-function 'error) fn)
    (use-package-only-one "label" '() #'identity)
    (while (null bt) (sleep-for 0.1))
    (remove-function (symbol-function 'error) fn))
  (should (equal (nth 0 (nth 2 bt)) #'use-package-only-one))
  (should (string-suffix-p "/use-package-core.el" (nth 1 (nth 2 bt))))
  ;; this is the important one
  (should (equal (nth 2 (nth 2 bt)) 'use-package)))

(ert-deftest snitch-test-package-type-importance ()
  "Test relative importance of package types."
  ;; nil > ?
  (should (not (null (snitch--package-type-more-important nil nil))))
  (should (null (snitch--package-type-more-important nil 'built-in)))
  (should (null (snitch--package-type-more-important nil 'site-lisp)))
  (should (null (snitch--package-type-more-important nil 'user)))
  (should (null (snitch--package-type-more-important nil 'use-package)))
  ;; built-in > ?
  (should (not (null (snitch--package-type-more-important 'built-in nil))))
  (should (not (null (snitch--package-type-more-important 'built-in 'built-in))))
  (should (null (snitch--package-type-more-important 'built-in 'site-lisp)))
  (should (null (snitch--package-type-more-important 'built-in 'user)))
  (should (null (snitch--package-type-more-important 'built-in 'use-package)))
  ;; site-lisp > ?
  (should (not (null (snitch--package-type-more-important 'site-lisp nil))))
  (should (not (null (snitch--package-type-more-important 'site-lisp 'built-in))))
  (should (not (null (snitch--package-type-more-important 'site-lisp 'site-lisp))))
  (should (null (snitch--package-type-more-important 'site-lisp 'user)))
  (should (null (snitch--package-type-more-important 'site-lisp 'use-package)))
  ;; user > ?
  (should (not (null (snitch--package-type-more-important 'user 'nil))))
  (should (not (null (snitch--package-type-more-important 'user 'built-in))))
  (should (not (null (snitch--package-type-more-important 'user 'site-lisp))))
  (should (null (snitch--package-type-more-important 'user 'user)))
  (should (null (snitch--package-type-more-important 'user 'use-package)))
  ;; package > ?
  (should (not (null (snitch--package-type-more-important 'use-package 'nil))))
  (should (not (null (snitch--package-type-more-important 'use-package 'built-in))))
  (should (not (null (snitch--package-type-more-important 'use-package 'site-lisp))))
  (should (not (null (snitch--package-type-more-important 'use-package 'user))))
  (should (null (snitch--package-type-more-important 'use-package 'use-package))))

(ert-deftest snitch-test-responsible-caller ()
  "Test that the correct item in the backtrace is marked as the
responsible caller."
  (let* ((caller (snitch--responsible-caller (snitch--backtrace)))
         (fn (nth 0 caller)))
    (should (or
             ;; ert called from command line
             (equal fn #'ert-run-tests-batch-and-exit)
             ;; ert called from within emacs
             (equal fn #'ert)
             ;; ert called from with emacs with helm installed
             (equal fn #'helm-M-x-execute-command)))))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;;
;; Test cases: network firewall
;;
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(ert-deftest snitch-test-network-default-deny ()
  "Test that network connections are denied when the default
policy is set to deny."
  (let ((orig-vars (snitch-test--save-vars t))
        (server1 (snitch-test--server 64221))
        (server2 (snitch-test--server 64222)))
    ;; set allow policy
    (snitch-test--clear-vars 'deny 'allow t)

    (snitch-test--net-client 64221 nil)
    (snitch-test--net-client 64222 nil)
    (snitch-test--net-client 7744 nil)
    (snitch-test--url-client "http://127.0.0.1" nil)
    (snitch-test--url-client "https://127.0.0.1" nil)
    (snitch-test--url-client "http://127.0.0.1:64221" nil)

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))


(ert-deftest snitch-test-network-default-allow ()
  "Test that network connections are permitted when the default
policy is set to allow."
  (let ((orig-vars (snitch-test--save-vars t))
        (server1 (snitch-test--server 64221))
        (server2 (snitch-test--server 64222)))
    ;; set allow policy
    (snitch-test--clear-vars 'allow 'allow t)

    (snitch-test--net-client 64221 t)
    (snitch-test--net-client 7711 t)
    (snitch-test--url-client "http://127.0.0.1" t)
    (snitch-test--url-client "https://127.0.0.1" t)

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))

(ert-deftest snitch-test-network-blacklist ()
  "Test that network connections are blocked when the policy is
allow but the event matches a blacklist filter."
  (let ((orig-vars (snitch-test--save-vars t))
        (server1 (snitch-test--server 64221))
        (server2 (snitch-test--server 64222)))
    ;; set allow policy
    (snitch-test--clear-vars 'allow 'allow t)

    ;; both should be allowed by default
    (snitch-test--net-client 64221 t)
    (snitch-test--net-client 64222 t)

    ;; add the second to the blacklist
    (setq snitch-network-blacklist
          '(((lambda (evt port) (eq (oref evt port) port)) . (64222))))

    ;; first allowed, second blacklisted
    (snitch-test--net-client 64221 t)
    (snitch-test--net-client 64222 nil)
    (snitch-test--url-client "http://127.0.0.1:64221" t)
    (snitch-test--url-client "http://127.0.0.1:64222" nil)

    ;;;; add both to the blacklist
    (add-to-list 'snitch-network-blacklist
                 (cons (lambda (evt port) (eq (oref evt port) port))
                       (list 64221)))
    ;; all blacklisted
    (snitch-test--net-client 64221 nil)
    (snitch-test--net-client 64222 nil)
    (snitch-test--url-client "http://127.0.0.1:64221" nil)
    (snitch-test--url-client "http://127.0.0.1:64222" nil)

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))

(ert-deftest snitch-test-network-whitelist ()
  "Test that network connections are allowed when the policy is
deny but the event matches a whitelist filter."
  (let ((orig-vars (snitch-test--save-vars t))
        (server1 (snitch-test--server 64221))
        (server2 (snitch-test--server 64222)))
    ;; set deny policy
    (snitch-test--clear-vars 'deny 'allow t)

    ;; both should be denied by default
    (snitch-test--net-client 64221 nil)
    (snitch-test--net-client 64222 nil)

    ;; add the second to the whitelist
    (setq snitch-network-whitelist
          '(((lambda (evt port) (eq (oref evt port) port)) . (64222))))

    ;; first denied, second whitelisted
    (snitch-test--net-client 64221 nil)
    (snitch-test--net-client 64222 t)
    (snitch-test--url-client "http://127.0.0.1:64221" nil)
    (snitch-test--url-client "http://127.0.0.1:64222" t)

    ;;;; add both to the whitelist
    (add-to-list 'snitch-network-whitelist
                 (cons (lambda (evt port) (eq (oref evt port) port))
                       (list 64221)))
    ;; all permitted
    (snitch-test--net-client 64221 t)
    (snitch-test--net-client 64222 t)
    (snitch-test--url-client "http://127.0.0.1:64221" t)
    (snitch-test--url-client "http://127.0.0.1:64222" t)

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;;
;; Test cases: process firewall
;;
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(ert-deftest snitch-test-process-default-deny ()
  "Test that subprocesses are denied when the default policy is
set to deny."
  (let ((orig-vars (snitch-test--save-vars t)))
    ;; set allow policy
    (snitch-test--clear-vars 'allow 'deny t)

    (snitch-test--process "ls" nil)

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))


(ert-deftest snitch-test-process-default-allow ()
  "Test that subprocesses are permitted when the default policy
is set to allow."
  (let ((orig-vars (snitch-test--save-vars t)))
    ;; set allow policy
    (snitch-test--clear-vars 'allow 'allow t)

    (snitch-test--process "ls" t)

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))

(ert-deftest snitch-test-process-blacklist ()
  "Test that subprocesses are blocked when the policy is allow
but the event matches a blacklist filter."
  (let ((orig-vars (snitch-test--save-vars t)))
    ;; set allow policy
    (snitch-test--clear-vars 'allow 'allow t)

    ;; both should be allowed by default
    (snitch-test--process "ls" t)
    (snitch-test--process "curl" t)

    ;; add the second to the blacklist
    (setq snitch-process-blacklist
          '(((lambda (evt exe)
               (string-equal (oref evt executable) exe)) . ("curl"))))

    ;; first allowed, second blacklisted
    (snitch-test--process "ls" t)
    (snitch-test--process "curl" nil)

    ;;;; add both to the blacklist
    (add-to-list 'snitch-process-blacklist
                 (cons (lambda (evt exe) (string-equal (oref evt executable) exe))
                       (list "ls")))
    ;; all blacklisted
    (snitch-test--process "ls" nil)
    (snitch-test--process "curl" nil)

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))

(ert-deftest snitch-test-process-whitelist ()
  "Test that subprocesses are allowed when the policy is deny but
the event matches a whitelist filter."
  (let ((orig-vars (snitch-test--save-vars t)))
    ;; set deny policy
    (snitch-test--clear-vars 'allow 'deny t)

    ;; both should be denied by default
    (snitch-test--process "ls" nil)
    (snitch-test--process "curl" nil)

    ;; add the second to the whitelist
    (setq snitch-process-whitelist
          '(((lambda (evt exe)
               (string-equal (oref evt executable) exe)) . ("curl"))))

    ;; first denied, second whitelisted
    (snitch-test--process "ls" nil)
    (snitch-test--process "curl" t)

    ;;;; add both to the whitelist
    (add-to-list 'snitch-process-whitelist
                 (cons (lambda (evt exe) (string-equal (oref evt executable) exe))
                       (list "ls")))
    ;; all whitelisted
    (snitch-test--process "ls" t)
    (snitch-test--process "curl" t)

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;;
;; Test cases: hooks
;;
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(ert-deftest snitch-test-hooks-on-event ()
  "Test that hooks are called upon receiving any event, and
returning nil from a hook immediately blocks the event."
  (setq hook1-var 0)
  (setq hook2-var 0)
  (setq types '())
  (let ((orig-vars (snitch-test--save-vars t))
        (hook1 (lambda (type event)
                 (add-to-list 'types type)
                 (setq hook1-var (+ hook1-var 1)) t))
        (hook2 (lambda (type event) (setq hook2-var (+ hook2-var 1)) t))
        (hook3 (lambda (type event) nil)))
    (snitch-test--clear-vars 'allow 'allow t)

    ;; verify hooks run, but don’t change decision
    (setq snitch-on-event-functions (list hook1 hook2))
    (snitch-test--url-client "http://127.0.0.1" t)
    (should (equal hook1-var 1))
    (should (equal hook2-var 1))
    (snitch-test--process "ls" t)
    (should (equal hook1-var 2))
    (should (equal hook2-var 2))

    ;; counter decision with final hook
    (setq snitch-on-event-functions (list hook1 hook2 hook3))
    (snitch-test--process "ls" nil)
    (should (equal hook1-var 3))
    (should (equal hook2-var 3))

    ;; short-circuit with early hook
    (setq snitch-on-event-functions (list hook3 hook1 hook2))
    (snitch-test--process "ls" nil)
    (should (equal hook1-var 3))
    (should (equal hook2-var 3))

    ;; verify hooks still run when denied
    (setq snitch-on-event-functions (list hook1 hook2))
    (setq snitch-process-policy 'deny)
    (snitch-test--process "ls" nil)
    (should (equal hook1-var 4))
    (should (equal hook2-var 4))

    (should (eq 1 (length types)))
    (should (memq 'event types))

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))

(ert-deftest snitch-test-hooks-on-allow ()
  "Test that hooks are called when snitch decides to allow an
event, and that returning nil from the hooks blocks the event."
  (setq hook1-var 0)
  (setq hook2-var 0)
  (setq types '())
  (let ((orig-vars (snitch-test--save-vars t))
        (hook1 (lambda (type event)
                 (add-to-list 'types type)
                 (setq hook1-var (+ hook1-var 1)) t))
        (hook2 (lambda (type event) (setq hook2-var (+ hook2-var 1)) t))
        (hook3 (lambda (type event) nil)))
    (snitch-test--clear-vars 'allow 'allow t)

    ;; Add to on-event as well, so it increments by 2 when allowed and
    ;; by 1 when denied.
    (setq snitch-on-event-functions (list hook1 hook2))

    ;; verify hooks run, but don’t change decision
    (setq snitch-on-allow-functions (list hook1 hook2))
    (snitch-test--url-client "http://127.0.0.1" t)
    (should (equal hook1-var 2))
    (should (equal hook2-var 2))
    (snitch-test--process "ls" t)
    (should (equal hook1-var 4))
    (should (equal hook2-var 4))

    ;; counter decision with final hook
    (setq snitch-on-allow-functions (list hook1 hook2 hook3))
    (snitch-test--process "ls" nil)
    (should (equal hook1-var 6))
    (should (equal hook2-var 6))

    ;; short-circuit with early hook
    (setq snitch-on-allow-functions (list hook3 hook1 hook2))
    (snitch-test--process "ls" nil)
    (should (equal hook1-var 7))
    (should (equal hook2-var 7))

    ;; verify hooks don’t run when snitch denies
    (setq snitch-on-allow-functions (list hook1 hook2))
    (setq snitch-process-policy 'deny)
    (snitch-test--process "ls" nil)
    (should (equal hook1-var 8))
    (should (equal hook2-var 8))

    (should (eq 2 (length types)))
    (should (memq 'event types))
    (should (memq 'allow types))

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))

(ert-deftest snitch-test-hooks-on-block ()
  "Test that hooks are called when snitch decides to block an
event, and that returning nil causes snitch to accept the event."
  (setq hook1-var 0)
  (setq hook2-var 0)
  (setq types '())
  (let ((orig-vars (snitch-test--save-vars t))
        (hook1 (lambda (type event)
                 (add-to-list 'types type)
                 (setq hook1-var (+ hook1-var 1)) t))
        (hook2 (lambda (type event) (setq hook2-var (+ hook2-var 1)) t))
        (hook3 (lambda (type event) nil)))
    (snitch-test--clear-vars 'deny 'deny t)

    ;; Add to on-event as well, so it increments by 2 unless a hook
    ;; blocks it.
    (setq snitch-on-event-functions (list hook1 hook2))

    ;; verify hooks run, but don’t change decision
    (setq snitch-on-block-functions (list hook1 hook2))
    (snitch-test--url-client "http://127.0.0.1" nil)
    (should (equal hook1-var 2))
    (should (equal hook2-var 2))
    (snitch-test--process "ls" nil)
    (should (equal hook1-var 4))
    (should (equal hook2-var 4))

    ;; counter decision with final hook
    (setq snitch-on-block-functions (list hook1 hook2 hook3))
    (snitch-test--process "ls" t)
    (should (equal hook1-var 6))
    (should (equal hook2-var 6))

    ;; short-circuit with early hook
    (setq snitch-on-block-functions (list hook3 hook1 hook2))
    (snitch-test--process "ls" t)
    (should (equal hook1-var 7))
    (should (equal hook2-var 7))

    ;; verify hooks don’t run when snitch allows
    (setq snitch-on-block-functions (list hook1 hook2))
    (setq snitch-process-policy 'allow)
    (snitch-test--process "ls" t)
    (should (equal hook1-var 8))
    (should (equal hook2-var 8))

    (should (eq 2 (length types)))
    (should (memq 'event types))
    (should (memq 'block types))

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))

(ert-deftest snitch-test-hooks-on-whitelist ()
  "Test that hooks are called when snitch accepts an event
because of a whitelist entry, and that returning nil causes
snitch to block it."
  (setq hook1-var 0)
  (setq hook2-var 0)
  (setq types '())
  (let ((orig-vars (snitch-test--save-vars t))
        (hook1 (lambda (type event)
                 (add-to-list 'types type)
                 (setq hook1-var (+ hook1-var 1)) t))
        (hook2 (lambda (type event) (setq hook2-var (+ hook2-var 1)) t))
        (hook3 (lambda (type event) nil)))
    (snitch-test--clear-vars 'deny 'deny t)

    ;; Add to on-event as well, so it increments by 2 unless a hook
    ;; blocks it.
    (setq snitch-on-event-functions (list hook1 hook2))

    ;; only whitelist ls process
    (setq snitch-process-whitelist
          '(((lambda (evt exe)
               (string-equal (oref evt executable) exe)) . ("ls"))))

    ;; verify hooks run, but don’t change decision
    (setq snitch-on-whitelist-functions (list hook1 hook2))
    (snitch-test--process "ls" t)
    (should (equal hook1-var 2))
    (should (equal hook2-var 2))
    (snitch-test--process "ls" t)
    (should (equal hook1-var 4))
    (should (equal hook2-var 4))

    ;; counter decision with final hook
    (setq snitch-on-whitelist-functions (list hook1 hook2 hook3))
    (snitch-test--process "ls" nil)
    (should (equal hook1-var 6))
    (should (equal hook2-var 6))

    ;; short-circuit with early hook
    (setq snitch-on-whitelist-functions (list hook3 hook1 hook2))
    (snitch-test--process "ls" nil)
    (should (equal hook1-var 7))
    (should (equal hook2-var 7))

    ;; verify hooks don’t run with a non-whitelisted exe
    (setq snitch-on-whitelist-functions (list hook1 hook2))
    (snitch-test--process "curl" nil)
    (should (equal hook1-var 8))
    (should (equal hook2-var 8))

    (should (eq 2 (length types)))
    (should (memq 'event types))
    (should (memq 'whitelist types))

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))

(ert-deftest snitch-test-hooks-on-blacklist ()
  "Test that hooks are called when snitch decides to block an
event because of the blacklist, and that returning nil causes
snitch to accept it."
  (setq hook1-var 0)
  (setq hook2-var 0)
  (setq types '())
  (let ((orig-vars (snitch-test--save-vars t))
        (hook1 (lambda (type event)
                 (add-to-list 'types type)
                 (setq hook1-var (+ hook1-var 1)) t))
        (hook2 (lambda (type event) (setq hook2-var (+ hook2-var 1)) t))
        (hook3 (lambda (type event) nil)))
    (snitch-test--clear-vars 'allow 'allow t)

    ;; Add to on-event as well, so it increments by 2 unless a hook
    ;; blocks it.
    (setq snitch-on-event-functions (list hook1 hook2))

    ;; only blacklist ls process
    (setq snitch-process-blacklist
          '(((lambda (evt exe)
               (string-equal (oref evt executable) exe)) . ("ls"))))

    ;; verify hooks run, but don’t change decision
    (setq snitch-on-blacklist-functions (list hook1 hook2))
    (snitch-test--process "ls" nil)
    (should (equal hook1-var 2))
    (should (equal hook2-var 2))
    (snitch-test--process "ls" nil)
    (should (equal hook1-var 4))
    (should (equal hook2-var 4))

    ;; counter decision with final hook
    (setq snitch-on-blacklist-functions (list hook1 hook2 hook3))
    (snitch-test--process "ls" t)
    (should (equal hook1-var 6))
    (should (equal hook2-var 6))

    ;; short-circuit with early hook
    (setq snitch-on-blacklist-functions (list hook3 hook1 hook2))
    (snitch-test--process "ls" t)
    (should (equal hook1-var 7))
    (should (equal hook2-var 7))

    ;; verify hooks don’t run with a non-blacklisted exe
    (setq snitch-on-blacklist-functions (list hook1 hook2))
    (snitch-test--process "curl" t)
    (should (equal hook1-var 8))
    (should (equal hook2-var 8))

    (should (eq 2 (length types)))
    (should (memq 'event types))
    (should (memq 'blacklist types))

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))

(ert-deftest snitch-test-log-hooks ()
  "Test that hooks are called when snitch emits a log message.
Tests passing, blocking, and modifying log messages."
  (setq hook1-var 0)
  (setq hook2-var 0)
  (let ((orig-vars (snitch-test--save-vars t))
        (hook1 (lambda (msg) (setq hook1-var (1+ hook1-var)) t))
        (hook2 (lambda (msg)
                 (setq hook2-var (1+ hook2-var))
                 (cond
                  ((equal (get-text-property 0 'snitch-executable msg) "curl")
                   "filtered out curl message\n")
                  ((equal (get-text-property 0 'snitch-executable msg) "ls")
                   nil)
                  (t t)))))
    (snitch-test--clear-vars 'allow 'allow t)
    (setq snitch-log-policy '(allowed))

    ;; All messages allowed
    (setq snitch-log-functions (list hook1))
    (snitch-test--clear-logs)

    (snitch-test--process "ls" t)
    (snitch-test--process "curl" t)
    (snitch-test--process "whoami" t)
    (should (eq hook1-var 3))
    (should (eq hook2-var 0))
    (should (eq (snitch-test--log-lines) 3))

    ;; Some messages filtered
    (setq snitch-log-functions (list hook1 hook2 hook1))
    (snitch-test--clear-logs)

    ;; hook1 run once (hook2 terminates)
    (snitch-test--process "ls" t)
    (should (eq hook1-var 4))
    (should (eq hook2-var 1))
    ;; ls blocked, nothing in log
    (should (eq (snitch-test--log-lines) 0))

    ;; hook1 run once (hook2 terminates)
    (snitch-test--process "curl" t)
    (should (eq hook1-var 5))
    (should (eq hook2-var 2))
    (should (eq (snitch-test--log-lines) 1))
    (should (string-match "filtered out curl"
                          (snitch-test--get-log-line-raw 0)))


    ;; hook1 run twice (hook2 passes)
    (snitch-test--process "whoami" t)
    (should (eq hook1-var 7))
    (should (eq hook2-var 3))
    (should (eq (snitch-test--log-lines) 2))

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;;
;; Test cases: logging
;;
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(ert-deftest snitch-test-log-policy-matcher ()
  "Test that the decisions on whether an event should be log
match the snitch-log-policy."
  (let ((orig-vars (snitch-test--save-vars t)))
    (snitch-test--clear-vars 'allow 'allow t)

    (setq snitch-log-policy '(all))
    (should (snitch--log-policy-match '(all)))
    (should (snitch--log-policy-match '(whitelisted)))
    (should (snitch--log-policy-match '(network-whitelisted)))
    (should (snitch--log-policy-match '(process-whitelisted)))
    (should (snitch--log-policy-match '(blacklisted)))
    (should (snitch--log-policy-match '(network-blacklisted)))
    (should (snitch--log-policy-match '(process-blacklisted)))
    (should (snitch--log-policy-match '(allowed)))
    (should (snitch--log-policy-match '(network-allowed)))
    (should (snitch--log-policy-match '(process-allowed)))
    (should (snitch--log-policy-match '(blocked)))
    (should (snitch--log-policy-match '(network-blocked)))
    (should (snitch--log-policy-match '(process-blocked)))

    (setq snitch-log-policy '(blacklisted))
    (should (null (snitch--log-policy-match '(all))))
    (should (null (snitch--log-policy-match '(whitelisted))))
    (should (null (snitch--log-policy-match '(network-whitelisted))))
    (should (null (snitch--log-policy-match '(process-whitelisted))))
    (should (snitch--log-policy-match '(blacklisted)))
    (should (snitch--log-policy-match '(network-blacklisted)))
    (should (snitch--log-policy-match '(process-blacklisted)))
    (should (snitch--log-policy-match '(blacklisted whitelisted)))
    (should (null (snitch--log-policy-match '(allowed))))
    (should (null (snitch--log-policy-match '(network-allowed))))
    (should (null (snitch--log-policy-match '(process-allowed))))
    (should (null (snitch--log-policy-match '(blocked))))
    (should (null (snitch--log-policy-match '(network-blocked))))
    (should (null (snitch--log-policy-match '(process-blocked))))

    (setq snitch-log-policy '(whitelisted))
    (should (snitch--log-policy-match '(whitelisted)))
    (should (snitch--log-policy-match '(network-whitelisted)))
    (should (snitch--log-policy-match '(process-whitelisted)))
    (should (snitch--log-policy-match '(blacklisted whitelisted)))
    (should (null (snitch--log-policy-match '(blacklisted))))
    (should (null (snitch--log-policy-match '(network-blacklisted))))
    (should (null (snitch--log-policy-match '(process-blacklisted))))
    (should (null (snitch--log-policy-match '(allowed))))
    (should (null (snitch--log-policy-match '(blocked))))

    (setq snitch-log-policy '(allowed))
    (should (snitch--log-policy-match '(network-allowed)))

    (setq snitch-log-policy '(whitelisted allowed))
    (should (snitch--log-policy-match '(whitelisted)))
    (should (snitch--log-policy-match '(network-whitelisted)))
    (should (snitch--log-policy-match '(process-whitelisted)))
    (should (snitch--log-policy-match '(whitelisted blacklisted)))
    (should (null (snitch--log-policy-match '(blacklisted))))
    (should (null (snitch--log-policy-match '(network-blacklisted))))
    (should (null (snitch--log-policy-match '(process-blacklisted))))
    (should (snitch--log-policy-match '(allowed)))
    (should (snitch--log-policy-match '(network-allowed)))
    (should (snitch--log-policy-match '(process-allowed)))
    (should (snitch--log-policy-match '(allowed whitelisted)))
    (should (snitch--log-policy-match '(allowed whitelisted blacklisted)))
    (should (null (snitch--log-policy-match '(blocked))))
    (should (null (snitch--log-policy-match '(blocked blacklisted))))

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))

(ert-deftest snitch-test-log-all ()
  "Test that the right log events are received when logging all
events."
  (let ((orig-vars (snitch-test--save-vars t)))
    (snitch-test--clear-vars 'allow 'deny t)

    (setq snitch-log-policy '(all))

    (snitch-test--clear-logs)
    (snitch-test--url-client "http://127.0.0.1" t)

    ;; first line is the arrival
    (pcase-let ((`(,event ,class ,props) (snitch-test--get-log-entry 0)))
      (should (string-equal event "event"))
      (should (string-equal class "snitch-network-entry"))
      (should (string-equal (plist-get props 'snitch-host) "127.0.0.1")))
    ;; second line is the decision (allow)
    (pcase-let ((`(,event ,class ,props) (snitch-test--get-log-entry 1)))
      (should (string-equal event "allowed"))
      (should (string-equal class "snitch-network-entry"))
      (should (string-equal (plist-get props 'snitch-host) "127.0.0.1")))
    (should (null (snitch-test--get-log-entry 2)))

    (snitch-test--clear-logs)
    (snitch-test--process "ls" nil)
    ;; first line is the arrival
    (pcase-let ((`(,event ,class ,props) (snitch-test--get-log-entry 0)))
      (should (string-equal event "event"))
      (should (string-equal class "snitch-process-entry"))
      (should (string-equal (plist-get props 'snitch-executable) "ls")))
    ;; second line is the decision (blocked)
    (pcase-let ((`(,event ,class ,props) (snitch-test--get-log-entry 1)))
      (should (string-equal event "blocked"))
      (should (string-equal class "snitch-process-entry"))
      (should (string-equal (plist-get props 'snitch-executable) "ls")))
    (should (null (snitch-test--get-log-entry 2)))

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))

(ert-deftest snitch-test-log-allowed ()
  "Test that the right log events are received when logging only
allowed events."
  (let ((orig-vars (snitch-test--save-vars t)))
    (snitch-test--clear-vars 'allow 'allow t)

    (setq snitch-log-policy '(allowed))
    (snitch-test--clear-logs)
    (snitch-test--url-client "http://127.0.0.1" t)
    (pcase-let ((`(,event ,class ,props) (snitch-test--get-log-entry 0)))
      (should (string-equal event "allowed"))
      (should (string-equal class "snitch-network-entry"))
      (should (string-equal (plist-get props 'snitch-host) "127.0.0.1")))
    (should (null (snitch-test--get-log-entry 1)))

    (setq snitch-log-policy '(network-allowed))
    (snitch-test--clear-logs)
    (snitch-test--url-client "http://127.0.0.1" t)
    (pcase-let ((`(,event ,class ,props) (snitch-test--get-log-entry 0)))
      (should (string-equal event "allowed"))
      (should (string-equal class "snitch-network-entry"))
      (should (string-equal (plist-get props 'snitch-host) "127.0.0.1")))
    (should (null (snitch-test--get-log-entry 1)))

    (setq snitch-log-policy '(process-allowed))
    (snitch-test--clear-logs)
    (snitch-test--url-client "http://127.0.0.1" t)
    (should (null (snitch-test--get-log-entry 0)))

    (setq snitch-log-policy '(process-allowed))
    (snitch-test--clear-logs)
    (snitch-test--process "ls" t)
    (pcase-let ((`(,event ,class ,props) (snitch-test--get-log-entry 0)))
      (should (string-equal event "allowed"))
      (should (string-equal class "snitch-process-entry"))
      (should (string-equal (plist-get props 'snitch-executable) "ls")))
    (should (null (snitch-test--get-log-entry 1)))

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))

(ert-deftest snitch-test-log-blocked ()
  "Test that the right log events are received when logging only
blocked events."
  (let ((orig-vars (snitch-test--save-vars t)))
    (snitch-test--clear-vars 'deny 'deny t)

    (setq snitch-log-policy '(blocked))
    (snitch-test--clear-logs)
    (snitch-test--url-client "http://127.0.0.1" nil)
    (pcase-let ((`(,event ,class ,props) (snitch-test--get-log-entry 0)))
      (should (string-equal event "blocked"))
      (should (string-equal class "snitch-network-entry"))
      (should (string-equal (plist-get props 'snitch-host) "127.0.0.1")))
    (should (null (snitch-test--get-log-entry 1)))

    (setq snitch-log-policy '(network-blocked))
    (snitch-test--clear-logs)
    (snitch-test--url-client "http://127.0.0.1" nil)
    (pcase-let ((`(,event ,class ,props) (snitch-test--get-log-entry 0)))
      (should (string-equal event "blocked"))
      (should (string-equal class "snitch-network-entry"))
      (should (string-equal (plist-get props 'snitch-host) "127.0.0.1")))
    (should (null (snitch-test--get-log-entry 1)))

    (setq snitch-log-policy '(process-blocked))
    (snitch-test--clear-logs)
    (snitch-test--url-client "http://127.0.0.1" nil)
    (should (null (snitch-test--get-log-entry 0)))

    (setq snitch-log-policy '(process-blocked))
    (snitch-test--clear-logs)
    (snitch-test--process "ls" nil)
    (pcase-let ((`(,event ,class ,props) (snitch-test--get-log-entry 0)))
      (should (string-equal event "blocked"))
      (should (string-equal class "snitch-process-entry"))
      (should (string-equal (plist-get props 'snitch-executable) "ls")))
    (should (null (snitch-test--get-log-entry 1)))

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))

(ert-deftest snitch-test-log-whitelisted ()
  "Test that the right log events are received when logging only
whitelisted events."
  (let ((orig-vars (snitch-test--save-vars t)))
    (snitch-test--clear-vars 'deny 'deny t)

    (setq snitch-network-whitelist
          '(((lambda (evt host)
               (string-equal (oref evt host) host)) . ("127.0.0.1"))))
    (setq snitch-process-whitelist
          '(((lambda (evt exe)
               (string-equal (oref evt executable) exe)) . ("ls"))))

    (setq snitch-log-policy '(whitelisted))
    (snitch-test--clear-logs)
    (snitch-test--url-client "http://127.0.0.1" t)
    (pcase-let ((`(,event ,class ,props) (snitch-test--get-log-entry 0)))
      (should (string-equal event "whitelisted"))
      (should (string-equal class "snitch-network-entry"))
      (should (string-equal (plist-get props 'snitch-host) "127.0.0.1")))
    (should (null (snitch-test--get-log-entry 1)))

    (setq snitch-log-policy '(network-whitelisted))
    (snitch-test--clear-logs)
    (snitch-test--url-client "http://127.0.0.1" t)
    (pcase-let ((`(,event ,class ,props) (snitch-test--get-log-entry 0)))
      (should (string-equal event "whitelisted"))
      (should (string-equal class "snitch-network-entry"))
      (should (string-equal (plist-get props 'snitch-host) "127.0.0.1")))
    (should (null (snitch-test--get-log-entry 1)))

    (setq snitch-log-policy '(process-whitelisted))
    (snitch-test--clear-logs)
    (snitch-test--url-client "http://127.0.0.1" t)
    (should (null (snitch-test--get-log-entry 0)))

    (setq snitch-log-policy '(process-whitelisted))
    (snitch-test--clear-logs)
    (snitch-test--process "ls" t)
    (pcase-let ((`(,event ,class ,props) (snitch-test--get-log-entry 0)))
      (should (string-equal event "whitelisted"))
      (should (string-equal class "snitch-process-entry"))
      (should (string-equal (plist-get props 'snitch-executable) "ls")))
    (should (null (snitch-test--get-log-entry 1)))

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))

(ert-deftest snitch-test-log-blacklisted ()
  "Test that the right log events are received when logging only
blacklisted events."
  (let ((orig-vars (snitch-test--save-vars t)))
    (snitch-test--clear-vars 'allow 'allow t)

    (setq snitch-network-blacklist
          '(((lambda (evt host)
               (string-equal (oref evt host) host)) . ("127.0.0.1"))))
    (setq snitch-process-blacklist
          '(((lambda (evt exe)
               (string-equal (oref evt executable) exe)) . ("ls"))))

    (setq snitch-log-policy '(blacklisted))
    (snitch-test--clear-logs)
    (snitch-test--url-client "http://127.0.0.1" nil)
    (pcase-let ((`(,event ,class ,props) (snitch-test--get-log-entry 0)))
      (should (string-equal event "blacklisted"))
      (should (string-equal class "snitch-network-entry"))
      (should (string-equal (plist-get props 'snitch-host) "127.0.0.1")))
    (should (null (snitch-test--get-log-entry 1)))

    (setq snitch-log-policy '(network-blacklisted))
    (snitch-test--clear-logs)
    (snitch-test--url-client "http://127.0.0.1" nil)
    (pcase-let ((`(,event ,class ,props) (snitch-test--get-log-entry 0)))
      (should (string-equal event "blacklisted"))
      (should (string-equal class "snitch-network-entry"))
      (should (string-equal (plist-get props 'snitch-host) "127.0.0.1")))
    (should (null (snitch-test--get-log-entry 1)))

    (setq snitch-log-policy '(process-blacklisted))
    (snitch-test--clear-logs)
    (snitch-test--url-client "http://127.0.0.1" nil)
    (should (null (snitch-test--get-log-entry 0)))

    (setq snitch-log-policy '(process-blacklisted))
    (snitch-test--clear-logs)
    (snitch-test--process "ls" nil)
    (pcase-let ((`(,event ,class ,props) (snitch-test--get-log-entry 0)))
      (should (string-equal event "blacklisted"))
      (should (string-equal class "snitch-process-entry"))
      (should (string-equal (plist-get props 'snitch-executable) "ls")))
    (should (null (snitch-test--get-log-entry 1)))

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))

(ert-deftest snitch-test-log-prune ()
  "Test that the log buffer can be pruned to a limited side."
  (let ((orig-vars (snitch-test--save-vars t)))
    (snitch-test--clear-vars 'allow 'allow t)

    (setq snitch-log-policy '(all))
    (snitch-test--clear-logs)

    ;; make 40 logs (2 per connection)
    (dotimes (i 20)  (snitch-test--process "ls" t))
    (should (eq 40 (snitch-test--log-lines)))

    (setq snitch-log-buffer-max-lines 30)
    (snitch--prune-log-buffer)
    (should (eq 30 (snitch-test--log-lines)))

    (setq snitch-log-buffer-max-lines 10)
    (snitch--prune-log-buffer)
    (should (eq 10 (snitch-test--log-lines)))

    (setq snitch-log-buffer-max-lines 1)
    (snitch--prune-log-buffer)
    (should (eq 1 (snitch-test--log-lines)))

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))

(ert-deftest snitch-test-log-prune-timer ()
  "Test that the log pruning timer prunes the log correctly."
  (let ((orig-vars (snitch-test--save-vars t)))
    (snitch-test--clear-vars 'allow 'allow t)

    (setq snitch-log-policy '(all))
    (snitch-test--clear-logs)

    ;; make 10 logs (2 per connection)
    (dotimes (i 5)  (snitch-test--process "ls" t))
    (should (eq 10 (snitch-test--log-lines)))

    (setq snitch-log-buffer-max-lines 5)
    (snitch--start-log-prune-timer)
    (timer-set-idle-time snitch--log-prune-timer 0)
    (timer-activate snitch--log-prune-timer)
    (sleep-for 0.5)
    (should (eq 5 (snitch-test--log-lines)))
    (should (null snitch--log-prune-timer))

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))

(ert-deftest snitch-test-log-verbose ()
  "Test that the log buffer receives larger verbose logs when
snitch-log-verbose is t."
  (let ((orig-vars (snitch-test--save-vars t)))
    (snitch-test--clear-vars 'allow 'allow t)

    (setq snitch-log-policy '(all))
    (setq snitch-log-verbose t)
    (snitch-test--clear-logs)
    (snitch-test--process "ls" t)

    (pcase-let ((`(,event ,class ,props) (snitch-test--get-verbose-log-entry)))
      (should (string-equal event "event"))
      (should (string-equal class "snitch-process-entry"))
      (should (string-equal (plist-get props 'snitch-executable) "ls")))

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;;
;; Test cases: log filter UI
;;
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(ert-deftest snitch-test-log-filter-mnemonics ()
  "Test that the name/mnemonic name/key shortcut mappings all
match for every display line of the log filter UI."
  (let* ((proc-event (snitch-test--proc-entry "ls"))
         (net-event (snitch-test--net-entry "127.0.0.1"))
         (proc-map (snitch--log-filter-map proc-event))
         (net-map (snitch--log-filter-map net-event)))
    ;; common fields
    (should (snitch-test--verify-mnemonic (alist-get 'src-fn net-map)))
    (should (snitch-test--verify-mnemonic (alist-get 'src-fn proc-map)))
    (should (snitch-test--verify-mnemonic (alist-get 'src-path net-map)))
    (should (snitch-test--verify-mnemonic (alist-get 'src-path proc-map)))
    (should (snitch-test--verify-mnemonic (alist-get 'src-pkg net-map)))
    (should (snitch-test--verify-mnemonic (alist-get 'src-pkg proc-map)))
    (should (snitch-test--verify-mnemonic (alist-get 'proc-name net-map)))
    (should (snitch-test--verify-mnemonic (alist-get 'proc-name proc-map)))
    ;; net fields
    (should (snitch-test--verify-mnemonic (alist-get 'host net-map)))
    (should (snitch-test--verify-mnemonic (alist-get 'port net-map)))
    (should (snitch-test--verify-mnemonic (alist-get 'family net-map)))
    ;; proc fields
    (should (snitch-test--verify-mnemonic (alist-get 'executable proc-map)))
    (should (snitch-test--verify-mnemonic (alist-get 'args proc-map)))))

(ert-deftest snitch-test-log-filter-popup-hook ()
  "Test that the user hook is called when the log filter buffer
is shown or hidden."
  (setq hook1-var 0)
  (let ((orig-vars (snitch-test--save-vars t))
        (hook1 (lambda () (setq hook1-var (+ hook1-var 1)) t)))
    (snitch-test--clear-vars 'allow 'allow t)

    (setq snitch-log-filter-window-open-hook (list hook1))
    (setq snitch-log-filter-window-close-hook (list hook1))
    (snitch--init-log-filter-buffer)
    (snitch--show-log-filter-window)
    (should (equal 1 hook1-var))
    (snitch--hide-log-filter-window snitch--log-filter-buffer)
    (should (equal 2 hook1-var))

    ;; cleanup
    (snitch-test--restore-vars orig-vars)
    (snitch-test--cleanup)))




;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;;
;; Manual tests and notes and scratch area
;;
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun snitch--test-wrap-process ()
  (setq snitch-log-verbose nil)
  (make-process :name "poop" :command '("ls" "-l")))

(defun snitch--test-wrap-network-process ()
  (make-network-process :name "netpoop" :host "blommorna.com" :service 443 :family 'ipv4)
  (url-retrieve "http://google.com" #'identity)
  (setq snitch-log-buffer-max-lines 5))


(defun snitch--test-log-filter-buffer ()
  (snitch--run-log-filter-wizard (snitch-network-entry :src-path "/hello")))

(defun snitch--test-package-from-path ()
  (snitch--package-from-path "/home/trevor/.emacs.d/elpa/elfeed-20200910.239/elfeed.el")
  (snitch--package-from-path "/usr/share/emacs/27.1/lisp/simple.el")
  (snitch--package-from-path "/usr/share/emacs/27.1/lisp/emacs-lisp/backtrace.el.gz")
  (snitch--package-from-path "/home/trevor/.emacs.d/firewall_test.el"))

(defun snitch--test-backtrace()
  (snitch--backtrace))

(defun snitch--test-responsible-caller ()
  (message "\n\n\nbacktrace:\n%s" (snitch--backtrace))
  (snitch--responsible-caller (snitch--backtrace)))


;; (let* ((frames (backtrace-frames))
;;        (elt (nth 0 frames)))
;;   (backtrace-print-to-string elt))


;; (car (snitch--test-backtrace))
;; (subrp 'make-network-process)
;; (subrp 'let)
;; (subrp 'backtrace)
;; (commandp 'let)
;; (symbolp 'let)
;; (subr-arity (symbol-function 'let))
;; (commandp 'progn)
;; (package-built-in-p 'backtrace)
;; (memq 'simple package-activated-list)
;; (package-installed-p 'simple)
;; (featurep 'simple)
;; (elisp-load-path-roots)
;; (site-lisp-dirs)
;; (site-lisp-roots)
;; (dir-in-site-lisp "/usr/share/emacs/27.1/lisp/blah")


;; ;; check if package is loaded
;; (memq 'elfeed package-activated-list)
;; ;; check if package is built-in
;; (package-built-in-p 'package)
;; ;; list all available packages
;; (package--alist)
;; ;; get pkg-desc (tuple) for an installed package
;; (alist-get 'elfeed (package--alist))
;; ;; get directory of installed package
;; (package-desc-dir (car (cdr (assoc 'elfeed (package--alist)))))
;;
;; ;; return package-desc of current buffer.  can navigate to buffer
;; ;; in stack trace and call this?
;; (package-buffer-info)
;; ;; same as above, but for the whole dir open in dired-mode
;; (pcakage-dir-info)
;; (symbol-file 'elfeed)
;; (featurep 'elfeed)
;; (symbol-name 'elfeed)
;; (package--list-loaded-files "/home/trevor/.emacs.d/elpa/elfeed-20200910.239")
;; (file-name-directory "/home/trevor/.emacs.d/elpa/elfeed-20200910.239/elfeed.elc")
;; (backtrace-frame 7)
;; (backtrace-get-frames)

;;; snitch-test.el ends here
