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
  (when deinit
    (snitch-test--cleanup))
  (list snitch-network-policy
        snitch-network-blacklist
        snitch-network-whitelist
        snitch-process-policy
        snitch-process-blacklist
        snitch-process-whitelist))

(defun snitch-test--restore-vars (vars)
  (setq snitch-network-policy (nth 0 vars))
  (setq snitch-network-blacklist (nth 1 vars))
  (setq snitch-network-whitelist (nth 2 vars))
  (setq snitch-process-policy (nth 3 vars))
  (setq snitch-process-blacklist (nth 4 vars))
  (setq snitch-process-whitelist (nth 5 vars)))

(defun snitch-test--clear-vars (net-policy proc-policy &optional init)
  (setq snitch-network-policy net-policy)
  (setq snitch-network-blacklist '())
  (setq snitch-network-whitelist '())
  (setq snitch-process-policy proc-policy)
  (setq snitch-process-blacklist '())
  (setq snitch-process-whitelist '())
  (when init
    (snitch-init)))

(defun snitch-test--net-client (port expect-success)
  "Make a network request to a TCP port.  Assert t if allowed
through the firewall, nil if blocked.  Note that a refused
connection still returns t, as it was allowed to pass."
  (let ((res (condition-case nil
                 ;; returns nil if snitch blocks it, t if it makes a
                 ;; connection
                 (make-network-process :name "ert-test"
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

(defun snitch-test--cleanup ()
  (cl-loop for proc in (process-list)
           do (delete-process proc))
  (snitch-deinit))

(defun snitch-test--server (port)
  (make-network-process :name (format "ert-test-server-%s" port)
                        :server t
                        :host "127.0.0.1"
                        :service port
                        :family 'ipv4))


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
    ;; first frame: lambda
    (should (equal (nth 0 (nth 0 backtrace)) 'lambda))
    (should (equal (nth 1 (nth 0 backtrace)) nil))
    (should (equal (nth 2 (nth 0 backtrace)) nil))
    ;; second frame: ert--run-test-internal
    (should (equal (nth 0 (nth 1 backtrace)) #'ert--run-test-internal))
    (should (string-suffix-p "/emacs-lisp/ert.el" (nth 1 (nth 1 backtrace))))
    (should (equal (nth 2 (nth 1 backtrace)) 'built-in))
    ;; third frame: ert-run-test
    (should (equal (nth 0 (nth 2 backtrace)) #'ert-run-test))
    (should (string-suffix-p "/emacs-lisp/ert.el" (nth 1 (nth 2 backtrace))))
    (should (equal (nth 2 (nth 2 backtrace)) 'built-in))
    ;; fourth frame: ert-run-or-rerun-test
    (should (equal (nth 0 (nth 3 backtrace)) #'ert-run-or-rerun-test))
    (should (string-suffix-p "/emacs-lisp/ert.el" (nth 1 (nth 3 backtrace))))
    (should (equal (nth 2 (nth 3 backtrace)) 'built-in))
    ;; fifth frame: ert-run-tests
    (should (equal (nth 0 (nth 4 backtrace)) #'ert-run-tests))
    (should (string-suffix-p "/emacs-lisp/ert.el" (nth 1 (nth 4 backtrace))))
    (should (equal (nth 2 (nth 4 backtrace)) 'built-in))))

(defun deepen-backtrace ()
  (let ((lamb (lambda () (snitch--backtrace))))
    (funcall lamb)))

(ert-deftest snitch-test-backtrace-lambdas ()
  "Test that backtraces get appropriately deeper when lambdas and
functions are added to the call stack."
  (let* ((outer-backtrace (snitch--backtrace))
         (middle-backtrace (funcall (lambda () (snitch--backtrace))))
         (inner-backtrace (funcall (lambda () (deepen-backtrace))))
         (outer-frames (length outer-backtrace))
         (middle-frames (length middle-backtrace))
         (inner-frames (length inner-backtrace)))
    (should (> inner-frames middle-frames))
    (should (> middle-frames outer-frames))
    ;; verify middle backtrace adds a lambda+funcall
    (should (equal (nth 0 (nth 0 middle-backtrace)) #'funcall))
    (should (equal (nth 0 (nth 1 middle-backtrace)) #'let*))
    (should (equal (nth 0 (nth 2 middle-backtrace)) 'lambda))
    (should (equal (nth 0 (nth 3 middle-backtrace)) #'ert--run-test-internal))
    ;; verify inner backtrace adds a lambda+deepen+funcall
    (should (equal (nth 0 (nth 0 inner-backtrace)) #'funcall))
    (should (equal (nth 0 (nth 1 inner-backtrace)) #'let))
    (should (equal (nth 0 (nth 2 inner-backtrace)) #'deepen-backtrace))
    (should (equal (nth 0 (nth 3 inner-backtrace)) 'lambda))
    (should (equal (nth 0 (nth 4 inner-backtrace)) #'let*))
    (should (equal (nth 0 (nth 5 inner-backtrace)) #'ert--run-test-internal))))

(ert-deftest snitch-test-backtrace-timer ()
  "Test that backtraces show correct details when sourced from a
timer."
  (setq timer-bt nil)
  (run-with-timer 0 nil (lambda () (setq timer-bt (snitch--backtrace))))
  (while (null timer-bt) (sleep-for 0.1))
  (should (equal (nth 0 (nth 2 timer-bt)) #'timer-event-handler))
  (should (string-suffix-p "/emacs-lisp/timer.el" (nth 1 (nth 2 timer-bt))))
  (should (equal (nth 2 (nth 2 timer-bt)) 'site-lisp)))

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
  (should (equal (nth 0 (nth 3 bt)) #'use-package-only-one))
  (should (string-suffix-p "/use-package-core.el" (nth 1 (nth 3 bt))))
  ;; this is the important one
  (should (equal (nth 2 (nth 3 bt)) 'use-package)))

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
;; Test cases: firewall
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
;; Manual tests and notes and scratch area
;;
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun snitch--test-wrap-process ()
  (setq snitch-log-verbose nil)
  (make-process :name "poop" :command '("ls" "-l"))
  )

(defun snitch--test-wrap-network-process ()
  (make-network-process :name "netpoop" :host "blommorna.com" :service 443 :family 'ipv4)
  (url-retrieve "http://google.com" #'identity)
  (setq snitch--log-buffer-max-lines 5)
  )


(defun snitch--test-log-filter-buffer ()
  (snitch--run-log-filter-wizard (snitch-network-entry :src-path "/hello"))
  )
;;(snitch--test-log-filter-buffer)

(defun snitch--test-package-from-path ()
  (snitch--package-from-path "/home/trevor/.emacs.d/elpa/elfeed-20200910.239/elfeed.el")
  (snitch--package-from-path "/usr/share/emacs/27.1/lisp/simple.el")
  (snitch--package-from-path "/usr/share/emacs/27.1/lisp/emacs-lisp/backtrace.el.gz")
  (snitch--package-from-path "/home/trevor/.emacs.d/firewall_test.el"))

(defun snitch--test-backtrace()
  (snitch--backtrace))

;; (snitch--test-backtrace)

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
