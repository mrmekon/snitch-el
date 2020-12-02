;;; snitch-backtrace.el                    -*- lexical-binding: t; -*-
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

;; find all directories in elisp load path that are NOT in the user dir
;; returns a list of strings
(defun snitch--site-lisp-dirs ()
  (let ((user-dir (expand-file-name package-user-dir)))
    (cl-loop for dir in (elisp-load-path-roots)
             unless (or (string-prefix-p user-dir dir)
                        (string-prefix-p package-user-dir dir))
             collect dir)))

;; find the 'root' directories of (site-lisp-dirs), which is hopefully
;; a list of all of the system-wide base dirs that contain elisp
;; returns a list of strings
(defun snitch--site-lisp-roots ()
  (cl-loop for dir in (snitch--site-lisp-dirs)
           if (or (string-equal "lisp" (file-name-base dir))
                  (string-equal "site-lisp" (file-name-base dir)))
           collect dir))

;; check if a directory is a subdirectory of a system-wide elisp dir
;; returns a boolean
(defun snitch--dir-in-site-lisp (dir)
  (not (null (cl-loop for site-dir in (snitch--site-lisp-roots)
                      if (string-prefix-p site-dir dir)
                      collect site-dir))))

;; check if a directory belongs to a package tracked by the package manager.
;; if so, returns its name as a symbol
(defun snitch--package-from-dir (dir)
  (nth 0
       (cl-loop for (pkgname . pkgdesc) in (package--alist)
                if (string-equal
                    (file-name-as-directory dir)
                    (file-name-as-directory (package-desc-dir (car pkgdesc))))
                collect pkgname)))

;; try to guess a package name for a full path to a file.  returns a symbol,
;; which is either an installed package name, or one of the three fixed values:
;;  - 'built-in, if registered as a built-in package
;;  - 'site-lisp, if found in a system-wide elisp directory
;;  - 'user, if its source is unknown
(defun snitch--package-from-path (path)
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

(defun snitch--backtrace ()
  (setq stack '())
  (let ((frames (backtrace-get-frames)))
    (dotimes (idx (length frames))
      (if (> idx 3) ; skip frames in snitch
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
                 (path (find-lisp-object-file-name fun 'defun))
                 (file (if path (file-name-base path) nil))
                 (dir (if path (file-name-directory path) nil))
                 (package (if path (snitch--package-from-path path) nil)))
            ;;(message "frame %d: %s (%s) [%s]" idx fun path package)
            (add-to-list 'stack (list clean-fun path package))))))
  (reverse stack))

;; return true of package type 'a' is "more important", i.e. more likely
;; to be the package responsible for a request.  Used to traverse a
;; backtrace looking for the "most important" function -- the most recent
;; function that should be considered the triggering cause.
(defun snitch--package-type-more-important (a b)
  (cond
   ;; nil only greater than nil
   ((null a) (member b (list nil)))
   ;; site-lisp more important than nil and itself
   ((eq 'site-lisp a) (member b (list nil 'site-lisp)))
   ;; built-in more important than nil, site-lisp, and itself
   ((eq 'built-in a) (member b (list nil 'site-lisp 'built-in)))
   ;; user more important than earlier, but not more important
   ;; than itself.
   ((eq 'user a) (member b (list nil 'site-lisp 'built-in)))
   ;; installed package is most important, traversal stops here.
   ((symbolp a) (member b (list nil 'site-lisp 'built-in 'user)))
   ;; anything else is unknown
   (t nil)))


(defun snitch--responsible-caller (backtrace)
  (cl-loop for caller in backtrace with result = nil
           when (snitch--package-type-more-important
                 (nth 2 caller)
                 (if (null result) nil
                   (nth 2 (car result))))
           do
           (push caller result)
           finally return (car result)))

(provide 'snitch-backtrace)

;;; snitch-backtrace.el ends here
