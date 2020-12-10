#!/bin/bash
set -e

emacs -batch \
      --eval "(package-initialize)" \
      --eval "(setq load-path (seq-filter \
                (lambda (x) (not (string-match \"/snitch\" x))) load-path))" \
      --eval "(add-to-list 'load-path \"~/.emacs.d/snitch/\")" \
      --eval "(require 'snitch)" \
      --eval "(message \"Testing snitch version: %s\" (snitch-version))" \
      --eval "(setq package-lint-batch-fail-on-warnings nil)" \
      --eval "(setq package-lint-main-file \"snitch.el\")" \
      -L . \
      -f package-lint-batch-and-exit \
      snitch.el snitch-backtrace.el snitch-custom.el \
      snitch-filter.el snitch-log.el snitch-timer.el

emacs -batch \
      --eval "(package-initialize)" \
      --eval "(setq load-path (seq-filter \
                (lambda (x) (not (string-match \"/snitch\" x))) load-path))" \
      --eval "(add-to-list 'load-path \"~/.emacs.d/snitch/\")" \
      --eval "(require 'snitch)" \
      --eval "(message \"Testing snitch version: %s\" (snitch-version))" \
      -l ert -l snitch-test.el \
      -f ert-run-tests-batch-and-exit
