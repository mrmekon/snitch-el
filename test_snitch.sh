#!/bin/bash
emacs -batch \
      --eval "(package-initialize)" \
      --eval "(setq load-path (seq-filter \
                (lambda (x) (not (string-match \"/snitch\" x))) load-path))" \
      --eval "(add-to-list 'load-path \"~/.emacs.d/snitch/\")" \
      --eval "(require 'snitch)" \
      --eval "(message \"Testing snitch version: %s\" (snitch-version))" \
      -l ert -l snitch-test.el \
      -f ert-run-tests-batch-and-exit
