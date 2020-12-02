#!/bin/bash
emacs -batch \
      --eval "(add-to-list 'load-path \"~/.emacs.d/snitch/\")" \
      --eval "(package-initialize)" \
      -l ert -l snitch-test.el \
      -f ert-run-tests-batch-and-exit
