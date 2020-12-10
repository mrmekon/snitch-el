#!/bin/bash
set -e

LINT_FILES='
  snitch.el
  snitch-backtrace.el
  snitch-custom.el
  snitch-filter.el
  snitch-log.el
  snitch-timer.el'

QUOTED_LINT_FILES=""
for file in ${LINT_FILES}; do
    QUOTED_LINT_FILES="$QUOTED_LINT_FILES \"$file\"";
done

#lint-compile:
#  @if [ -n "${LINT_COMPILE_FILES}" ]; then \
#    echo "# Run byte compilation on $(call split_with_commas,${MAKEL_LINT_COMPILE_FILES})…"; \
#    ${BATCH} \
#    --eval "(setq byte-compile-error-on-warn t)" \
#    $(if ${LINT_COMPILE_OPTIONS},${LINT_COMPILE_OPTIONS}) \
#    --funcall batch-byte-compile \
#    ${MAKEL_LINT_COMPILE_FILES}; \
#    fi

echo "byte-compiling..."
emacs -batch \
      --eval "(package-initialize)" \
      --eval "(setq load-path (seq-filter \
                (lambda (x) (not (string-match \"/snitch\" x))) load-path))" \
      --eval "(add-to-list 'load-path \"~/.emacs.d/snitch/\")" \
      --eval "(require 'snitch)" \
      --eval "(message \"Testing snitch version: %s\" (snitch-version))" \
      --eval "(setq byte-compile-error-on-warn t)" \
      --funcall batch-byte-compile \
      ${LINT_FILES}

echo "checkdoc..."
# Just print findings, don't exit on errors
emacs -batch \
      --eval "(mapcar #'checkdoc-file (list ${QUOTED_LINT_FILES}))"

echo "package-lint..."
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

echo "ert tests..."
emacs -batch \
      --eval "(package-initialize)" \
      --eval "(setq load-path (seq-filter \
                (lambda (x) (not (string-match \"/snitch\" x))) load-path))" \
      --eval "(add-to-list 'load-path \"~/.emacs.d/snitch/\")" \
      --eval "(require 'snitch)" \
      --eval "(message \"Testing snitch version: %s\" (snitch-version))" \
      -l ert -l snitch-test.el \
      -f ert-run-tests-batch-and-exit
