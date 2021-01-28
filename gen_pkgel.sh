#!/bin/bash
set -eux

cat <<EOF > snitch-pkg.el
(define-package
  "snitch"
  "0.3.0"
  "A firewall for emacs."
  '((emacs "27.1")))
EOF
