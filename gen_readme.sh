#!/bin/bash
echo "\`\`\`" > README.md
cat snitch.el \
    | awk 'f&&f++&&f>2;/^;;; Commentary/{f=1};/^;;; Code/{f=0}' \
    | sed \$d \
    | sed 's/^;;[ ]\?//' \
          >> README.md
echo "\`\`\`" >> README.md
