#!/bin/bash
nft list tables | grep -E '^table\s+(inet)\s+main.*' | awk '{print $3}' | xargs -I {} nft delete table inet {}
