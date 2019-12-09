#!/usr/bin/env bash

###Read this before execute this script
###Make sure you have this script in the dir had .git

git checkout --orphan temp_branch

git add -A
git commit -am "delete history"

git branch -D master
git branch -m master

git push -f origin master
