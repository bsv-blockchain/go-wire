# Common makefile commands & variables between projects
include .make/common.mk

# Common Golang makefile commands & variables between projects
include .make/go.mk

## Set default repository details if not provided
REPO_NAME  ?= go-wire
REPO_OWNER ?= bsv-blockchain
