# larssh - an SSH server for micropython by LarsH

This is a small SSH server python implementation.

## License

Like micropython/micropython, this project is licensed under the MIT
License.

In addition it has the following non-legally binding clause:

> Lars likes beer. If you use this software for practical or educational
> purposes, like it and meet Lars at a bar/conference/similar; you are
> not legally bound (but happily encouraged) to offer Lars a beer. :)

## Goals

The goals of this project are

  - to implement a minimal SSH server that can run on micropython
  - to provide an easy-to-understand example of how SSH works

The ultimate goal is to provide the same functionality as
micropython/webrepl, with an SSH prompt and SFTP file transfer.

The project aims to reach these goals by

  - putting references to RFC-sections for all relevant code parts

## Anti-goals

It is *not* a goal of this project

  - to be fully compliant with all the MUST-clauses of the SSH
    specification.
  - to be general. Supporting a single algorithm is probably good
    enough.
