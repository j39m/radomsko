# radomsko

... is a personal project not meant for general consumption.

Do _not_ use `radomsko`.

> **NOTE**: This project is free software, a personal project by j39m.
> However, Google LLC owns the copyright on this particular project.
> This does not impact your ability to use and to hack at this free
> software; I provide this notice only for attribution purposes.

## Memo: completion

There's some weird dynamic completion sourcing going on:

```none
__python_argcomplete_expand_tilde_by_ref executable
```

And it's not enough to complete on `_pass`; one also needs to create
a symlink (with the same name as the executable) to the `pass`
completion script. For me, that's
`/usr/share/bash-completion/completions/pass`.
