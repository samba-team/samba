# Guidance for AI coding agents in the Samba tree

This is a condensed form of README.Coding.md, which remains the reference
for human readers.

## Formatting: git clang-format

Layout is defined by `.clang-format` in the tree root (tabs, 79 columns,
brace placement, parameter alignment / one parameter per line). Don't
hand-format or reflow; for every commit with C changes run

    git clang-format --diff <commit>^ <commit>

and fold the relevant hunks into that commit. Skip hunks that only reflow
large initializer tables (torture_ops[], PyMethodDef arrays, test data
tables); hand-format new table entries like their neighbours instead, and
say what was skipped. Don't reformat code the change doesn't touch.

## C rules clang-format can't check

- Booleans: `bool`/`true`/`false`; check bool results via
  `ok = f(...); if (!ok) {`, not `if (!f(...))`.
- Integers: `[u]int{8,16,32,64}_t`, printed with `PRIu32` etc. (not for
  `uid_t`/`gid_t`).
- `struct x { ... };`, no `typedef struct { ... } x_t;`.
- Every pointer declared `= NULL`, even when assigned right after; structs
  `= {}` (never `{0}`) or designated initializers.
- Always braces, also around single statements.
- No function calls as arguments, no assignment in conditions. Exceptions:
  iterator loops (`while ((opt = poptGetNextOpt(pc)) != -1)`), arguments
  to `DBG_*`.
- Error handling: early return, or `goto fail`/`goto done` as the single
  exit; once a function has a common exit, every failure path uses it.
  Don't nest the success path inside `if (ret == OK)`.
- No control-flow macros (`NT_STATUS_NOT_OK_RETURN` etc.) in new code;
  `CHECK_STATUS`-style macros in tests are fine.
- Logging: `DBG_ERR`/`DBG_WARNING`/`DBG_NOTICE`/`DBG_INFO`/`DBG_DEBUG`,
  not `DEBUG(n, (...))`.
- Comments: `/* */` only; blank line before a comment, none between the
  comment and the code it documents. One-liners `/* text */` with spaces
  inside; multi-line comments start with a bare `/*` line, every further
  line starts with an aligned ` * `, and `*/` sits on its own line.
- talloc: `TALLOC_FREE(p)`, not `talloc_free(p)` (except when its return
  value is used, or in `while (list) talloc_free(list)` loops whose
  destructor unlinks the head); `talloc_move()` instead of
  `talloc_steal()` when the source pointer isn't needed afterwards.
- Marshalling in new code: `PUSH_*`/`PULL_*` from `lib/util/bytearray.h`,
  not `SBVAL`/`IVAL`/... from byteorder.h. Leave merely reindented code
  alone.

Apply these rules to new and changed code only; don't restyle unrelated
code.

## Python

PEP8, compatible with Python 3.6.

## Tests

New SMB-level tests are preferably written in Python
(`python/samba/tests/libsmb*.py`), extending the
`samba.samba3.libsmb_samba_internal` bindings in
`source3/libsmb/pylibsmb.c` where needed. C torture tests
remain fine where Python would be awkward.
