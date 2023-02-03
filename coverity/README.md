# Coverity Scan Modelling File

The `coverity_assert_model.c` is a file for
(Coverity Models)[https://scan.coverity.com/models]. You can find the
documentation for it
(here)[https://documentation.blackduck.com/bundle/coverity-docs/page/customizing_coverity/topics/models_primitives/c_models_primitives.html]

- A model file can't import any header files.
- Therefore only some built-in primitives like int, char and void are
  available but not NULL etc.
- Modeling doesn't need full structs and typedefs. Rudimentary structs
  and similar types are sufficient.
- An uninitialized local pointer is not an error. It signifies that the
  variable could be either NULL or have some data.

Coverity Scan doesn't pick up modifications automatically. The model file must
be uploaded by an admin.

## Testing the coverity_assert_model.c

Whenever you modify the `coverity_assert_model.c` please run:

```sh
make -C coverity
```

This will check if the file compiles with gcc.
