Python scripts to generate rust code.

To use:

```text
$ python generate_sign_msg.py > sign_msg.rs
```

Then copy and paste code from sign_msg.rs into src/lib.rs to be compiled into
wasm.
