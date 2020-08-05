# How to build the project

```bash
$ wasm-pack build --target=web; python convert.py
```

This will create bls-standalone.html which you can double click to use the tool.

# Developers

Add new wasm functions to `src/lib.rs`.

These wasm functions can be called from javascript, usually by adding a function
to `html/js/index.js` under the `threshold_crypto wasm calls` section.

If you change the rust, you need to update the standalone html file:

```
$ wasm-pack build --target=web; python convert.py
```

If you only change the javascript or html or css, you can update the
standalone page without rebuilding the wasm library.

```
$ python convert.py
```

After every change you will need to rebuild the standalone html file.

Once generated, bls-standalone.html (in the root of the repo) can be double
clicked to open in your browser.
