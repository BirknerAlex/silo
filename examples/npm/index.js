#!/usr/bin/env node
// Scoped on purpose: `@silo-example/hello` puts a slash inside what npm
// treats as one path segment, which is the case silo's npm route has to
// handle and the one most likely to break.
console.log("hello from silo npm 1.2.3");
