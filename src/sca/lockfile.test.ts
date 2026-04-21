import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { extractPackagesFromDiff } from './lockfile.js';

describe('extractPackagesFromDiff', () => {
  it('returns empty array for empty diff', () => {
    const result = extractPackagesFromDiff('');
    assert.deepEqual(result, []);
  });

  it('returns empty array for diff with no lockfile changes', () => {
    const diff = `diff --git a/src/index.ts b/src/index.ts
index abc123..def456 100644
--- a/src/index.ts
+++ b/src/index.ts
@@ -1,5 +1,5 @@
 console.log('hello');
-const x = 1;
+const x = 2;
`;
    const result = extractPackagesFromDiff(diff);
    assert.deepEqual(result, []);
  });

  describe('npm package-lock.json', () => {
    it('extracts packages from package-lock.json diff', () => {
      const diff = `diff --git a/package-lock.json b/package-lock.json
index abc123..def456 100644
--- a/package-lock.json
+++ b/package-lock.json
@@ -1,20 +1,20 @@
 {
   "dependencies": {
     "lodash": {
+      "version": "4.17.21",
       "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
     },
     "express": {
+      "version": "4.18.2",
       "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
     }
   }
 }
`;
      const result = extractPackagesFromDiff(diff);
      assert.deepEqual(
        result.sort((a, b) => a.name.localeCompare(b.name)),
        [
          { name: 'express', version: '4.18.2', ecosystem: 'npm' },
          { name: 'lodash', version: '4.17.21', ecosystem: 'npm' },
        ]
      );
    });

    it('ignores removed lines in package-lock.json', () => {
      const diff = `diff --git a/package-lock.json b/package-lock.json
index abc123..def456 100644
--- a/package-lock.json
+++ b/package-lock.json
@@ -1,10 +1,10 @@
 {
   "dependencies": {
     "lodash": {
-      "version": "4.17.20",
+      "version": "4.17.21",
       "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
     }
   }
 }
`;
      const result = extractPackagesFromDiff(diff);
      // Should only include the added version
      assert.equal(result.length, 1);
      assert.equal(result[0].version, '4.17.21');
    });
  });

  describe('yarn.lock', () => {
    it('extracts packages from yarn.lock diff', () => {
      const diff = `diff --git a/yarn.lock b/yarn.lock
index abc123..def456 100644
--- a/yarn.lock
+++ b/yarn.lock
@@ -1,10 +1,10 @@
 # yarn lockfile v1
+"lodash@4.17.21":
+  version "4.17.21"
   resolved "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"

+"express@4.18.2":
+  version "4.18.2"
   resolved "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
`;
      const result = extractPackagesFromDiff(diff);
      assert.deepEqual(
        result.sort((a, b) => a.name.localeCompare(b.name)),
        [
          { name: 'express', version: '4.18.2', ecosystem: 'npm' },
          { name: 'lodash', version: '4.17.21', ecosystem: 'npm' },
        ]
      );
    });

    it('parses yarn.lock with version specifiers', () => {
      const diff = `diff --git a/yarn.lock b/yarn.lock
index abc123..def456 100644
--- a/yarn.lock
+++ b/yarn.lock
@@ -1,5 +1,5 @@
 # yarn lockfile v1
+"react@^18.0.0":
+  version "18.2.0"
   resolved "https://registry.npmjs.org/react/-/react-18.2.0.tgz"
`;
      const result = extractPackagesFromDiff(diff);
      assert.equal(result.length, 1);
      assert.equal(result[0].name, 'react');
      assert.equal(result[0].version, '^18.0.0');
    });
  });

  describe('pnpm-lock.yaml', () => {
    it('extracts packages from pnpm-lock.yaml diff', () => {
      const diff = `diff --git a/pnpm-lock.yaml b/pnpm-lock.yaml
index abc123..def456 100644
--- a/pnpm-lock.yaml
+++ b/pnpm-lock.yaml
@@ -1,10 +1,10 @@
 lockfileVersion: 5.4

 dependencies:
+  lodash: 4.17.21
+  express: 4.18.2

 devDependencies: {}

+/lodash@4.17.21:
+  resolution: {integrity: 'sha512...'}
+/express@4.18.2:
+  resolution: {integrity: 'sha512...'}
`;
      const result = extractPackagesFromDiff(diff);
      assert.ok(result.length > 0);
      const names = result.map(p => p.name);
      assert.ok(names.includes('lodash') || names.includes('express'));
    });
  });

  describe('Pipfile.lock (Python)', () => {
    it('extracts packages from Pipfile.lock diff', () => {
      const diff = `diff --git a/Pipfile.lock b/Pipfile.lock
index abc123..def456 100644
--- a/Pipfile.lock
+++ b/Pipfile.lock
@@ -1,25 +1,25 @@
 {
     "default": {
         "requests": {
+            "version": "==2.31.0",
             "hashes": []
         },
         "flask": {
+            "version": "==2.3.0",
             "hashes": []
         }
     }
 }
`;
      const result = extractPackagesFromDiff(diff);
      assert.deepEqual(
        result.sort((a, b) => a.name.localeCompare(b.name)),
        [
          { name: 'flask', version: '2.3.0', ecosystem: 'PyPI' },
          { name: 'requests', version: '2.31.0', ecosystem: 'PyPI' },
        ]
      );
    });

    it('strips version specifiers from Pipfile.lock', () => {
      const diff = `diff --git a/Pipfile.lock b/Pipfile.lock
index abc123..def456 100644
--- a/Pipfile.lock
+++ b/Pipfile.lock
@@ -1,10 +1,10 @@
 {
     "default": {
         "requests": {
+            "version": ">=2.28.0,<3.0.0",
             "hashes": []
         }
     }
 }
`;
      const result = extractPackagesFromDiff(diff);
      assert.equal(result.length, 1);
      assert.equal(result[0].version, '2.28.0,<3.0.0');
    });
  });

  describe('poetry.lock', () => {
    it('extracts packages from poetry.lock diff', () => {
      const diff = `diff --git a/poetry.lock b/poetry.lock
index abc123..def456 100644
--- a/poetry.lock
+++ b/poetry.lock
@@ -1,18 +1,18 @@
 # This file is automatically generated by Poetry

+[[package]]
+name = "requests"
+version = "2.31.0"
 description = "Python HTTP for Humans."

+[[package]]
+name = "flask"
+version = "2.3.0"
 description = "A simple framework for building web applications."
`;
      const result = extractPackagesFromDiff(diff);
      assert.deepEqual(
        result.sort((a, b) => a.name.localeCompare(b.name)),
        [
          { name: 'flask', version: '2.3.0', ecosystem: 'PyPI' },
          { name: 'requests', version: '2.31.0', ecosystem: 'PyPI' },
        ]
      );
    });
  });

  describe('go.sum', () => {
    it('extracts packages from go.sum diff', () => {
      const diff = `diff --git a/go.sum b/go.sum
index abc123..def456 100644
--- a/go.sum
+++ b/go.sum
@@ -1,5 +1,5 @@
+github.com/sirupsen/logrus v1.8.1 h1:dJKuHgqk91NevLj9IlNjPqMd+QH+9/3/ngvjvxdgrQ=
+github.com/sirupsen/logrus v1.8.1/go.mod h1:yWOB1SBYC5IA1ByLk2k8Ps1/VkKCVh3D+BQzEeT8o=
 other stuff
+github.com/stretchr/testify v1.7.0 h1:nwc3DEeHmmLAfoZucVR881uASk0Mfjw8xYiL9AKAYI=
`;
      const result = extractPackagesFromDiff(diff);
      assert.deepEqual(
        result.sort((a, b) => a.name.localeCompare(b.name)),
        [
          { name: 'github.com/sirupsen/logrus', version: 'v1.8.1', ecosystem: 'Go' },
          { name: 'github.com/stretchr/testify', version: 'v1.7.0', ecosystem: 'Go' },
        ]
      );
    });

    it('deduplicates go.sum entries (regular and /go.mod)', () => {
      const diff = `diff --git a/go.sum b/go.sum
index abc123..def456 100644
--- a/go.sum
+++ b/go.sum
+github.com/sirupsen/logrus v1.8.1 h1:dJKuHgqk91NevLj9IlNjPqMd+QH+9/3/ngvjvxdgrQ=
+github.com/sirupsen/logrus v1.8.1/go.mod h1:yWOB1SBYC5IA1ByLk2k8Ps1/VkKCVh3D+BQzEeT8o=
`;
      const result = extractPackagesFromDiff(diff);
      // Should only have one entry for logrus
      assert.equal(result.length, 1);
      assert.equal(result[0].name, 'github.com/sirupsen/logrus');
      assert.equal(result[0].version, 'v1.8.1');
    });
  });

  describe('Cargo.lock', () => {
    it('extracts packages from Cargo.lock diff', () => {
      const diff = `diff --git a/Cargo.lock b/Cargo.lock
index abc123..def456 100644
--- a/Cargo.lock
+++ b/Cargo.lock
@@ -1,18 +1,18 @@
 # This file is automatically generated by Cargo

+[[package]]
+name = "serde"
+version = "1.0.163"
 source = "registry+https://github.com/rust-lang/crates.io-index"

+[[package]]
+name = "tokio"
+version = "1.27.0"
 source = "registry+https://github.com/rust-lang/crates.io-index"
`;
      const result = extractPackagesFromDiff(diff);
      assert.deepEqual(
        result.sort((a, b) => a.name.localeCompare(b.name)),
        [
          { name: 'serde', version: '1.0.163', ecosystem: 'Cargo' },
          { name: 'tokio', version: '1.27.0', ecosystem: 'Cargo' },
        ]
      );
    });
  });

  describe('Gemfile.lock (Ruby)', () => {
    it('extracts packages from Gemfile.lock diff', () => {
      const diff = `diff --git a/Gemfile.lock b/Gemfile.lock
index abc123..def456 100644
--- a/Gemfile.lock
+++ b/Gemfile.lock
@@ -1,30 +1,30 @@
 GEM
   remote: https://rubygems.org/
   specs:
+    rails (7.0.0)
+      actioncable (= 7.0.0)
+    bundler (2.3.0)
+    rake (13.0.0)

 PLATFORMS
   ruby
`;
      const result = extractPackagesFromDiff(diff);
      assert.deepEqual(
        result.sort((a, b) => a.name.localeCompare(b.name)),
        [
          { name: 'bundler', version: '2.3.0', ecosystem: 'RubyGems' },
          { name: 'rails', version: '7.0.0', ecosystem: 'RubyGems' },
          { name: 'rake', version: '13.0.0', ecosystem: 'RubyGems' },
        ]
      );
    });

    it('filters out metadata sections in Gemfile.lock', () => {
      const diff = `diff --git a/Gemfile.lock b/Gemfile.lock
index abc123..def456 100644
--- a/Gemfile.lock
+++ b/Gemfile.lock
@@ -1,10 +1,10 @@
 GEM
   remote: https://rubygems.org/
   specs:
+    bundler (2.3.0)

 PLATFORMS
+  ruby

 DEPENDENCIES
+  bundler
`;
      const result = extractPackagesFromDiff(diff);
      assert.deepEqual(result, [{ name: 'bundler', version: '2.3.0', ecosystem: 'RubyGems' }]);
    });
  });

  describe('deduplication', () => {
    it('deduplicates packages by name+version+ecosystem', () => {
      const diff = `diff --git a/package-lock.json b/package-lock.json
index abc123..def456 100644
--- a/package-lock.json
+++ b/package-lock.json
@@ -1,15 +1,15 @@
 {
   "dependencies": {
     "lodash": {
+      "version": "4.17.21",
+      "version": "4.17.21",
       "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
     }
   }
 }
`;
      const result = extractPackagesFromDiff(diff);
      // Should have only one lodash entry despite being added twice
      assert.equal(result.length, 1);
      assert.equal(result[0].name, 'lodash');
    });

    it('keeps different versions of same package', () => {
      const diff = `diff --git a/package-lock.json b/package-lock.json
index abc123..def456 100644
--- a/package-lock.json
+++ b/package-lock.json
@@ -1,20 +1,20 @@
 {
   "dependencies": {
     "lodash": {
+      "version": "4.17.20",
     },
     "lodash-compat": {
+      "version": "3.10.2",
       "resolved": "https://registry.npmjs.org/lodash-compat/-/lodash-compat-3.10.2.tgz"
     }
   }
 }
`;
      const result = extractPackagesFromDiff(diff);
      assert.equal(result.length, 2);
    });
  });

  describe('multiple lockfile types in single diff', () => {
    it('processes multiple lockfile changes in one diff', () => {
      const diff = `diff --git a/package-lock.json b/package-lock.json
index abc123..def456 100644
--- a/package-lock.json
+++ b/package-lock.json
@@ -1,10 +1,10 @@
 {
   "dependencies": {
     "lodash": {
+      "version": "4.17.21"
     }
   }
 }

diff --git a/go.sum b/go.sum
index abc123..def456 100644
--- a/go.sum
+++ b/go.sum
+github.com/sirupsen/logrus v1.8.1 h1:dJKuHgqk91NevLj9IlNjPqMd+QH+9/3/ngvjvxdgrQ=
`;
      const result = extractPackagesFromDiff(diff);
      assert.equal(result.length, 2);
      const ecosystems = new Set(result.map(p => p.ecosystem));
      assert.ok(ecosystems.has('npm'));
      assert.ok(ecosystems.has('Go'));
    });
  });

  describe('edge cases', () => {
    it('handles diff with no content changes', () => {
      const diff = `diff --git a/package-lock.json b/package-lock.json
index abc123..def456 100644
--- a/package-lock.json
+++ b/package-lock.json
`;
      const result = extractPackagesFromDiff(diff);
      assert.deepEqual(result, []);
    });

    it('ignores diff header lines (+++, ---, @@)', () => {
      const diff = `diff --git a/poetry.lock b/poetry.lock
index abc123..def456 100644
--- a/poetry.lock
+++ b/poetry.lock
@@ -1,5 +1,5 @@
+[[package]]
+name = "requests"
+version = "2.31.0"
`;
      const result = extractPackagesFromDiff(diff);
      assert.equal(result.length, 1);
      assert.equal(result[0].name, 'requests');
    });

    it('handles whitespace-only additions', () => {
      const diff = `diff --git a/poetry.lock b/poetry.lock
index abc123..def456 100644
--- a/poetry.lock
+++ b/poetry.lock
@@ -1,5 +1,6 @@
 # This file is automatically generated
+
+[[package]]
+name = "requests"
+version = "2.31.0"
`;
      const result = extractPackagesFromDiff(diff);
      assert.equal(result.length, 1);
    });
  });
});
