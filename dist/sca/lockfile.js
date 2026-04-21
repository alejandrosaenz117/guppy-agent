/**
 * Parses a git diff and extracts packages from lockfile changes.
 * Only includes lines that were added (starting with '+' but not '+++').
 * Returns deduplicated packages by name+version+ecosystem.
 */
export function extractPackagesFromDiff(diff) {
    if (!diff || diff.trim() === '') {
        return [];
    }
    const packages = new Map();
    // Split by "diff --git" to get individual file diffs
    const fileDiffs = diff.split(/^diff --git /m).slice(1);
    for (const fileDiff of fileDiffs) {
        const lines = fileDiff.split('\n');
        if (lines.length === 0)
            continue;
        // First line contains the file paths: a/path b/path
        const firstLine = lines[0];
        const filename = extractFilename(firstLine);
        // Detect ecosystem from filename
        const ecosystem = detectEcosystem(filename);
        if (!ecosystem) {
            continue; // Not a lockfile we care about
        }
        // For JSON-based lockfiles, we need context lines, so pass all lines with markers
        // For line-based lockfiles (go.sum, yarn.lock, etc.), extract just the added lines
        const parsedPackages = parsePackagesForEcosystem(ecosystem, lines, filename);
        // Add to deduplication map
        for (const pkg of parsedPackages) {
            const key = `${pkg.name}|${pkg.version}|${pkg.ecosystem}`;
            packages.set(key, pkg);
        }
    }
    return Array.from(packages.values());
}
/**
 * Extract filename from the first line of a file diff.
 * Format: "a/path/to/file b/path/to/file"
 */
function extractFilename(line) {
    // Remove "a/" and get the path before "b/"
    const parts = line.split(' b/');
    if (parts.length < 2) {
        return '';
    }
    const aPath = parts[0].replace(/^a\//, '');
    return aPath;
}
/**
 * Detect the package ecosystem from the lockfile filename.
 */
function detectEcosystem(filename) {
    if (!filename)
        return null;
    const lowerFilename = filename.toLowerCase();
    // npm
    if (lowerFilename === 'package-lock.json')
        return 'npm';
    if (lowerFilename === 'yarn.lock')
        return 'npm'; // yarn is npm ecosystem
    if (lowerFilename === 'pnpm-lock.yaml')
        return 'npm'; // pnpm is npm ecosystem
    // Python
    if (lowerFilename === 'pipfile.lock')
        return 'PyPI';
    if (lowerFilename === 'poetry.lock')
        return 'PyPI';
    // Go
    if (lowerFilename === 'go.sum')
        return 'Go';
    // Rust
    if (lowerFilename === 'cargo.lock')
        return 'Cargo';
    // Ruby
    if (lowerFilename === 'gemfile.lock')
        return 'RubyGems';
    return null;
}
/**
 * Parse packages from lines based on the ecosystem and lockfile format.
 * Lines include diff markers (+, -, space for context).
 */
function parsePackagesForEcosystem(ecosystem, lines, filename) {
    const lowerFilename = filename.toLowerCase();
    if (lowerFilename === 'package-lock.json') {
        return parseNpmPackageLock(lines, ecosystem);
    }
    if (lowerFilename === 'yarn.lock') {
        return parseYarnLock(lines, ecosystem);
    }
    if (lowerFilename === 'pnpm-lock.yaml') {
        return parsePnpmLock(lines, ecosystem);
    }
    if (lowerFilename === 'pipfile.lock') {
        return parsePipfileLock(lines, ecosystem);
    }
    if (lowerFilename === 'poetry.lock') {
        return parsePoetryLock(lines, ecosystem);
    }
    if (lowerFilename === 'go.sum') {
        return parseGoSum(lines, ecosystem);
    }
    if (lowerFilename === 'cargo.lock') {
        return parseCargoLock(lines, ecosystem);
    }
    if (lowerFilename === 'gemfile.lock') {
        return parseGemfileLock(lines, ecosystem);
    }
    return [];
}
/**
 * Parse npm package-lock.json format.
 * Format:
 *   "package-name": {
 *     "version": "1.2.3",
 *
 * Strategy: Find added version lines and track back to find the package name in either added or context lines.
 */
function parseNpmPackageLock(lines, ecosystem) {
    const packages = [];
    // Extract only the content without diff markers for processing
    const cleanLines = lines.map(line => {
        if (line.startsWith('+') || line.startsWith('-')) {
            return line.substring(1);
        }
        return line;
    });
    // Build a map of package names with their line numbers
    const packageNames = new Map();
    for (let i = 0; i < cleanLines.length; i++) {
        const line = cleanLines[i];
        const packageMatch = line.match(/"([^"]+)"\s*:\s*\{/);
        if (packageMatch) {
            const name = packageMatch[1];
            if (name !== 'dependencies' && name !== 'devDependencies' && name !== 'optionalDependencies') {
                packageNames.set(i, name);
            }
        }
    }
    // Find version lines in added changes
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // Only process added lines
        if (!line.startsWith('+') || line.startsWith('+++')) {
            continue;
        }
        const cleanedLine = line.substring(1);
        const versionMatch = cleanedLine.match(/"version"\s*:\s*"([^"]+)"/);
        if (versionMatch) {
            const version = versionMatch[1];
            // Find the nearest package name before this line in cleanLines
            let packageName;
            for (let j = i - 1; j >= Math.max(0, i - 30); j--) {
                if (packageNames.has(j)) {
                    packageName = packageNames.get(j);
                    break;
                }
            }
            if (packageName) {
                packages.push({ name: packageName, version, ecosystem });
            }
        }
    }
    return packages;
}
/**
 * Parse yarn.lock format.
 * Format:
 *   package-name@version:
 *     version "1.2.3"
 */
function parseYarnLock(lines, ecosystem) {
    const packages = [];
    for (const line of lines) {
        // Only process added lines
        if (line.startsWith('-') || line.startsWith('@@')) {
            continue;
        }
        // Remove diff markers
        const cleanLine = line.startsWith('+') && !line.startsWith('+++') ? line.substring(1) : line;
        // Match lines like: "package-name@1.2.3:" or "package-name@^1.0.0:"
        const match = cleanLine.match(/^"?([^"@]+)@([^":]+)"?:/);
        if (match) {
            const name = match[1];
            const versionSpec = match[2];
            // For yarn.lock, we extract the actual version from the version field or use the spec
            packages.push({ name, version: versionSpec, ecosystem });
        }
    }
    return packages;
}
/**
 * Parse pnpm-lock.yaml format.
 * Format:
 *   dependencies:
 *     package-name: 1.2.3
 * Or with spec:
 *     package-name: specifier
 * And resolutions:
 *   /package-name@1.2.3:
 */
function parsePnpmLock(lines, ecosystem) {
    const packages = [];
    for (const line of lines) {
        // Only process added lines
        if (line.startsWith('-') || line.startsWith('@@')) {
            continue;
        }
        // Remove diff markers
        const cleanLine = line.startsWith('+') && !line.startsWith('+++') ? line.substring(1) : line;
        // Match direct dependencies format: "  package-name: version"
        const depMatch = cleanLine.match(/^\s*([^:\s]+):\s*(.+)$/);
        if (depMatch) {
            const name = depMatch[1];
            const versionSpec = depMatch[2].trim();
            // Only add if it looks like a version (not section headers)
            if (versionSpec && !versionSpec.startsWith('#') && name !== 'dependencies' && name !== 'devDependencies') {
                packages.push({ name, version: versionSpec, ecosystem });
            }
        }
        // Match resolutions format: "/package-name@version:"
        const resMatch = cleanLine.match(/^\/([^@]+)@([^:]+):/);
        if (resMatch) {
            const name = resMatch[1];
            const version = resMatch[2];
            packages.push({ name, version, ecosystem });
        }
    }
    return packages;
}
/**
 * Parse Pipfile.lock format (JSON).
 * Format:
 *   "package-name": {
 *     "version": "==1.2.3"
 */
function parsePipfileLock(lines, ecosystem) {
    const packages = [];
    // Extract clean lines for context
    const cleanLines = lines.map(line => {
        if (line.startsWith('+') || line.startsWith('-')) {
            return line.substring(1);
        }
        return line;
    });
    // Build a map of package names with their line numbers
    const packageNames = new Map();
    for (let i = 0; i < cleanLines.length; i++) {
        const line = cleanLines[i];
        const packageMatch = line.match(/"([^"]+)"\s*:\s*\{/);
        if (packageMatch) {
            const name = packageMatch[1];
            if (name !== 'default' && name !== 'develop') {
                packageNames.set(i, name);
            }
        }
    }
    // Find version lines in added changes
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // Only process added lines
        if (!line.startsWith('+') || line.startsWith('+++')) {
            continue;
        }
        const cleanedLine = line.substring(1);
        const versionMatch = cleanedLine.match(/"version"\s*:\s*"([^"]+)"/);
        if (versionMatch) {
            let version = versionMatch[1];
            // Clean up version specifiers
            version = version.replace(/^[<>=!~]+/, '');
            // Find the nearest package name before this line
            let packageName;
            for (let j = i - 1; j >= Math.max(0, i - 30); j--) {
                if (packageNames.has(j)) {
                    packageName = packageNames.get(j);
                    break;
                }
            }
            if (packageName) {
                packages.push({ name: packageName, version, ecosystem });
            }
        }
    }
    return packages;
}
/**
 * Parse poetry.lock format (TOML-like).
 * Format:
 *   [[package]]
 *   name = "package-name"
 *   version = "1.2.3"
 */
function parsePoetryLock(lines, ecosystem) {
    const packages = [];
    let currentPackage = {};
    for (const line of lines) {
        // Remove diff markers
        const cleanLine = line.startsWith('+') && !line.startsWith('+++') ? line.substring(1) : line;
        if (line.startsWith('-') || line.startsWith('@@')) {
            continue;
        }
        // Reset on new package entry
        if (cleanLine.trim() === '[[package]]') {
            if (currentPackage.name && currentPackage.version) {
                packages.push({
                    name: currentPackage.name,
                    version: currentPackage.version,
                    ecosystem,
                });
            }
            currentPackage = {};
        }
        // Extract name
        const nameMatch = cleanLine.match(/name\s*=\s*"([^"]+)"/);
        if (nameMatch) {
            currentPackage.name = nameMatch[1];
        }
        // Extract version
        const versionMatch = cleanLine.match(/version\s*=\s*"([^"]+)"/);
        if (versionMatch) {
            currentPackage.version = versionMatch[1];
        }
    }
    // Don't forget the last package
    if (currentPackage.name && currentPackage.version) {
        packages.push({
            name: currentPackage.name,
            version: currentPackage.version,
            ecosystem,
        });
    }
    return packages;
}
/**
 * Parse go.sum format.
 * Format:
 *   github.com/user/package v1.2.3 h1:...
 *   github.com/user/package v1.2.3/go.mod h1:...
 *
 * Note: Both forms have the same name and version, so we deduplicate by name+version.
 * The /go.mod suffix appears AFTER the version number in the same column.
 */
function parseGoSum(lines, ecosystem) {
    const packages = new Map();
    for (const line of lines) {
        // Only process added lines
        if (line.startsWith('-') || line.startsWith('@@')) {
            continue;
        }
        // Remove diff markers
        const cleanLine = line.startsWith('+') && !line.startsWith('+++') ? line.substring(1) : line;
        // Match: "module-name v1.2.3[/go.mod] hash"
        // The version part is v followed by numbers/dots, optionally followed by /go.mod
        const match = cleanLine.match(/^([^\s]+?)\s+(v[^\s/]+)(?:\/go\.mod)?\s+/);
        if (match) {
            const name = match[1];
            const version = match[2];
            // Deduplicate by name and version
            const key = `${name}|${version}`;
            if (!packages.has(key)) {
                packages.set(key, { name, version, ecosystem });
            }
        }
    }
    return Array.from(packages.values());
}
/**
 * Parse Cargo.lock format (TOML).
 * Format:
 *   [[package]]
 *   name = "package-name"
 *   version = "1.2.3"
 */
function parseCargoLock(lines, ecosystem) {
    const packages = [];
    let currentPackage = {};
    for (const line of lines) {
        // Remove diff markers
        const cleanLine = line.startsWith('+') && !line.startsWith('+++') ? line.substring(1) : line;
        if (line.startsWith('-') || line.startsWith('@@')) {
            continue;
        }
        // Reset on new package entry
        if (cleanLine.trim() === '[[package]]') {
            if (currentPackage.name && currentPackage.version) {
                packages.push({
                    name: currentPackage.name,
                    version: currentPackage.version,
                    ecosystem,
                });
            }
            currentPackage = {};
        }
        // Extract name
        const nameMatch = cleanLine.match(/name\s*=\s*"([^"]+)"/);
        if (nameMatch) {
            currentPackage.name = nameMatch[1];
        }
        // Extract version
        const versionMatch = cleanLine.match(/version\s*=\s*"([^"]+)"/);
        if (versionMatch) {
            currentPackage.version = versionMatch[1];
        }
    }
    // Don't forget the last package
    if (currentPackage.name && currentPackage.version) {
        packages.push({
            name: currentPackage.name,
            version: currentPackage.version,
            ecosystem,
        });
    }
    return packages;
}
/**
 * Parse Gemfile.lock format.
 * Format:
 *   GEM
 *     remote: https://rubygems.org/
 *     specs:
 *       gem-name (1.2.3)
 *         dependency-name (~> 2.0)
 *
 * We need to distinguish top-level gems from their dependencies by indentation.
 * Top-level gems are indented with 4 spaces, dependencies with more (6+ spaces).
 */
function parseGemfileLock(lines, ecosystem) {
    const packages = new Set();
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // Remove diff markers
        const cleanLine = line.startsWith('+') && !line.startsWith('+++') ? line.substring(1) : line;
        if (line.startsWith('-') || line.startsWith('@@')) {
            continue;
        }
        // Match lines like "    gem-name (1.2.3)" - 4 spaces for top-level gems
        // Dependencies have 6+ spaces indentation
        const match = cleanLine.match(/^(\s+)([^\s(]+)\s+\(([^)]+)\)/);
        if (match) {
            const indentation = match[1].length;
            const name = match[2];
            const version = match[3];
            // Skip metadata section headers (all uppercase)
            if (/^[A-Z]+$/.test(name)) {
                continue;
            }
            // Only include top-level gems (4 spaces indent) and skip dependencies (6+ spaces)
            // Top-level gems under specs: should be 4 spaces
            if (indentation === 4) {
                const key = `${name}|${version}`;
                if (!packages.has(key)) {
                    packages.add(key);
                }
            }
        }
    }
    return Array.from(packages).map(key => {
        const [name, version] = key.split('|');
        return { name, version, ecosystem };
    });
}
//# sourceMappingURL=lockfile.js.map