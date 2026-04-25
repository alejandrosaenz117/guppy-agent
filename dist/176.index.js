export const id = 176;
export const ids = [176];
export const modules = {

/***/ 1176:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "generateSecureCode": () => (/* binding */ generateSecureCode)
/* harmony export */ });
/* harmony import */ var ai__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(9438);
/* harmony import */ var _actions_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(2186);


/**
 * Generates secure, production-ready code fixes using a language model.
 * Called after Guppy identifies vulnerabilities to produce high-quality remediation code.
 */
async function generateSecureCode(model, finding, vulnerableCode) {
    try {
        const fileExt = (finding.file ?? '').split('.').pop()?.toLowerCase() ?? '';
        const langName = mapExtensionToLanguage(fileExt);
        const codesmith = `You are a security-focused code remediation expert. Your task is to rewrite vulnerable code securely.

CRITICAL REQUIREMENTS:
1. Write production-ready, secure code in ${langName}
2. The code must be minimal and drop-in replaceable
3. Do NOT add new imports, network calls, eval, exec, or shell operations not in the original
4. Return ONLY the rewritten code block — no explanations, no markdown, no additional text
5. The code must compile/run without errors
6. Include necessary error handling and input validation
7. Add comments explaining the security fix

VULNERABILITY: ${finding.type}
SEVERITY: ${finding.severity}
DESCRIPTION: ${finding.message}

VULNERABLE CODE:
${vulnerableCode}

Return ONLY the fixed code, nothing else.`;
        const result = await (0,ai__WEBPACK_IMPORTED_MODULE_1__/* .generateText */ ._4)({
            model,
            system: codesmith,
            prompt: 'Generate the secure replacement code:',
            temperature: 0.3,
        });
        const fixedCode = result.text.trim();
        // Validate the result looks like code (not an explanation)
        if (fixedCode.length < 10 || fixedCode.startsWith('I ') || fixedCode.startsWith('Here ')) {
            _actions_core__WEBPACK_IMPORTED_MODULE_0__.debug('[Codesmith] Generated response looks like explanation, not code. Rejecting.');
            return null;
        }
        return fixedCode;
    }
    catch (error) {
        _actions_core__WEBPACK_IMPORTED_MODULE_0__.debug('[Codesmith] Code generation failed: ' + (error instanceof Error ? error.message : String(error)));
        return null;
    }
}
function mapExtensionToLanguage(ext) {
    const mapping = {
        ts: 'TypeScript',
        tsx: 'TypeScript/React',
        js: 'JavaScript',
        jsx: 'JavaScript/React',
        py: 'Python',
        go: 'Go',
        rb: 'Ruby',
        java: 'Java',
        kt: 'Kotlin',
        rs: 'Rust',
        cs: 'C#',
        cpp: 'C++',
        c: 'C',
        php: 'PHP',
        sh: 'Bash',
    };
    return mapping[ext] || 'the target language';
}
//# sourceMappingURL=codesmith.js.map

/***/ })

};
