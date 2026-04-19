import { lintSource } from '@secretlint/core';
import { creator as recommendPreset } from '@secretlint/secretlint-rule-preset-recommend';
const secretlintConfig = {
    rules: [
        {
            id: recommendPreset.meta.id,
            rule: recommendPreset,
            options: {},
        },
    ],
};
export class Scrubber {
    async scrub(input) {
        if (!input)
            return input;
        const result = await lintSource({
            source: {
                content: input,
                filePath: 'diff.txt',
                ext: '.txt',
                contentType: 'text',
            },
            options: {
                config: secretlintConfig,
                noPhysicFilePath: true,
            },
        });
        if (!result.messages || result.messages.length === 0) {
            return input;
        }
        // Redact detected secrets by replacing their ranges in reverse order
        // (reverse so earlier replacements don't shift indices of later ones)
        let scrubbed = input;
        const ranges = [...result.messages]
            .sort((a, b) => b.range[0] - a.range[0]);
        for (const msg of ranges) {
            const [start, end] = msg.range;
            scrubbed = scrubbed.slice(0, start) + '[REDACTED]' + scrubbed.slice(end);
        }
        return scrubbed;
    }
}
export const scrubber = new Scrubber();
//# sourceMappingURL=scrubber.js.map