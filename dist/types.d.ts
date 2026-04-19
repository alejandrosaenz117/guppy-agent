import { z } from 'zod';
export declare const FindingSchema: z.ZodObject<{
    file: z.ZodString;
    line: z.ZodNumber;
    severity: z.ZodEnum<["critical", "high", "medium", "low", "none"]>;
    type: z.ZodString;
    message: z.ZodString;
    fix: z.ZodString;
}, "strip", z.ZodTypeAny, {
    file?: string;
    line?: number;
    severity?: "critical" | "high" | "medium" | "low" | "none";
    type?: string;
    message?: string;
    fix?: string;
}, {
    file?: string;
    line?: number;
    severity?: "critical" | "high" | "medium" | "low" | "none";
    type?: string;
    message?: string;
    fix?: string;
}>;
export type Finding = z.infer<typeof FindingSchema>;
export declare const FindingsSchema: z.ZodArray<z.ZodObject<{
    file: z.ZodString;
    line: z.ZodNumber;
    severity: z.ZodEnum<["critical", "high", "medium", "low", "none"]>;
    type: z.ZodString;
    message: z.ZodString;
    fix: z.ZodString;
}, "strip", z.ZodTypeAny, {
    file?: string;
    line?: number;
    severity?: "critical" | "high" | "medium" | "low" | "none";
    type?: string;
    message?: string;
    fix?: string;
}, {
    file?: string;
    line?: number;
    severity?: "critical" | "high" | "medium" | "low" | "none";
    type?: string;
    message?: string;
    fix?: string;
}>, "many">;
export declare const ActionInputsSchema: z.ZodObject<{
    api_key: z.ZodString;
    provider: z.ZodDefault<z.ZodEnum<["anthropic", "openai", "google"]>>;
    model: z.ZodDefault<z.ZodString>;
    post_comments: z.ZodDefault<z.ZodBoolean>;
    fail_on_severity: z.ZodDefault<z.ZodEnum<["critical", "high", "medium", "low", "none"]>>;
    github_token: z.ZodString;
}, "strip", z.ZodTypeAny, {
    api_key?: string;
    provider?: "anthropic" | "openai" | "google";
    model?: string;
    post_comments?: boolean;
    fail_on_severity?: "critical" | "high" | "medium" | "low" | "none";
    github_token?: string;
}, {
    api_key?: string;
    provider?: "anthropic" | "openai" | "google";
    model?: string;
    post_comments?: boolean;
    fail_on_severity?: "critical" | "high" | "medium" | "low" | "none";
    github_token?: string;
}>;
export type ActionInputs = z.infer<typeof ActionInputsSchema>;
export declare const SEVERITY_ORDER: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    none: number;
};
//# sourceMappingURL=types.d.ts.map