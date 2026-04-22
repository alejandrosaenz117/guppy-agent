import { z } from 'zod';
export interface Enrichable {
    enrichable?: boolean;
}
export type ReachabilityVerdict = 'reachable' | 'unreachable' | 'unknown';
export declare const REACHABILITY_CONFIDENCE_LABELS: Record<1 | 2 | 3, string>;
export interface DetectedPackage {
    name: string;
    version: string;
    ecosystem: string;
}
export interface OsvVulnerability extends Enrichable {
    id: string;
    summary: string;
    details: string;
    severity?: string;
    affected_versions: string[];
    cvss_score?: number;
    package_name?: string;
    installed_version?: string;
    fixed_version?: string;
    vulnerable_function?: string;
    cwe_ids?: string[];
}
export interface ScannerAdapter {
    scan(packages: DetectedPackage[]): Promise<OsvVulnerability[]>;
    enrichVulnerabilities?(vulns: OsvVulnerability[]): Promise<OsvVulnerability[]>;
}
export interface ScaFinding {
    package: DetectedPackage;
    vulnerability: OsvVulnerability;
    reachability?: ReachabilityVerdict;
    confidence?: 1 | 2 | 3;
    file?: string;
}
export declare const FindingSchema: z.ZodObject<{
    file: z.ZodString;
    line: z.ZodNumber;
    severity: z.ZodEnum<["critical", "high", "medium", "low", "none"]>;
    type: z.ZodString;
    message: z.ZodString;
    fix: z.ZodString;
    fix_snippet: z.ZodOptional<z.ZodString>;
    cwe_id: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    severity?: "low" | "medium" | "high" | "critical" | "none";
    file?: string;
    line?: number;
    type?: string;
    message?: string;
    fix?: string;
    fix_snippet?: string;
    cwe_id?: string;
}, {
    severity?: "low" | "medium" | "high" | "critical" | "none";
    file?: string;
    line?: number;
    type?: string;
    message?: string;
    fix?: string;
    fix_snippet?: string;
    cwe_id?: string;
}>;
export type Finding = z.infer<typeof FindingSchema>;
export declare const FindingsSchema: z.ZodObject<{
    findings: z.ZodArray<z.ZodObject<{
        file: z.ZodString;
        line: z.ZodNumber;
        severity: z.ZodEnum<["critical", "high", "medium", "low", "none"]>;
        type: z.ZodString;
        message: z.ZodString;
        fix: z.ZodString;
        fix_snippet: z.ZodOptional<z.ZodString>;
        cwe_id: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        severity?: "low" | "medium" | "high" | "critical" | "none";
        file?: string;
        line?: number;
        type?: string;
        message?: string;
        fix?: string;
        fix_snippet?: string;
        cwe_id?: string;
    }, {
        severity?: "low" | "medium" | "high" | "critical" | "none";
        file?: string;
        line?: number;
        type?: string;
        message?: string;
        fix?: string;
        fix_snippet?: string;
        cwe_id?: string;
    }>, "many">;
}, "strip", z.ZodTypeAny, {
    findings?: {
        severity?: "low" | "medium" | "high" | "critical" | "none";
        file?: string;
        line?: number;
        type?: string;
        message?: string;
        fix?: string;
        fix_snippet?: string;
        cwe_id?: string;
    }[];
}, {
    findings?: {
        severity?: "low" | "medium" | "high" | "critical" | "none";
        file?: string;
        line?: number;
        type?: string;
        message?: string;
        fix?: string;
        fix_snippet?: string;
        cwe_id?: string;
    }[];
}>;
export declare const ActionInputsSchema: z.ZodObject<{
    api_key: z.ZodString;
    provider: z.ZodDefault<z.ZodEnum<["anthropic", "openai", "google"]>>;
    model: z.ZodDefault<z.ZodString>;
    skeptic_pass: z.ZodDefault<z.ZodBoolean>;
    post_comments: z.ZodDefault<z.ZodBoolean>;
    fail_on_severity: z.ZodDefault<z.ZodEnum<["critical", "high", "medium", "low", "none"]>>;
    github_token: z.ZodString;
    upload_sarif: z.ZodDefault<z.ZodBoolean>;
    sca_enabled: z.ZodDefault<z.ZodBoolean>;
    sca_scanner: z.ZodDefault<z.ZodEnum<["osv"]>>;
    sca_reachability: z.ZodDefault<z.ZodBoolean>;
    sca_reachability_threshold: z.ZodDefault<z.ZodEnum<["critical", "high", "medium", "low", "none"]>>;
    sca_reachability_confidence_threshold: z.ZodDefault<z.ZodUnion<[z.ZodLiteral<1>, z.ZodLiteral<2>, z.ZodLiteral<3>]>>;
}, "strip", z.ZodTypeAny, {
    api_key?: string;
    provider?: "anthropic" | "openai" | "google";
    model?: string;
    skeptic_pass?: boolean;
    post_comments?: boolean;
    fail_on_severity?: "low" | "medium" | "high" | "critical" | "none";
    github_token?: string;
    upload_sarif?: boolean;
    sca_enabled?: boolean;
    sca_scanner?: "osv";
    sca_reachability?: boolean;
    sca_reachability_threshold?: "low" | "medium" | "high" | "critical" | "none";
    sca_reachability_confidence_threshold?: 1 | 2 | 3;
}, {
    api_key?: string;
    provider?: "anthropic" | "openai" | "google";
    model?: string;
    skeptic_pass?: boolean;
    post_comments?: boolean;
    fail_on_severity?: "low" | "medium" | "high" | "critical" | "none";
    github_token?: string;
    upload_sarif?: boolean;
    sca_enabled?: boolean;
    sca_scanner?: "osv";
    sca_reachability?: boolean;
    sca_reachability_threshold?: "low" | "medium" | "high" | "critical" | "none";
    sca_reachability_confidence_threshold?: 1 | 2 | 3;
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