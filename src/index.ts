import * as core from '@actions/core';
import * as github from '@actions/github';
import { Guppy } from './guppy.js';
import { scrubber } from './scrubber.js';
import { enrichFinding, formatScaComment } from './enricher.js';
import { findingsToSarif } from './sarif.js';
import { ActionInputsSchema, SEVERITY_ORDER, Finding } from './types.js';
import { ScaAuditor } from './sca/index.js';
import { ScaHunter } from './sca/hunter.js';
import { OsvAdapter } from './sca/adapters/osv.js';
import { extractPackagesFromDiff } from './sca/lockfile.js';
import type { ScaFinding } from './types.js';
import { gzipSync } from 'zlib';
import { anthropic } from '@ai-sdk/anthropic';
import { openai } from '@ai-sdk/openai';
import { google } from '@ai-sdk/google';

function extractTouchedFiles(diff: string): string[] {
  const files: string[] = [];
  for (const line of diff.split('\n')) {
    const match = line.match(/^diff --git a\/.+ b\/(.+)$/);
    if (match) files.push(match[1]);
  }
  return [...new Set(files)];
}

async function main() {
  try {
    core.info('[Guppy] Acknowledged. Initiating security scan. As you wish, Bob.');

    await core.summary
      .addHeading('Guppy Security Scanner', 3)
      .addTable([
        [{ data: 'Input', header: true }, { data: 'Value', header: true }],
        ['comment_severity_threshold', core.getInput('comment_severity_threshold') || 'high'],
        ['fail_on_severity', core.getInput('fail_on_severity') || 'high'],
      ])
      .write();

    // Parse inputs
    const api_key = process.env.LLM_API_KEY || core.getInput('api_key');
    if (!api_key) {
      throw new Error('[Guppy] Error: LLM API key not provided. Set either environment variable "LLM_API_KEY" or input "api_key"');
    }
    core.setSecret(api_key);
    const provider = core.getInput('provider') || 'anthropic';
    const model = core.getInput('model') || 'claude-3-5-sonnet-20241022';
    const skeptic_pass = core.getBooleanInput('skeptic_pass');
    const post_comments = core.getBooleanInput('post_comments');
    const fail_on_severity = core.getInput('fail_on_severity') || 'high';
    const comment_severity_threshold = core.getInput('comment_severity_threshold') || 'high';
    const github_token = process.env.GITHUB_TOKEN || core.getInput('github_token');
    if (!github_token) {
      throw new Error('[Guppy] Error: GitHub token not provided. Set either environment variable "GITHUB_TOKEN" or input "github_token"');
    }
    const upload_sarif = core.getBooleanInput('upload_sarif');
    const sca_enabled = core.getBooleanInput('sca_enabled');
    const sca_scanner = core.getInput('sca_scanner') || 'osv';
    const sca_reachability = core.getBooleanInput('sca_reachability');
    const sca_reachability_threshold = core.getInput('sca_reachability_threshold') || 'high';
    const sca_reachability_confidence_threshold = parseInt(core.getInput('sca_reachability_confidence_threshold') || '2', 10) as 1 | 2 | 3;

    // Validate inputs
    const inputs = ActionInputsSchema.parse({
      api_key,
      provider,
      model,
      skeptic_pass,
      post_comments,
      fail_on_severity,
      comment_severity_threshold,
      github_token,
      upload_sarif,
      sca_enabled,
      sca_scanner,
      sca_reachability,
      sca_reachability_threshold,
      sca_reachability_confidence_threshold,
    });

    // Set API key in environment and select model client
    let modelClient;
    switch (inputs.provider) {
      case 'openai':
        process.env.OPENAI_API_KEY = inputs.api_key;
        modelClient = openai(inputs.model);
        break;
      case 'google':
        process.env.GOOGLE_GENERATIVE_AI_API_KEY = inputs.api_key;
        modelClient = google(inputs.model);
        break;
      case 'anthropic':
      default:
        process.env.ANTHROPIC_API_KEY = inputs.api_key;
        modelClient = anthropic(inputs.model);
    }

    core.debug(`[Guppy] Model client initialized: ${inputs.provider}/${inputs.model}`);

    // Extract PR context
    const context = github.context;
    if (!context.payload.pull_request) {
      core.setFailed('[Guppy] Warning: Not running in a PR context. Aborting.');
      return;
    }

    const prNumber = context.payload.pull_request.number;
    core.info(`[Guppy] Analyzing PR #${prNumber}...`);

    // Fetch PR diff
    const octokit = github.getOctokit(inputs.github_token);
    const repo = context.repo;

    const diffResponse = await octokit.request('GET /repos/{owner}/{repo}/pulls/{pull_number}', {
      owner: repo.owner,
      repo: repo.repo,
      pull_number: prNumber,
      headers: { accept: 'application/vnd.github.v3.diff' },
    });

    const rawDiff = typeof diffResponse.data === 'string' ? diffResponse.data : JSON.stringify(diffResponse.data);
    core.info(`[Guppy] Diff size: ${rawDiff.length} bytes`);

    // Enforce max diff size to prevent runaway costs and context overflow
    const MAX_DIFF_BYTES = 500_000;
    const truncatedDiff = rawDiff.length > MAX_DIFF_BYTES
      ? rawDiff.slice(0, MAX_DIFF_BYTES) + '\n[Guppy] Warning: Diff truncated at 500KB.'
      : rawDiff;

    // Extract packages from raw diff BEFORE scrubbing
    // This prevents secretlint redaction from corrupting version strings
    const rawPackages = extractPackagesFromDiff(truncatedDiff);

    // Scrub secrets before sending to LLM
    const scrubbedDiff = await scrubber.scrub(truncatedDiff);
    core.info(`[Guppy] Scrubbed diff size: ${scrubbedDiff.length} bytes. Proceeding to analysis...`);

    // Run SAST and SCA pipelines in parallel
    const guppy = new Guppy(modelClient, inputs.skeptic_pass);
    core.info('[Guppy] Starting SAST Hunter pass...');

    let scaAuditor: ScaAuditor | null = null;
    if (inputs.sca_enabled) {
      const adapter = new OsvAdapter();
      const hunter = inputs.sca_reachability
        ? new ScaHunter(modelClient, inputs.sca_reachability_threshold)
        : null;
      scaAuditor = new ScaAuditor(adapter, hunter, rawPackages);
    }

    const [findings, scaFindings] = await Promise.all([
      guppy.audit(scrubbedDiff),
      scaAuditor ? scaAuditor.audit(scrubbedDiff) : Promise.resolve([] as ScaFinding[]),
    ]);

    core.info(`[Guppy] SAST: ${findings.length} finding(s). SCA: ${scaFindings.length} finding(s).`);

    // Clean up API key from environment after use
    delete process.env.ANTHROPIC_API_KEY;
    delete process.env.OPENAI_API_KEY;
    delete process.env.GOOGLE_GENERATIVE_AI_API_KEY;

    if (findings.length === 0 && scaFindings.length === 0) {
      core.info('[Guppy] No vulnerabilities detected.');
      return;
    }

    core.warning(`[Guppy] Calculation: ${findings.length} potential vulnerabilities identified.`);

    // Compute comment severity threshold once for both SAST and SCA
    const commentThreshold = SEVERITY_ORDER[inputs.comment_severity_threshold as keyof typeof SEVERITY_ORDER];
    const commentableFindings = findings.filter(
      (f) => SEVERITY_ORDER[f.severity as keyof typeof SEVERITY_ORDER] >= commentThreshold
    );

    // Enrich all findings once — reused for both PR comments and SARIF help text
    const enrichedTexts = new Map<Finding, string>();
    if ((inputs.post_comments || inputs.upload_sarif) && commentableFindings.length > 0) {
      core.info('[Guppy] Enriching findings with CWE/CAPEC data and generating secure code...');
      await Promise.all(commentableFindings.map(async (f) => {
        enrichedTexts.set(f, await enrichFinding(f, modelClient));
      }));
    }

    // Post inline comments only if SARIF upload is not enabled — when SARIF is
    // active, GitHub's native code scanning annotations already surface findings.
    if (inputs.post_comments && !inputs.upload_sarif && commentableFindings.length > 0) {
      core.info('[Guppy] Posting inline comments to PR...');

      // Fetch existing Guppy comments to update in place instead of duplicating
      const existingComments = await octokit.paginate(
        (octokit.rest.pulls as any).listReviewComments,
        { owner: repo.owner, repo: repo.repo, pull_number: prNumber, per_page: 100 }
      );
      const guppyComments = existingComments.filter(
        (c: any) => c.user?.login === 'github-actions[bot]' && c.body?.startsWith('🚨')
      );

      for (const finding of commentableFindings) {
        const body = enrichedTexts.get(finding)!;
        const existing = guppyComments.find(
          (c: any) => c.path === finding.file && c.line === finding.line
        );

        if (existing) {
          await (octokit.rest.pulls as any).updateReviewComment({
            owner: repo.owner,
            repo: repo.repo,
            comment_id: existing.id,
            body,
          }).catch((err: any) => {
            core.warning(`[Guppy] Failed to update comment on ${finding.file}:${finding.line}: ${err.message}`);
          });
        } else {
          await (octokit.rest.pulls as any).createReviewComment({
            owner: repo.owner,
            repo: repo.repo,
            pull_number: prNumber,
            body,
            commit_id: context.payload.pull_request.head.sha,
            path: finding.file,
            line: finding.line,
          }).catch((err: any) => {
            core.warning(`[Guppy] Failed to post comment on ${finding.file}:${finding.line}: ${err.message}`);
          });
        }
      }

      core.info(`[Guppy] ${commentableFindings.length} comment(s) posted.`);
    }

    // Upload SARIF to GitHub Advanced Security
    if (inputs.upload_sarif && findings.length > 0) {
      core.info('[Guppy] Uploading SARIF report to GitHub Advanced Security...');
      try {
        const sarif = findingsToSarif(findings, enrichedTexts);
        const encoded = gzipSync(Buffer.from(JSON.stringify(sarif))).toString('base64');
        const prRef = `refs/pull/${prNumber}/head`;
        await octokit.request('POST /repos/{owner}/{repo}/code-scanning/sarifs', {
          owner: repo.owner,
          repo: repo.repo,
          commit_sha: context.payload.pull_request.head.sha,
          ref: prRef,
          sarif: encoded,
          tool_name: 'guppy-agent',
        });
        core.info('[Guppy] SARIF upload complete. Findings visible in Security tab.');
      } catch (err: any) {
        core.warning(`[Guppy] SARIF upload failed (non-fatal): ${err.message}. Ensure security-events: write permission is set.`);
      }
    }

    // Filter SCA findings by comment severity threshold before posting comments
    const commentableScaFindings = scaFindings.filter(
      (f) => SEVERITY_ORDER[f.vulnerability.severity as keyof typeof SEVERITY_ORDER] >= commentThreshold
    );

    // Post SCA comments to PR
    if (inputs.post_comments && commentableScaFindings.length > 0) {
      core.info(`[Guppy SCA] Posting ${commentableScaFindings.length} comment(s)...`);
      const existingComments = await octokit.paginate(
        (octokit.rest.pulls as any).listReviewComments,
        { owner: repo.owner, repo: repo.repo, pull_number: prNumber, per_page: 100 }
      );
      const guppyScaComments = existingComments.filter(
        (c: any) => c.user?.login === 'github-actions[bot]' && c.body?.startsWith('⚠️')
      );

      for (const finding of commentableScaFindings) {
        const body = formatScaComment(finding);
        const existing = guppyScaComments.find(
          (c: any) => c.path === finding.file && c.body?.includes(finding.vulnerability.id)
        );
        if (existing) {
          await (octokit.rest.pulls as any).updateReviewComment({
            owner: repo.owner, repo: repo.repo, comment_id: existing.id, body,
          }).catch((err: any) => {
            core.warning(`[Guppy SCA] Failed to update comment for ${finding.vulnerability.id}: ${err.message}`);
          });
        } else {
          await (octokit.rest.pulls as any).createReviewComment({
            owner: repo.owner, repo: repo.repo, pull_number: prNumber, body,
            commit_id: context.payload.pull_request.head.sha,
            path: finding.file, line: 1,
          }).catch((err: any) => {
            core.warning(`[Guppy SCA] Failed to post comment for ${finding.vulnerability.id}: ${err.message}`);
          });
        }
      }
    }

    // Check severity threshold
    const severityThreshold = SEVERITY_ORDER[inputs.fail_on_severity as keyof typeof SEVERITY_ORDER];
    const blockingFindings = findings.filter(
      (f) => SEVERITY_ORDER[f.severity as keyof typeof SEVERITY_ORDER] >= severityThreshold
    );

    // Filter SCA findings by severity and confidence threshold
    const scaBlockingFindings = scaFindings.filter((f) => {
      const meetsSeverity = SEVERITY_ORDER[f.vulnerability.severity as keyof typeof SEVERITY_ORDER] >= severityThreshold;
      if (!meetsSeverity) return false;
      if (f.confidence === null || f.confidence === undefined) return true;
      return f.confidence >= inputs.sca_reachability_confidence_threshold;
    });

    core.setOutput('findings_count', findings.length);
    core.setOutput('blocking_count', blockingFindings.length);
    core.setOutput('sca_findings_count', scaFindings.length);
    core.setOutput('sca_blocking_count', scaBlockingFindings.length);

    if (blockingFindings.length > 0 && severityThreshold > 0) {
      const hasCritical = blockingFindings.some((f) => f.severity === 'critical');
      if (hasCritical) {
        core.error(`[Guppy] It's a trap!`);
      }
      core.error(
        `[Guppy] Calculation: Threat level exceeds safety parameters. Terminating build sequence, Bob.`
      );
      core.error(`Found ${blockingFindings.length} issue(s) at or above ${inputs.fail_on_severity} severity.`);
      blockingFindings.forEach((f) => {
        core.error(`  - [${f.severity}] ${f.type} in ${f.file}:${f.line}`);
      });
      core.setFailed('[Guppy] Build blocked by security findings.');
    } else if (blockingFindings.length === 0 && findings.length > 0) {
      core.warning('[Guppy] Findings reported but below fail threshold. Proceeding with caution, Bob.');
    }

    if (scaBlockingFindings.length > 0 && severityThreshold > 0) {
      core.error(`[Guppy SCA] ${scaBlockingFindings.length} blocking SCA finding(s)`);
      scaBlockingFindings.forEach((f) => {
        const reachLabel = f.confidence ? ` [confidence: ${f.confidence}]` : '';
        core.error(`  - [${f.vulnerability.severity}] ${f.vulnerability.id} in ${f.package.name}${reachLabel}`);
      });
      core.setFailed('[Guppy] Build blocked by security findings.');
    }
  } catch (error) {
    if (error instanceof Error) {
      const safeMessage = await scrubber.scrub(error.message);
      core.setFailed(`[Guppy] Error: ${safeMessage}`);
    } else {
      core.setFailed(`[Guppy] Unknown error occurred`);
    }
  }
}

main();
