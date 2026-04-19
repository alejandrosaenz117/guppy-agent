import * as core from '@actions/core';
import * as github from '@actions/github';
import { Guppy } from './guppy.js';
import { scrubber } from './scrubber.js';
import { ActionInputsSchema, SEVERITY_ORDER, Finding } from './types.js';
import { anthropic } from '@ai-sdk/anthropic';
import { openai } from '@ai-sdk/openai';
import { google } from '@ai-sdk/google';

async function main() {
  try {
    core.info('[Guppy] Acknowledged. Initiating security scan. As you wish, Bob.');

    // Parse inputs
    const api_key = core.getInput('api_key', { required: true });
    core.setSecret(api_key);
    const provider = core.getInput('provider') || 'anthropic';
    const model = core.getInput('model') || 'claude-3-5-sonnet-20241022';
    const post_comments = core.getBooleanInput('post_comments');
    const fail_on_severity = core.getInput('fail_on_severity') || 'high';
    const github_token = core.getInput('github_token', { required: true });

    // Validate inputs
    const inputs = ActionInputsSchema.parse({
      api_key,
      provider,
      model,
      post_comments,
      fail_on_severity,
      github_token,
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

    // Scrub secrets before sending to LLM
    const scrubbedDiff = await scrubber.scrub(truncatedDiff);
    core.info(`[Guppy] Scrubbed diff size: ${scrubbedDiff.length} bytes. Proceeding to analysis...`);

    // Run Guppy auditing
    const guppy = new Guppy(modelClient);
    core.info('[Guppy] Starting Hunter pass...');
    const findings = await guppy.audit(scrubbedDiff);
    core.info(`[Guppy] Audit complete. Raw findings: ${findings.length}`);

    // Clean up API key from environment after use
    delete process.env.ANTHROPIC_API_KEY;
    delete process.env.OPENAI_API_KEY;
    delete process.env.GOOGLE_GENERATIVE_AI_API_KEY;

    if (findings.length === 0) {
      core.info('[Guppy] Observation: The tactical situation is clear. No traps detected, Bob.');
      return;
    }

    core.warning(`[Guppy] Calculation: ${findings.length} potential vulnerabilities identified.`);

    // Post inline comments
    if (inputs.post_comments && findings.length > 0) {
      core.info('[Guppy] Posting inline comments to PR...');

      for (const finding of findings) {
        await (octokit.rest.pulls as any).createReviewComment({
          owner: repo.owner,
          repo: repo.repo,
          pull_number: prNumber,
          body: `🚨 **[${finding.severity.toUpperCase()}] ${finding.type}**\n\n${finding.message}\n\n**Recommended Fix:**\n${finding.fix}`,
          commit_id: context.payload.pull_request.head.sha,
          path: finding.file,
          line: finding.line,
        }).catch((err: any) => {
          core.warning(`[Guppy] Failed to post comment on ${finding.file}:${finding.line}: ${err.message}`);
        });
      }

      core.info(`[Guppy] ${findings.length} comment(s) posted.`);
    }

    // Check severity threshold
    const severityThreshold = SEVERITY_ORDER[inputs.fail_on_severity as keyof typeof SEVERITY_ORDER];
    const blockingFindings = findings.filter(
      (f) => SEVERITY_ORDER[f.severity as keyof typeof SEVERITY_ORDER] >= severityThreshold
    );

    core.setOutput('findings_count', findings.length);
    core.setOutput('blocking_count', blockingFindings.length);

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
