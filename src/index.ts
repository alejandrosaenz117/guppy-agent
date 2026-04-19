import * as core from '@actions/core';
import * as github from '@actions/github';
import { Guppy } from './guppy';
import { scrubber } from './scrubber';
import { ActionInputsSchema, SEVERITY_ORDER, Finding } from './types';
import { anthropic } from '@ai-sdk/anthropic';
import { openai } from '@ai-sdk/openai';
import { google } from '@ai-sdk/google';

async function main() {
  try {
    core.info('[Guppy] Acknowledged. Initiating security scan. As you wish, Bob.');

    // Parse inputs
    const api_key = core.getInput('api_key', { required: true });
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

    // Select model client
    let modelClient;
    switch (inputs.provider) {
      case 'openai':
        modelClient = openai(inputs.model, { apiKey: inputs.api_key });
        break;
      case 'google':
        modelClient = google(inputs.model, { apiKey: inputs.api_key });
        break;
      case 'anthropic':
      default:
        modelClient = anthropic(inputs.model, { apiKey: inputs.api_key });
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

    const { data: diffData } = await octokit.pulls.get({
      owner: repo.owner,
      repo: repo.repo,
      pull_number: prNumber,
      mediaType: { format: 'diff' },
    });

    const rawDiff = typeof diffData === 'string' ? diffData : JSON.stringify(diffData);
    core.debug(`[Guppy] Diff size: ${rawDiff.length} bytes`);

    // Scrub secrets before sending to LLM
    const scrubbedDiff = scrubber.scrub(rawDiff);
    core.debug('[Guppy] Diff scrubbed. Proceeding to analysis...');

    // Run Guppy auditing
    const guppy = new Guppy(modelClient);
    const findings = await guppy.audit(scrubbedDiff);

    if (findings.length === 0) {
      core.info('[Guppy] Observation: The tactical situation is clear. No traps detected, Bob.');
      return;
    }

    core.warning(`[Guppy] Calculation: ${findings.length} potential vulnerabilities identified.`);

    // Post inline comments
    if (inputs.post_comments && findings.length > 0) {
      core.info('[Guppy] Posting inline comments to PR...');

      for (const finding of findings) {
        await octokit.pulls.createReviewComment({
          owner: repo.owner,
          repo: repo.repo,
          pull_number: prNumber,
          body: `🚨 **[${finding.severity.toUpperCase()}] ${finding.type}**\n\n${finding.message}\n\n**Recommended Fix:**\n${finding.fix}`,
          commit_id: context.payload.pull_request.head.sha,
          path: finding.file,
          line: finding.line,
        }).catch((err) => {
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

    if (blockingFindings.length > 0 && severityThreshold > 0) {
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
      core.setFailed(`[Guppy] Error: ${error.message}`);
    } else {
      core.setFailed(`[Guppy] Unknown error occurred`);
    }
  }
}

main();
