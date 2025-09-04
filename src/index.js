const core = require('@actions/core');
const github = require('@actions/github');
const fs = require('fs');
const path = require('path');
const glob = require('glob');

// Predefined sensitive patterns
const SENSITIVE_PATTERNS = {
  secrets: {
    patterns: [
      /(password|passwd|pwd)\s*[=:]\s*['"]\w+['"]/gi,
      /(api[_-]?key|apikey)\s*[=:]\s*['"]\w+['"]/gi,
      /(secret|token)\s*[=:]\s*['"]\w+['"]/gi,
      /(access[_-]?token)\s*[=:]\s*['"]\w+['"]/gi,
      /(private[_-]?key)\s*[=:]\s*['"]\w+['"]/gi,
      /(database[_-]?url|db[_-]?url)\s*[=:]\s*['"]\w+['"]/gi,
      /sk-[a-zA-Z0-9]{32,}/g, // OpenAI API keys
      /ghp_[a-zA-Z0-9]{36}/g, // GitHub tokens
      /xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}/g, // Slack tokens
      /ya29\.[a-zA-Z0-9_-]{100,}/g, // Google OAuth tokens
      /AKIA[0-9A-Z]{16}/g, // AWS Access Key ID
      /([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_\-\+\/=]*)/g, // JWT tokens
    ],
    severity: 'high',
    description: 'Potential secrets or credentials'
  },
  suspicious_code: {
    patterns: [
      /eval\s*\(/g,
      /document\.write\s*\(/g,
      /innerHTML\s*=/g,
      /dangerouslySetInnerHTML/g,
      /\$\{[^}]*\}/g, // Template injection
      /__import__\s*\(/g, // Python dynamic imports
      /exec\s*\(/g,
      /system\s*\(/g,
    ],
    severity: 'medium',
    description: 'Potentially dangerous code patterns'
  },
  hardcoded_urls: {
    patterns: [
      /https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)/g,
      /https?:\/\/[^\/\s]+\.(?:local|dev|test)/g,
    ],
    severity: 'low',
    description: 'Hardcoded development URLs'
  }
};

class SensitiveScanner {
  constructor() {
    this.githubToken = core.getInput('github-token', { required: true });
    this.sensitiveWordsFile = core.getInput('sensitive-words-file');
    this.customPatterns = this.parseCustomPatterns(core.getInput('custom-patterns'));
    this.excludeFiles = core.getInput('exclude-files').split(',').map(p => p.trim());
    this.severityLevel = core.getInput('severity-level');
    this.failOnDetection = core.getInput('fail-on-detection') === 'true';
    this.commentMode = core.getInput('comment-mode');
    
    this.octokit = github.getOctokit(this.githubToken);
    this.context = github.context;
    this.findings = [];
  }

  parseCustomPatterns(input) {
    try {
      return JSON.parse(input || '[]');
    } catch (error) {
      core.warning(`Invalid custom patterns JSON: ${error.message}`);
      return [];
    }
  }

  async run() {
    try {
      if (this.context.eventName !== 'pull_request') {
        core.info('Not a pull request event, skipping scan');
        return;
      }

      const prNumber = this.context.payload.pull_request.number;
      core.info(`Scanning PR #${prNumber}...`);

      await this.scanPR(prNumber);
      await this.reportFindings(prNumber);
      
      // Set outputs
      core.setOutput('findings-count', this.findings.length);
      core.setOutput('has-high-severity', this.findings.some(f => f.severity === 'high'));
      core.setOutput('scan-status', this.getScanStatus());

    } catch (error) {
      core.setFailed(`Action failed: ${error.message}`);
    }
  }

  getScanStatus() {
    if (this.findings.length === 0) return 'passed';
    if (this.findings.some(f => f.severity === 'high')) return 'failed';
    return 'warning';
  }

  async scanPR(prNumber) {
    const { data: files } = await this.octokit.rest.pulls.listFiles({
      ...this.context.repo,
      pull_number: prNumber,
    });

    // Load custom patterns
    this.loadCustomSensitiveWords();
    this.loadCustomRegexPatterns();

    for (const file of files) {
      if (this.shouldSkipFile(file.filename)) {
        core.debug(`Skipping file: ${file.filename}`);
        continue;
      }

      if (file.status === 'removed') continue;

      await this.scanFile(file);
    }
  }

  shouldSkipFile(filename) {
    return this.excludeFiles.some(pattern => {
      const regex = new RegExp(pattern.replace(/\*/g, '.*'));
      return regex.test(filename);
    });
  }

  loadCustomSensitiveWords() {
    if (fs.existsSync(this.sensitiveWordsFile)) {
      const words = fs.readFileSync(this.sensitiveWordsFile, 'utf8')
        .split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'));
      
      if (words.length > 0) {
        SENSITIVE_PATTERNS.custom_words = {
          patterns: words.map(word => new RegExp(word, 'gi')),
          severity: 'medium',
          description: 'Custom sensitive words'
        };
      }
    }
  }

  loadCustomRegexPatterns() {
    if (this.customPatterns.length > 0) {
      SENSITIVE_PATTERNS.custom_patterns = {
        patterns: this.customPatterns.map(pattern => new RegExp(pattern, 'g')),
        severity: 'medium',
        description: 'Custom regex patterns'
      };
    }
  }

  async scanFile(file) {
    core.debug(`Scanning file: ${file.filename}`);
    
    let content = '';
    if (file.patch) {
      // Extract added lines from patch
      const lines = file.patch.split('\n');
      const addedLines = lines
        .filter(line => line.startsWith('+') && !line.startsWith('+++'))
        .map(line => line.substring(1));
      content = addedLines.join('\n');
    }

    if (!content.trim()) return;

    for (const [category, config] of Object.entries(SENSITIVE_PATTERNS)) {
      for (const pattern of config.patterns) {
        const matches = [...content.matchAll(pattern)];
        for (const match of matches) {
          const lineNumber = this.getLineNumber(content, match.index);
          this.findings.push({
            file: file.filename,
            line: lineNumber,
            match: match[0],
            category,
            severity: config.severity,
            description: config.description,
            context: this.getContext(content, match.index)
          });
        }
      }
    }
  }

  getLineNumber(content, index) {
    const beforeMatch = content.substring(0, index);
    return beforeMatch.split('\n').length;
  }

  getContext(content, index) {
    const lines = content.split('\n');
    const lineIndex = this.getLineNumber(content, index) - 1;
    const start = Math.max(0, lineIndex - 1);
    const end = Math.min(lines.length, lineIndex + 2);
    return lines.slice(start, end).join('\n');
  }

  async reportFindings(prNumber) {
    const severityOrder = { low: 1, medium: 2, high: 3 };
    const minSeverity = severityOrder[this.severityLevel] || 2;

    const filteredFindings = this.findings.filter(
      finding => severityOrder[finding.severity] >= minSeverity
    );

    if (filteredFindings.length === 0) {
      core.info('✅ No sensitive content found!');
      if (this.commentMode !== 'none') {
        await this.postComment(prNumber, '✅ **Sensitive Content Scanner**: No issues found in this PR.');
      }
      return;
    }

    const comment = this.formatComment(filteredFindings);
    
    if (this.commentMode !== 'none') {
      await this.postComment(prNumber, comment);
    }
    
    core.warning(`Found ${filteredFindings.length} potential issue(s)`);
    
    if (this.failOnDetection) {
      core.setFailed(`Sensitive content detected: ${filteredFindings.length} issue(s) found`);
    }
  }

  formatComment(findings) {
    const grouped = findings.reduce((acc, finding) => {
      if (!acc[finding.severity]) acc[finding.severity] = [];
      acc[finding.severity].push(finding);
      return acc;
    }, {});

    let comment = '🔍 **Sensitive Content Scanner Results**\n\n';
    comment += `Found ${findings.length} potential issue(s) in this PR:\n\n`;

    for (const severity of ['high', 'medium', 'low']) {
      if (!grouped[severity]) continue;
      
      const emoji = severity === 'high' ? '🚨' : severity === 'medium' ? '⚠️' : 'ℹ️';
      comment += `## ${emoji} ${severity.toUpperCase()} Severity\n\n`;
      
      for (const finding of grouped[severity]) {
        comment += `**${finding.file}** (Line ${finding.line})\n`;
        comment += `- **Category**: ${finding.description}\n`;
        comment += `- **Match**: \`${finding.match}\`\n`;
        comment += `\`\`\`\n${finding.context}\n\`\`\`\n\n`;
      }
    }

    comment += '---\n';
    comment += '> Please review these findings and remove any sensitive information before merging.\n';
    comment += '> If these are false positives, you can update the exclusion patterns or sensitive words file.';

    return comment;
  }

  async postComment(prNumber, body) {
    try {
      await this.octokit.rest.issues.createComment({
        ...this.context.repo,
        issue_number: prNumber,
        body: body
      });
    } catch (error) {
      core.warning(`Failed to post comment: ${error.message}`);
    }
  }
}

// Main execution
async function main() {
  const scanner = new SensitiveScanner();
  await scanner.run();
}

if (require.main === module) {
  main().catch(error => {
    core.setFailed(error.message);
  });
}

module.exports = { SensitiveScanner };
