import chalk from 'chalk';
import * as Debug from 'debug';
import {
  IacTestResponse,
  AnnotatedIacIssue,
} from '../../../lib/snyk-test/iac-test-result';
import { getSeverityValue } from './formatters';
import { printPath } from './formatters/remediation-based-format-issues';
import { titleCaseText } from './formatters/legacy-format-issue';
import * as Sarif from 'sarif';
const debug = Debug('iac-output');

function formatIacIssue(
  issue: AnnotatedIacIssue,
  isNew: boolean,
  path: string[],
): string {
  const severitiesColourMapping = {
    low: {
      colorFunc(text) {
        return chalk.blueBright(text);
      },
    },
    medium: {
      colorFunc(text) {
        return chalk.yellowBright(text);
      },
    },
    high: {
      colorFunc(text) {
        return chalk.redBright(text);
      },
    },
  };
  const newBadge = isNew ? ' (new)' : '';
  const name = issue.subType ? ` in ${chalk.bold(issue.subType)}` : '';

  let introducedBy = '';
  if (path) {
    // In this mode, we show only one path by default, for compactness
    const pathStr = printPath(path);
    introducedBy = `\n    introduced by ${pathStr}`;
  }

  const description = extractOverview(issue.description).trim();
  const descriptionLine = `\n    ${description}\n`;

  return (
    severitiesColourMapping[issue.severity].colorFunc(
      `  ✗ ${chalk.bold(issue.title)}${newBadge} [${titleCaseText(
        issue.severity,
      )} Severity]`,
    ) +
    ` [${issue.id}]` +
    name +
    introducedBy +
    descriptionLine
  );
}

function extractOverview(description: string): string {
  if (!description) {
    return '';
  }

  const overviewRegExp = /## Overview([\s\S]*?)(?=##|(# Details))/m;
  const overviewMatches = overviewRegExp.exec(description);
  return (overviewMatches && overviewMatches[1]) || '';
}

export function getIacDisplayedOutput(
  iacTest: IacTestResponse,
  testedInfoText: string,
  meta: string,
  prefix: string,
): string {
  const issuesTextArray = [
    chalk.bold.white('\nInfrastructure as code issues:'),
  ];

  const NotNew = false;

  const issues: AnnotatedIacIssue[] = iacTest.result.cloudConfigResults;
  debug(`iac display output - ${issues.length} issues`);

  issues
    .sort((a, b) => getSeverityValue(b.severity) - getSeverityValue(a.severity))
    .forEach((issue) => {
      issuesTextArray.push(
        formatIacIssue(issue, NotNew, issue.cloudConfigPath),
      );
    });

  const issuesInfoOutput: string[] = [];
  debug(`Iac display output - ${issuesTextArray.length} issues text`);
  if (issuesTextArray.length > 0) {
    issuesInfoOutput.push(issuesTextArray.join('\n'));
  }

  let body = issuesInfoOutput.join('\n\n') + '\n\n' + meta;

  const vulnCountText = `found ${issues.length} issues`;
  const summary = testedInfoText + ', ' + chalk.red.bold(vulnCountText);

  body = body + '\n\n' + summary;

  return prefix + body;
}

export function capitalizePackageManager(type) {
  switch (type) {
    case 'k8sconfig': {
      return 'Kubernetes';
    }
    case 'helmconfig': {
      return 'Helm';
    }
    case 'terraformconfig': {
      return 'Terraform';
    }
    default: {
      return 'Infrastracture as Code';
    }
  }
}

export function createSarifOutputForIac(
  iacTestResponses: IacTestResponse[],
): Sarif.Log {
  const sarifRes: Sarif.Log = {
    version: '2.1.0',
    runs: [],
  };

  iacTestResponses.forEach((iacTestResult) => {
    sarifRes.runs.push({
      tool: getTool(iacTestResult),
      results: getResults(iacTestResult),
    });
  });

  return sarifRes;
}

function uppercaseFirstLatter(str: string): string {
  return str.charAt(0).toUpperCase() + str.slice(1);
}
export function getTool(iacTestResponse: IacTestResponse): Sarif.Tool {
  const tool: Sarif.Tool = {
    driver: {
      name: 'Snyk',
      rules: [],
    },
  };

  //TODO: remove?
  if (!iacTestResponse.result || !iacTestResponse.result.cloudConfigResults) {
    return tool;
  }

  const pushedIds: string[] = [];
  iacTestResponse.result.cloudConfigResults.forEach(
    (iacIssue: AnnotatedIacIssue) => {
      if (pushedIds.includes(iacIssue.id)) {
        return;
      }
      tool.driver.rules?.push({
        id: iacIssue.id,
        shortDescription: {
          text: `${uppercaseFirstLatter(iacIssue.severity)} - ${
            iacIssue.title
          }`,
        },
        fullDescription: {
          text: `Kubernetes ${iacIssue.subType}`,
        },
        help: {
          text: '',
          markdown: iacIssue.description,
        },
        defaultConfiguration: {
          level: 'warning',
        },
        properties: {
          tags: ['security', `kubernetes/${iacIssue.subType}`],
        },
      });
      pushedIds.push(iacIssue.id);
    },
  );
  return tool;
}

export function getResults(iacTestResponse: IacTestResponse): Sarif.Result[] {
  const results: Sarif.Result[] = [];

  iacTestResponse.result.cloudConfigResults.forEach(
    (iacIssue: AnnotatedIacIssue) => {
      results.push({
        ruleId: iacIssue.id,
        message: {
          text: `This line contains a potential ${iacIssue.severity} severity misconfiguration affacting the Kubernetes ${iacIssue.subType}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                //TODO: how to get the repo path?
                uri: iacTestResponse.targetFile,
              },
              region: {
                startLine: iacIssue.lineNumber,
              },
            },
          },
        ],
      });
    },
  );
  return results;
}
